#![forbid(unsafe_code)]
//! Source-independent analysis engine. The caller owns I/O, scheduling and event
//! storage. All native analysis state is bounded by EngineConfig.
use crate::{
    packet,
    protocols::{DecodeContext, DecodeSession},
    stream::{FragmentCache, TcpStream},
    *,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::{BTreeMap, HashMap},
    net::IpAddr,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EngineConfig {
    pub max_flows: usize,
    pub max_devices: usize,
    pub max_flow_bytes: usize,
    pub max_total_bytes: usize,
    pub max_message_bytes: usize,
    pub max_packet_bytes: usize,
    pub max_events_per_packet: usize,
    pub flow_timeout_seconds: u64,
    pub fragment_timeout_seconds: u64,
    pub emit_packets: bool,
    /// Opt in to medical fields and potentially sensitive HTTP headers/URLs.
    pub include_sensitive: bool,
    pub protocol: Option<String>,
}
impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            max_flows: 4096,
            max_devices: 16384,
            max_flow_bytes: 1024 * 1024,
            max_total_bytes: 64 * 1024 * 1024,
            max_message_bytes: 1024 * 1024,
            max_packet_bytes: 2 * 1024 * 1024,
            max_events_per_packet: 256,
            flow_timeout_seconds: 120,
            fragment_timeout_seconds: 30,
            emit_packets: false,
            include_sensitive: false,
            protocol: None,
        }
    }
}
impl EngineConfig {
    pub fn validate(&self) -> Result<()> {
        if self.max_flows == 0
            || self.max_devices == 0
            || self.max_events_per_packet == 0
            || self.flow_timeout_seconds == 0
            || self.fragment_timeout_seconds == 0
        {
            return Err(Error::Invalid(
                "resource counts/timeouts must be nonzero".into(),
            ));
        }
        if self.max_message_bytes < 64
            || self.max_message_bytes > 16 * 1024 * 1024
            || self.max_flow_bytes < self.max_message_bytes
            || self.max_total_bytes < self.max_flow_bytes
            || self.max_packet_bytes < 64
            || self.max_packet_bytes > 16 * 1024 * 1024
        {
            return Err(Error::Invalid(
                "invalid memory limits; message <= flow <= total, packet/message <= 16 MiB".into(),
            ));
        }
        if self.max_flows > 1_000_000
            || self.max_devices > 1_000_000
            || self.max_events_per_packet > 4096
        {
            return Err(Error::Invalid(
                "resource counts exceed supported limits".into(),
            ));
        }
        Ok(())
    }
}
#[derive(Default)]
struct Direction {
    stream: TcpStream,
    buffer: Vec<u8>,
    decoder: Option<Box<dyn DecodeSession>>,
    name: Option<String>,
}
impl Direction {
    fn memory(&self) -> usize {
        self.buffer.len()
            + self.stream.buffered_bytes()
            + self.decoder.as_ref().map_or(0, |s| s.buffered_bytes())
    }
}
struct Connection {
    summary: FlowSummary,
    directions: [Direction; 2],
    pending_hl7: HashMap<String, (u64, u64, usize)>,
}
impl Connection {
    fn memory(&self) -> usize {
        self.directions.iter().map(Direction::memory).sum::<usize>()
            + self.pending_hl7.keys().map(|k| k.len() + 32).sum::<usize>()
    }
}
type DeviceKey = (String, u32, Vec<u16>, IpAddr);

pub struct Engine {
    config: EngineConfig,
    registry: ProtocolRegistry,
    connections: HashMap<FlowKey, Connection>,
    inventory: BTreeMap<DeviceKey, Device>,
    fragments: FragmentCache,
    stats: Statistics,
    sequence: u64,
    next_flow: u64,
    watermark: u64,
    namespace: u16,
    flow_buffered: usize,
    last_sweep_ns: u64,
}
impl Engine {
    pub fn new(config: EngineConfig) -> Result<Self> {
        Self::with_registry(config, ProtocolRegistry::default())
    }
    pub fn with_registry(config: EngineConfig, registry: ProtocolRegistry) -> Result<Self> {
        config.validate()?;
        if let Some(name) = &config.protocol {
            if registry.get(name).is_none() {
                return Err(Error::Invalid(format!("unknown forced protocol: {name}")));
            }
        }
        let fragments = FragmentCache::new(
            config.max_flows.min(1024),
            config.max_total_bytes / 4,
            config
                .fragment_timeout_seconds
                .saturating_mul(1_000_000_000),
        );
        Ok(Self {
            config,
            registry,
            connections: HashMap::new(),
            inventory: BTreeMap::new(),
            fragments,
            stats: Statistics::default(),
            sequence: 0,
            next_flow: 0,
            watermark: 0,
            namespace: 0,
            flow_buffered: 0,
            last_sweep_ns: 0,
        })
    }
    pub fn config(&self) -> &EngineConfig {
        &self.config
    }
    pub fn statistics(&self) -> &Statistics {
        &self.stats
    }
    pub fn devices(&self) -> Vec<Device> {
        self.inventory.values().cloned().collect()
    }
    pub fn flows(&self) -> Vec<FlowSummary> {
        let mut v: Vec<_> = self
            .connections
            .values()
            .map(|c| c.summary.clone())
            .collect();
        v.sort_by_key(|f| f.id);
        v
    }
    pub fn buffered_bytes(&self) -> usize {
        self.fragments.buffered_bytes() + self.flow_buffered
    }
    pub fn registry_mut(&mut self) -> &mut ProtocolRegistry {
        &mut self.registry
    }
    pub(crate) fn set_namespace(&mut self, namespace: u16) {
        self.namespace = namespace;
        self.sequence = (namespace as u64) << 48;
        self.next_flow = (namespace as u64) << 48;
    }
    fn emit(
        &mut self,
        out: &mut Vec<Event>,
        source: &Source,
        ts: u64,
        packet: Option<u64>,
        kind: EventKind,
    ) {
        self.sequence += 1;
        out.push(Event {
            schema_version: 1,
            sequence: self.sequence,
            timestamp_ns: ts,
            source: source.clone(),
            packet_id: packet.map(|n| n | ((self.namespace as u64) << 48)),
            kind,
        });
    }
    fn diagnostic(
        &mut self,
        out: &mut Vec<Event>,
        p: &Packet,
        flow: Option<u64>,
        code: &str,
        detail: impl Into<String>,
    ) {
        self.emit(
            out,
            &p.source,
            p.timestamp_ns,
            (!p.data.is_empty()).then_some(self.stats.packets),
            EventKind::Diagnostic {
                code: code.into(),
                detail: detail.into(),
                flow_id: flow,
            },
        );
    }
    pub fn record_loss(&mut self, source: Source, capture: u64, queue: u64) -> Vec<Event> {
        self.record_capture_loss(source, capture, 0, queue)
    }
    /// libpcap ps_drop and ps_ifdrop are kept separate because their meaning is platform-specific.
    pub fn record_capture_loss(
        &mut self,
        source: Source,
        capture: u64,
        interface: u64,
        queue: u64,
    ) -> Vec<Event> {
        self.stats.capture_drops = self.stats.capture_drops.saturating_add(capture);
        self.stats.interface_drops = self.stats.interface_drops.saturating_add(interface);
        self.stats.queue_drops = self.stats.queue_drops.saturating_add(queue);
        let mut out = Vec::new();
        if capture > 0 || queue > 0 || interface > 0 {
            self.emit(
                &mut out,
                &source,
                self.watermark,
                None,
                EventKind::Diagnostic {
                    code: "capture_loss".into(),
                    detail: format!("driver drops: {capture}; interface drops: {interface}; pipeline queue drops: {queue}"),
                    flow_id: None,
                },
            );
        }
        out
    }
    #[allow(clippy::too_many_arguments)]
    fn observe(
        &mut self,
        out: &mut Vec<Event>,
        p: &Packet,
        vlans: &[u16],
        ip: IpAddr,
        mac: Option<String>,
        name: Option<String>,
        evidence: &str,
    ) {
        if ip.is_unspecified()
            || ip.is_multicast()
            || ip == IpAddr::V4(std::net::Ipv4Addr::BROADCAST)
        {
            return;
        }
        let key = (
            p.source.sensor.clone(),
            p.source.interface,
            vlans.to_vec(),
            ip,
        );
        if !self.inventory.contains_key(&key) && self.inventory.len() >= self.config.max_devices {
            if let Some(old) = self
                .inventory
                .iter()
                .min_by_key(|(_, d)| d.last_seen_ns)
                .map(|(k, _)| k.clone())
            {
                self.inventory.remove(&old);
                self.stats.resource_evictions += 1;
                self.diagnostic(
                    out,
                    p,
                    None,
                    "device_evicted",
                    "device inventory bound reached",
                );
            }
        }
        let new = !self.inventory.contains_key(&key);
        let device = self.inventory.entry(key).or_insert(Device {
            sensor: p.source.sensor.clone(),
            interface: p.source.interface,
            vlans: vlans.to_vec(),
            ip,
            mac: None,
            first_seen_ns: p.timestamp_ns,
            last_seen_ns: p.timestamp_ns,
            packets: 0,
            names: Vec::new(),
            evidence: Vec::new(),
        });
        device.first_seen_ns = device.first_seen_ns.min(p.timestamp_ns);
        device.last_seen_ns = device.last_seen_ns.max(p.timestamp_ns);
        device.packets += 1;
        let mut changed = new;
        if let Some(mac) = mac {
            if device.mac.as_ref() != Some(&mac) {
                device.mac = Some(mac);
                changed = true;
            }
        }
        if let Some(name) = name {
            if !name.is_empty()
                && name.len() <= 255
                && !device.names.contains(&name)
                && device.names.len() < 16
            {
                device.names.push(name);
                changed = true;
            }
        }
        if !device.evidence.iter().any(|e| e == evidence) && device.evidence.len() < 16 {
            device.evidence.push(evidence.into());
            changed = true;
        }
        if changed {
            let device = device.clone();
            self.emit(
                out,
                &p.source,
                p.timestamp_ns,
                Some(self.stats.packets),
                EventKind::DeviceObserved { device },
            );
        }
    }
    pub fn ingest(&mut self, p: &Packet) -> Vec<Event> {
        let mut out = Vec::new();
        self.stats.packets += 1;
        self.stats.captured_bytes = self
            .stats
            .captured_bytes
            .saturating_add(p.data.len() as u64);
        self.watermark = self.watermark.max(p.timestamp_ns);
        if p.data.len() > self.config.max_packet_bytes
            || p.data.len() > p.original_len as usize
            || p.source.sensor.len() > 4096
        {
            self.stats.malformed_packets += 1;
            self.diagnostic(
                &mut out,
                p,
                None,
                "packet_rejected",
                "invalid packet/source size",
            );
            return out;
        }
        if p.data.len() < p.original_len as usize {
            self.stats.truncated_packets += 1;
            self.diagnostic(
                &mut out,
                p,
                None,
                "capture_truncated",
                "captured length is smaller than original wire length",
            );
        }
        self.expire(&mut out);
        let parsed = match packet::parse(p) {
            Ok(v) => v,
            Err(e) => {
                self.stats.malformed_packets += 1;
                self.diagnostic(&mut out, p, None, "packet_parse_error", e.to_string());
                return out;
            }
        };
        if self.config.emit_packets || parsed.network.is_none() {
            self.emit(
                &mut out,
                &p.source,
                p.timestamp_ns,
                Some(self.stats.packets),
                EventKind::PacketObserved {
                    captured_len: p.data.len(),
                    original_len: p.original_len,
                    layers: parsed.layers.clone(),
                },
            );
        }
        if let Some((ip, mac)) = parsed.arp {
            self.observe(
                &mut out,
                p,
                &parsed.vlans,
                ip,
                Some(mac),
                None,
                "arp_sender",
            );
        }
        let Some(network) = parsed.network else {
            return out;
        };
        // Ethernet source MAC may belong to a router. Do not claim it identifies
        // the IP endpoint without ARP/DHCP/NDP evidence.
        self.observe(
            &mut out,
            p,
            &parsed.vlans,
            network.src,
            None,
            None,
            "ip_source",
        );
        self.observe(
            &mut out,
            p,
            &parsed.vlans,
            network.dst,
            None,
            None,
            "ip_destination_only",
        );
        let fragment = self
            .fragments
            .push(&p.source, &parsed.vlans, network, p.timestamp_ns);
        for warning in fragment.diagnostics {
            self.stats.stream_gaps += 1;
            self.diagnostic(&mut out, p, None, "ip_fragment_error", warning);
        }
        let Some(network) = fragment.packet else {
            return out;
        };
        let transport = match packet::transport(&network) {
            Ok(v) => v,
            Err(e) => {
                self.stats.malformed_packets += 1;
                self.diagnostic(&mut out, p, None, "transport_parse_error", e.to_string());
                return out;
            }
        };
        let (key, direction) = FlowKey::new(
            p.source.clone(),
            parsed.vlans.clone(),
            transport.transport,
            transport.src.clone(),
            transport.dst.clone(),
        );
        // A new SYN (without ACK) on an existing tuple starts a new incarnation.
        if transport.flags & 0x12 == 0x02 {
            if let Some(old) = self.connections.get(&key) {
                if old.directions[direction].stream.initial_sequence() != Some(transport.sequence) {
                    self.close(&key, "tuple_reused", &mut out);
                }
            }
        }
        if !self.connections.contains_key(&key) && self.connections.len() >= self.config.max_flows {
            self.evict_oldest("flow_limit", &mut out);
        }
        let mut connection = if let Some(c) = self.connections.remove(&key) {
            self.flow_buffered = self.flow_buffered.saturating_sub(c.memory());
            c
        } else {
            self.next_flow += 1;
            let summary = FlowSummary {
                id: self.next_flow,
                key: key.clone(),
                first_seen_ns: p.timestamp_ns,
                last_seen_ns: p.timestamp_ns,
                packets: [0; 2],
                bytes: [0; 2],
                protocols: Vec::new(),
                partial: false,
                close_reason: None,
            };
            self.emit(
                &mut out,
                &p.source,
                p.timestamp_ns,
                Some(self.stats.packets),
                EventKind::FlowOpened {
                    flow: summary.clone(),
                },
            );
            Connection {
                summary,
                directions: [Direction::default(), Direction::default()],
                pending_hl7: HashMap::new(),
            }
        };
        connection.summary.last_seen_ns = connection.summary.last_seen_ns.max(p.timestamp_ns);
        connection.summary.first_seen_ns = connection.summary.first_seen_ns.min(p.timestamp_ns);
        connection.summary.packets[direction] += 1;
        connection.summary.bytes[direction] += transport.payload.len() as u64;
        let context = DecodeContext {
            transport: transport.transport,
            source_port: transport.src.port,
            destination_port: transport.dst.port,
            max_message: self.config.max_message_bytes,
        };
        if transport.transport == Transport::Tcp {
            let stream = connection.directions[direction].stream.push(
                transport.sequence,
                transport.flags & 2 != 0,
                transport.flags & 1 != 0,
                &transport.payload,
                self.config.max_flow_bytes,
            );
            for (code, detail) in stream.diagnostics {
                if code == "stream_gap" {
                    self.stats.stream_gaps += 1;
                }
                if code == "midstream_capture" || code == "tcp_overlap_conflict" {
                    connection.summary.partial = true;
                }
                self.diagnostic(&mut out, p, Some(connection.summary.id), &code, detail);
            }
            if stream.gap {
                connection.summary.partial = true;
                let d = &mut connection.directions[direction];
                if let Some(s) = &mut d.decoder {
                    s.on_gap(None);
                }
                d.buffer.clear();
                d.decoder = None;
                d.name = None;
            }
            let chunk_count = stream.chunks.len();
            'chunks: for (chunk_index, chunk) in stream.chunks.into_iter().enumerate() {
                let mut offset = 0;
                while offset < chunk.len() {
                    let d = &mut connection.directions[direction];
                    if d.buffer.len() == self.config.max_message_bytes {
                        connection.summary.partial = true;
                        self.stats.stream_gaps += 1;
                        self.diagnostic(
                            &mut out,
                            p,
                            Some(connection.summary.id),
                            "message_limit",
                            "application buffer reset at configured bound",
                        );
                        if let Some(s) = &mut d.decoder {
                            s.on_gap(None);
                        }
                        d.buffer.clear();
                        d.decoder = None;
                        d.name = None;
                    }
                    let size =
                        (self.config.max_message_bytes - d.buffer.len()).min(chunk.len() - offset);
                    d.buffer.extend_from_slice(&chunk[offset..offset + size]);
                    offset += size;
                    self.decode(&mut connection, direction, context, false, p, &mut out);
                    if out.len() >= self.config.max_events_per_packet {
                        if offset < chunk.len() || chunk_index + 1 < chunk_count {
                            connection.summary.partial = true;
                            self.diagnostic(
                                &mut out,
                                p,
                                Some(connection.summary.id),
                                "event_limit",
                                "remaining stream bytes discarded at event bound",
                            );
                        }
                        break 'chunks;
                    }
                }
            }
            if stream.closed {
                self.decode(&mut connection, direction, context, true, p, &mut out);
            }
        } else {
            // Datagram boundaries are preserved; no payload joins across UDP packets.
            connection.directions[direction].buffer = transport.payload;
            self.decode(&mut connection, direction, context, true, p, &mut out);
            connection.directions[direction].buffer.clear();
            connection.directions[direction].decoder = None;
            connection.directions[direction].name = None;
        }
        let closed = transport.flags & 4 != 0
            || connection.directions.iter().all(|d| d.stream.closed)
                && transport.transport == Transport::Tcp;
        let flow_memory = connection.memory();
        self.flow_buffered += flow_memory;
        self.connections.insert(key.clone(), connection);
        if flow_memory > self.config.max_flow_bytes {
            self.stats.resource_evictions += 1;
            self.close(&key, "flow_memory_limit", &mut out);
        }
        if closed {
            self.close(
                &key,
                if transport.flags & 4 != 0 {
                    "reset"
                } else {
                    "fin"
                },
                &mut out,
            );
        }
        while self.buffered_bytes() > self.config.max_total_bytes && !self.connections.is_empty() {
            self.evict_oldest("memory_limit", &mut out);
        }
        out
    }
    fn decode(
        &mut self,
        c: &mut Connection,
        dir: usize,
        ctx: DecodeContext,
        eof: bool,
        p: &Packet,
        out: &mut Vec<Event>,
    ) {
        for _ in 0..self.config.max_events_per_packet {
            if out.len() >= self.config.max_events_per_packet {
                break;
            }
            let d = &mut c.directions[dir];
            if d.buffer.is_empty() {
                break;
            }
            if d.decoder.is_none() {
                let candidate = if let Some(name) = &self.config.protocol {
                    self.registry.get(name)
                } else if c.summary.protocols.iter().any(|n| n == "http2") {
                    self.registry.get("http2")
                } else {
                    self.registry.identify(&d.buffer, ctx)
                };
                if let Some(candidate) = candidate {
                    d.name = Some(candidate.name().into());
                    d.decoder = Some(candidate.session());
                }
            }
            let result = if let Some(session) = &mut d.decoder {
                session.decode(&d.buffer, ctx, eof)
            } else {
                if !eof && d.buffer.len() < 4096 {
                    break;
                }
                let n = d.buffer.len();
                DecodeResult::Message {
                    consumed: n,
                    message: Message {
                        protocol: "unknown".into(),
                        completeness: Completeness::Unknown,
                        wire_len: n,
                        fields: json!({"length":n}),
                    },
                }
            };
            match result {
                DecodeResult::Skip { consumed } => {
                    if consumed == 0 || consumed > d.buffer.len() {
                        self.diagnostic(
                            out,
                            p,
                            Some(c.summary.id),
                            "decoder_contract_violation",
                            "invalid skipped byte count",
                        );
                        d.buffer.clear();
                        break;
                    }
                    d.buffer.drain(..consumed);
                }
                DecodeResult::NeedMore => {
                    if eof {
                        c.summary.partial = true;
                        self.diagnostic(
                            out,
                            p,
                            Some(c.summary.id),
                            "incomplete_message",
                            format!("{} buffered bytes at stream end", d.buffer.len()),
                        );
                        d.buffer.clear();
                    }
                    break;
                }
                DecodeResult::Invalid { consumed, detail } => {
                    c.summary.partial = true;
                    self.diagnostic(out, p, Some(c.summary.id), "protocol_error", detail);
                    if consumed == 0 || consumed > d.buffer.len() {
                        d.buffer.clear();
                        break;
                    }
                    d.buffer.drain(..consumed);
                    d.decoder = None;
                    d.name = None;
                }
                DecodeResult::Message {
                    consumed,
                    mut message,
                } => {
                    if consumed == 0 || consumed > d.buffer.len() {
                        self.diagnostic(
                            out,
                            p,
                            Some(c.summary.id),
                            "decoder_contract_violation",
                            "decoder consumed zero or more than available bytes",
                        );
                        d.buffer.clear();
                        d.decoder = None;
                        break;
                    }
                    d.buffer.drain(..consumed);
                    if c.summary.partial && message.completeness == Completeness::Complete {
                        message.completeness = Completeness::Partial;
                    }
                    if !c.summary.protocols.contains(&message.protocol) {
                        c.summary.protocols.push(message.protocol.clone());
                    }
                    if message.protocol == "hl7" {
                        let ack = message.fields["acknowledgement"]["control_id"]
                            .as_str()
                            .map(str::to_owned);
                        if let Some(id) = ack {
                            if let Some((time, packet, request_dir)) = c.pending_hl7.remove(&id) {
                                if dir != request_dir {
                                    message.fields["correlation"] = json!({"request_packet_id":packet,"response_time_ns":p.timestamp_ns.checked_sub(time)});
                                }
                            }
                        } else if let Some(id) = message.fields["control_id"].as_str() {
                            if id.len() <= 512 && c.pending_hl7.len() < 1024 {
                                c.pending_hl7.insert(
                                    id.into(),
                                    (
                                        p.timestamp_ns,
                                        self.stats.packets | ((self.namespace as u64) << 48),
                                        dir,
                                    ),
                                );
                            }
                        }
                    }
                    // Peer state carries negotiated DICOM syntax and HTTP request
                    // methods. Custom sessions receive their peer's messages too.
                    {
                        let peer = &mut c.directions[1 - dir];
                        if peer.decoder.is_none()
                            && matches!(message.protocol.as_str(), "dicom" | "http")
                        {
                            if let Some(decoder) = self.registry.get(&message.protocol) {
                                peer.name = Some(message.protocol.clone());
                                peer.decoder = Some(decoder.session());
                            }
                        }
                        if peer.name.as_deref() == Some(message.protocol.as_str()) {
                            if let Some(session) = &mut peer.decoder {
                                session.on_peer_message(&message);
                            }
                        }
                    }
                    self.learn(p, &c.summary.key.vlans, &message, out);
                    if !self.config.include_sensitive {
                        redact(&mut message);
                    }
                    self.stats.messages += 1;
                    self.emit(
                        out,
                        &p.source,
                        p.timestamp_ns,
                        (!p.data.is_empty()).then_some(self.stats.packets),
                        EventKind::MessageDecoded {
                            flow_id: Some(c.summary.id),
                            direction: dir,
                            message,
                        },
                    );
                }
            }
        }
        if !c.directions[dir].buffer.is_empty() && out.len() >= self.config.max_events_per_packet {
            c.summary.partial = true;
            self.diagnostic(
                out,
                p,
                Some(c.summary.id),
                "event_limit",
                "remaining application bytes discarded at event bound",
            );
            c.directions[dir].buffer.clear();
            c.directions[dir].decoder = None;
        }
    }
    fn learn(&mut self, p: &Packet, vlans: &[u16], m: &Message, out: &mut Vec<Event>) {
        if m.protocol == "dhcp" {
            let addr = m.fields["your_ip"]
                .as_str()
                .filter(|s| *s != "0.0.0.0")
                .or_else(|| m.fields["client_ip"].as_str());
            if let Some(ip) = addr.and_then(|s| s.parse().ok()) {
                self.observe(
                    out,
                    p,
                    vlans,
                    ip,
                    m.fields["client_mac"].as_str().map(str::to_owned),
                    m.fields["hostname"].as_str().map(str::to_owned),
                    "dhcp_claim",
                );
            }
        }
        if m.protocol == "dns" {
            if let Some(records) = m.fields["records"].as_array() {
                for record in records {
                    if let Some(ip) = record["value"].as_str().and_then(|s| s.parse().ok()) {
                        self.observe(
                            out,
                            p,
                            vlans,
                            ip,
                            None,
                            record["name"].as_str().map(str::to_owned),
                            "dns_answer_claim",
                        );
                    }
                }
            }
        }
        if m.protocol == "icmp" && m.fields["type"] == 136 && m.fields["link_address_option"] == 2 {
            if let Some(ip) = m.fields["ndp_target"].as_str().and_then(|s| s.parse().ok()) {
                self.observe(
                    out,
                    p,
                    vlans,
                    ip,
                    m.fields["link_address"].as_str().map(str::to_owned),
                    None,
                    "ndp_claim",
                );
            }
        }
    }
    fn expire(&mut self, out: &mut Vec<Event>) {
        if self.watermark.saturating_sub(self.last_sweep_ns) < 1_000_000_000 {
            return;
        }
        self.last_sweep_ns = self.watermark;
        let timeout = self
            .config
            .flow_timeout_seconds
            .saturating_mul(1_000_000_000);
        let keys: Vec<_> = self
            .connections
            .iter()
            .filter(|(_, c)| self.watermark.saturating_sub(c.summary.last_seen_ns) > timeout)
            .map(|(k, _)| k.clone())
            .collect();
        for k in keys {
            self.close(&k, "timeout", out);
        }
        let n = self.fragments.expire(self.watermark);
        if n > 0 {
            self.stats.stream_gaps += n as u64;
            self.emit(
                out,
                &Source::default(),
                self.watermark,
                None,
                EventKind::Diagnostic {
                    code: "fragment_timeout".into(),
                    detail: format!("{n} incomplete IP datagrams expired"),
                    flow_id: None,
                },
            );
        }
    }
    fn evict_oldest(&mut self, reason: &str, out: &mut Vec<Event>) {
        if let Some(key) = self
            .connections
            .iter()
            .min_by_key(|(_, c)| c.summary.last_seen_ns)
            .map(|(k, _)| k.clone())
        {
            self.stats.resource_evictions += 1;
            self.close(&key, reason, out);
        }
    }
    fn close(&mut self, key: &FlowKey, reason: &str, out: &mut Vec<Event>) {
        if let Some(mut c) = self.connections.remove(key) {
            self.flow_buffered = self.flow_buffered.saturating_sub(c.memory());
            let p = Packet {
                source: key.source.clone(),
                timestamp_ns: c.summary.last_seen_ns,
                original_len: 0,
                data: Vec::new(),
            };
            for dir in 0..2 {
                let s = c.directions[dir].stream.finish();
                if s.gap {
                    c.summary.partial = true;
                    self.stats.stream_gaps += 1;
                    for (code, detail) in s.diagnostics {
                        self.diagnostic(out, &p, Some(c.summary.id), &code, detail);
                    }
                }
                let (src, dst) = if dir == 0 {
                    (&key.a, &key.b)
                } else {
                    (&key.b, &key.a)
                };
                let ctx = DecodeContext {
                    transport: key.transport,
                    source_port: src.port,
                    destination_port: dst.port,
                    max_message: self.config.max_message_bytes,
                };
                self.decode(&mut c, dir, ctx, true, &p, out);
                if let Some(s) = &mut c.directions[dir].decoder {
                    if s.has_pending_message() {
                        c.summary.partial = true;
                        self.diagnostic(
                            out,
                            &p,
                            Some(c.summary.id),
                            "incomplete_protocol_state",
                            "stream ended inside a fragmented application message",
                        );
                    }
                    s.on_close();
                }
            }
            c.summary.close_reason = Some(reason.into());
            self.emit(
                out,
                &key.source,
                c.summary.last_seen_ns,
                None,
                EventKind::FlowClosed { flow: c.summary },
            );
        }
    }
    pub fn finish(&mut self) -> Vec<Event> {
        let mut out = Vec::new();
        let mut keys: Vec<_> = self.connections.keys().cloned().collect();
        keys.sort();
        for key in keys {
            self.close(&key, "end_of_input", &mut out);
        }
        let fragments = self.fragments.clear();
        if fragments > 0 {
            self.stats.stream_gaps += fragments as u64;
            self.emit(
                &mut out,
                &Source::default(),
                self.watermark,
                None,
                EventKind::Diagnostic {
                    code: "incomplete_fragments".into(),
                    detail: format!("{fragments} incomplete datagrams at end of input"),
                    flow_id: None,
                },
            );
        }
        self.emit(
            &mut out,
            &Source::default(),
            self.watermark,
            None,
            EventKind::Statistics {
                counters: self.stats.clone(),
            },
        );
        out
    }
    /// Decode an application-provided complete message without opening a socket.
    pub fn decode_message(&self, protocol: &str, data: &[u8]) -> Result<Vec<Message>> {
        if data.len() > self.config.max_message_bytes {
            return Err(Error::Limit("message exceeds configured bound".into()));
        }
        let decoder = self
            .registry
            .get(protocol)
            .ok_or_else(|| Error::Invalid(format!("unknown protocol: {protocol}")))?;
        let mut session = decoder.session();
        let mut pos = 0;
        let mut out = Vec::new();
        while pos < data.len() {
            if out.len() >= self.config.max_events_per_packet {
                return Err(Error::Limit("message count bound".into()));
            }
            match session.decode(
                &data[pos..],
                DecodeContext {
                    transport: Transport::Tcp,
                    source_port: 0,
                    destination_port: 0,
                    max_message: self.config.max_message_bytes,
                },
                true,
            ) {
                DecodeResult::Skip { consumed } if consumed > 0 && consumed <= data.len() - pos => {
                    pos += consumed;
                }
                DecodeResult::Message {
                    consumed,
                    mut message,
                } if consumed > 0 && consumed <= data.len() - pos => {
                    if !self.config.include_sensitive {
                        redact(&mut message);
                    }
                    out.push(message);
                    pos += consumed;
                }
                DecodeResult::Invalid { detail, .. } => return Err(Error::Invalid(detail)),
                _ => {
                    return Err(Error::Invalid(
                        "incomplete message or decoder contract violation".into(),
                    ));
                }
            }
        }
        Ok(out)
    }
}

fn redact(message: &mut Message) {
    let fields = &mut message.fields;
    match message.protocol.as_str() {
        "hl7" => {
            fields["segments"] = json!("[redacted]");
            if fields["acknowledgement"].is_object() {
                fields["acknowledgement"]["text"] = json!("[redacted]");
            }
        }
        "astm" => {
            if fields.get("message").is_some() {
                fields["message"] = json!("[redacted]");
            }
            if fields.get("records").is_some() {
                fields["records"] = json!("[redacted]");
            }
            if fields.get("incomplete_records").is_some() {
                fields["incomplete_records"] = json!("[redacted]");
            }
        }
        "poct" => fields["elements"] = json!("[redacted]"),
        "dicom" => {
            if let Some(pdvs) = fields["pdvs"].as_array_mut() {
                for pdv in pdvs {
                    if let Some(tags) = pdv["dataset_tags"].as_array_mut() {
                        for tag in tags {
                            if tag.get("value").is_some() {
                                tag["value"] = json!("[redacted]");
                            }
                        }
                    }
                }
            }
        }
        "http" | "http2" => {
            if fields.get("target").is_some() {
                fields["target"] = json!("[redacted]");
            }
            if fields.get("start_line").is_some() {
                fields["start_line"] = json!("[redacted]");
            }
            if let Some(headers) = fields["headers"].as_array_mut() {
                for h in headers {
                    h["value"] = json!("[redacted]");
                }
            }
        }
        _ => (),
    }
}
