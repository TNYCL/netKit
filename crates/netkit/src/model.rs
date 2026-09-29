use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::net::IpAddr;

/// Source identity scopes addresses and flows; use a distinct sensor for each
/// capture location. Interface IDs are local to the source/pcapng section.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Source {
    pub sensor: String,
    pub interface: u32,
    pub link_type: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Packet {
    pub source: Source,
    pub timestamp_ns: u64,
    pub original_len: u32,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Endpoint {
    pub ip: IpAddr,
    pub port: u16,
}
impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.ip {
            IpAddr::V4(ip) => write!(f, "{ip}:{}", self.port),
            IpAddr::V6(ip) => write!(f, "[{ip}]:{}", self.port),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Tcp,
    Udp,
    Icmp,
    Other(u8),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct FlowKey {
    pub source: Source,
    pub vlans: Vec<u16>,
    pub transport: Transport,
    pub a: Endpoint,
    pub b: Endpoint,
}
impl FlowKey {
    pub fn new(
        source: Source,
        vlans: Vec<u16>,
        transport: Transport,
        src: Endpoint,
        dst: Endpoint,
    ) -> (Self, usize) {
        let (a, b, direction) = if src <= dst {
            (src, dst, 0)
        } else {
            (dst, src, 1)
        };
        (
            Self {
                source,
                vlans,
                transport,
                a,
                b,
            },
            direction,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Completeness {
    Complete,
    Partial,
    Encrypted,
    Opaque,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub protocol: String,
    pub completeness: Completeness,
    pub fields: Value,
    pub wire_len: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Statistics {
    pub packets: u64,
    pub captured_bytes: u64,
    pub messages: u64,
    pub malformed_packets: u64,
    pub truncated_packets: u64,
    pub stream_gaps: u64,
    pub resource_evictions: u64,
    pub capture_drops: u64,
    /// Driver/interface loss counts can overlap; do not add them together.
    pub interface_drops: u64,
    pub queue_drops: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowSummary {
    pub id: u64,
    pub key: FlowKey,
    pub first_seen_ns: u64,
    pub last_seen_ns: u64,
    pub packets: [u64; 2],
    pub bytes: [u64; 2],
    pub protocols: Vec<String>,
    pub partial: bool,
    pub close_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub sensor: String,
    pub interface: u32,
    pub vlans: Vec<u16>,
    pub ip: IpAddr,
    pub mac: Option<String>,
    pub first_seen_ns: u64,
    pub last_seen_ns: u64,
    pub packets: u64,
    pub names: Vec<String>,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub schema_version: u32,
    pub sequence: u64,
    pub timestamp_ns: u64,
    pub source: Source,
    pub packet_id: Option<u64>,
    #[serde(flatten)]
    pub kind: EventKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EventKind {
    PacketObserved {
        captured_len: usize,
        original_len: u32,
        layers: Value,
    },
    DeviceObserved {
        device: Device,
    },
    FlowOpened {
        flow: FlowSummary,
    },
    FlowClosed {
        flow: FlowSummary,
    },
    MessageDecoded {
        flow_id: Option<u64>,
        direction: usize,
        message: Message,
    },
    Diagnostic {
        code: String,
        detail: String,
        flow_id: Option<u64>,
    },
    Statistics {
        counters: Statistics,
    },
}
