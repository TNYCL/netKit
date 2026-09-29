#![forbid(unsafe_code)]
//! Pluggable incremental decoders. A separate session is constructed for every
//! direction of every flow; decoder state is never shared between connections.
mod clinical;
mod internet;
use crate::{Completeness, Message, Transport};
pub use clinical::{parse_astm_records, parse_hl7};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::Arc;

#[derive(Debug, Clone, Copy)]
pub struct DecodeContext {
    pub transport: Transport,
    pub source_port: u16,
    pub destination_port: u16,
    pub max_message: usize,
}
pub enum DecodeResult {
    NeedMore,
    Skip { consumed: usize },
    Message { consumed: usize, message: Message },
    Invalid { consumed: usize, detail: String },
}
pub trait DecodeSession: Send {
    fn decode(&mut self, data: &[u8], context: DecodeContext, eof: bool) -> DecodeResult;
    fn on_gap(&mut self, _missing_bytes: Option<u64>) {}
    fn on_close(&mut self) {}
    /// Called with unredacted peer messages before the event leaves the engine.
    fn on_peer_message(&mut self, _message: &Message) {}
    fn buffered_bytes(&self) -> usize {
        0
    }
    /// True when a consumed frame left an unfinished application message.
    fn has_pending_message(&self) -> bool {
        false
    }
}
pub trait Decoder: Send + Sync {
    fn name(&self) -> &str;
    /// Return 0 for no evidence; ports may be hints but are not proof.
    fn probe(&self, data: &[u8], context: DecodeContext) -> u8;
    fn session(&self) -> Box<dyn DecodeSession>;
}

#[derive(Clone)]
pub struct ProtocolRegistry {
    decoders: Vec<Arc<dyn Decoder>>,
}
impl Default for ProtocolRegistry {
    fn default() -> Self {
        let mut this = Self {
            decoders: Vec::new(),
        };
        for name in [
            "hl7", "astm", "poct", "http", "http2", "dns", "dhcp", "dicom", "tls", "quic", "icmp",
        ] {
            this.register(Arc::new(NativeDecoder(name)));
        }
        this
    }
}
impl ProtocolRegistry {
    pub fn empty() -> Self {
        Self {
            decoders: Vec::new(),
        }
    }
    pub fn register(&mut self, decoder: Arc<dyn Decoder>) {
        self.decoders.retain(|d| d.name() != decoder.name());
        self.decoders.push(decoder);
    }
    pub fn get(&self, name: &str) -> Option<Arc<dyn Decoder>> {
        self.decoders.iter().find(|d| d.name() == name).cloned()
    }
    pub fn identify(&self, data: &[u8], context: DecodeContext) -> Option<Arc<dyn Decoder>> {
        self.decoders
            .iter()
            .map(|d| (d.probe(data, context), d))
            .filter(|(n, _)| *n > 0)
            .max_by_key(|(n, _)| *n)
            .map(|(_, d)| d.clone())
    }
    pub fn names(&self) -> Vec<String> {
        self.decoders.iter().map(|d| d.name().to_owned()).collect()
    }
}

struct NativeDecoder(&'static str);
impl Decoder for NativeDecoder {
    fn name(&self) -> &str {
        self.0
    }
    fn probe(&self, b: &[u8], c: DecodeContext) -> u8 {
        let tcp = c.transport == Transport::Tcp;
        let udp = c.transport == Transport::Udp;
        match self.0 {
            "hl7" if b.starts_with(b"\x0bMSH") || b.starts_with(b"MSH") => 100,
            "astm" if b.starts_with(&[2]) && b.len() > 3 && b[1].is_ascii_digit() => 85,
            "astm" if b.starts_with(b"H|\\") => 85,
            "astm" if b.len() == 1 && matches!(b[0], 4 | 5 | 6 | 21) => 15,
            "poct"
                if b.starts_with(b"<?xml")
                    || [
                        b"<HEL.".as_slice(),
                        b"<OBS.",
                        b"<ACK.",
                        b"<DST.",
                        b"<END.",
                        b"<REQ.",
                        b"<RSP.",
                        b"<POCT",
                    ]
                    .iter()
                    .any(|p| b.starts_with(p)) =>
            {
                90
            }
            "http2" if b.starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") => 100,
            "http"
                if [
                    b"GET ".as_slice(),
                    b"POST ",
                    b"PUT ",
                    b"HEAD ",
                    b"DELETE ",
                    b"OPTIONS ",
                    b"PATCH ",
                    b"CONNECT ",
                    b"TRACE ",
                    b"HTTP/1.",
                ]
                .iter()
                .any(|p| b.starts_with(p)) =>
            {
                95
            }
            "dns"
                if (udp || tcp)
                    && ([c.source_port, c.destination_port]
                        .iter()
                        .any(|p| matches!(p, 53 | 5353 | 5355))) =>
            {
                60
            }
            "dhcp" if udp && b.len() >= 240 && b[236..240] == [99, 130, 83, 99] => 95,
            "dicom"
                if tcp
                    && b.len() >= 6
                    && (1..=7).contains(&b[0])
                    && b[1] == 0
                    && crate::packet::be32(&b[2..]) as usize <= c.max_message =>
            {
                65
            }
            "tls" if tcp && b.len() >= 5 && (20..=24).contains(&b[0]) && b[1] == 3 && b[2] <= 4 => {
                80
            }
            "quic" if udp && b.len() >= 7 && b[0] & 0xc0 == 0xc0 => 40,
            "icmp" if c.transport == Transport::Icmp => 100,
            _ => 0,
        }
    }
    fn session(&self) -> Box<dyn DecodeSession> {
        Box::new(NativeSession {
            kind: self.0,
            h2: internet::Http2::default(),
            http: internet::Http1::default(),
            astm: clinical::AstmSession::default(),
            tls_handshake: Vec::new(),
            dicom: clinical::DicomSession::default(),
        })
    }
}
struct NativeSession {
    kind: &'static str,
    h2: internet::Http2,
    http: internet::Http1,
    astm: clinical::AstmSession,
    tls_handshake: Vec<u8>,
    dicom: clinical::DicomSession,
}
impl DecodeSession for NativeSession {
    fn has_pending_message(&self) -> bool {
        match self.kind {
            "astm" => self.astm.has_pending_message(),
            "dicom" => self.dicom.has_pending_message(),
            "http2" => self.h2.has_pending_message(),
            "tls" => !self.tls_handshake.is_empty(),
            _ => false,
        }
    }
    fn buffered_bytes(&self) -> usize {
        self.astm.buffered_bytes()
            + self.tls_handshake.len()
            + if self.kind == "http2" {
                self.h2.buffered_bytes()
            } else {
                0
            }
            + self.http.buffered_bytes()
            + self.dicom.buffered_bytes()
    }
    fn on_peer_message(&mut self, message: &Message) {
        self.dicom.on_peer_message(message);
        self.http.on_peer_message(message);
    }
    fn decode(&mut self, b: &[u8], c: DecodeContext, eof: bool) -> DecodeResult {
        match self.kind {
            "hl7" => clinical::hl7(b, eof),
            "astm" => clinical::astm(b, eof, &mut self.astm, c.max_message),
            "poct" => clinical::poct(b, eof, c.max_message),
            "dicom" => self.dicom.decode(b, c.max_message),
            "http" => self.http.decode(b, eof, c.max_message),
            "http2" => self.h2.decode(b, c.max_message),
            "dns" => internet::dns(b, c.transport == Transport::Tcp),
            "dhcp" => internet::dhcp(b),
            "tls" => internet::tls(b, &mut self.tls_handshake, c.max_message),
            "quic" => internet::quic(b),
            "icmp" => internet::icmp(b, c.source_port),
            _ => DecodeResult::Invalid {
                consumed: b.len(),
                detail: "decoder unavailable".into(),
            },
        }
    }
}
pub(crate) fn message(protocol: &str, n: usize, fields: Value) -> DecodeResult {
    DecodeResult::Message {
        consumed: n,
        message: Message {
            protocol: protocol.into(),
            completeness: Completeness::Complete,
            fields,
            wire_len: n,
        },
    }
}
pub(crate) fn invalid(n: usize, s: impl Into<String>) -> DecodeResult {
    DecodeResult::Invalid {
        consumed: n,
        detail: s.into(),
    }
}
pub(crate) fn find(b: &[u8], needle: &[u8]) -> Option<usize> {
    b.windows(needle.len()).position(|w| w == needle)
}
pub(crate) fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ProtocolSupport {
    pub name: String,
    pub native: String,
    pub external: Option<String>,
}
pub fn support() -> Value {
    json!([
        {"name":"ethernet/vlan/ipv4/ipv6/tcp/udp","native":"headers and bounded reassembly"},
        {"name":"802.11/radiotap","native":"headers, management SSID, unprotected non-aggregated data","limitations":"protected, fragmented and A-MSDU payloads stay opaque"},
        {"name":"hl7","native":"MLLP, generic v2 ER7 fields, components, repetitions and escapes; ACK identifiers","limitations":"structural parsing, not every version's semantic conformance"},
        {"name":"astm","native":"E1381 framing/checksum and E1394 records","limitations":"vendor semantic profiles require fixtures"},
        {"name":"poct","native":"bounded XML message framing and attributes","limitations":"structural XML, not vendor-certified POCT conformance"},
        {"name":"dicom","native":"association negotiation, PDU/PDV, fragmented DIMSE commands, selected explicit/implicit LE and explicit BE dataset tags; pixel bytes skipped","limitations":"undefined-length sequences and unsupported transfer syntaxes stay opaque","external":"TShark for additional DIMSE/data-set dissection"},
        {"name":"http","native":"HTTP/1.x framing, chunked bodies, headers, HEAD/CONNECT response correlation","limitations":"upgraded/tunneled payloads stay opaque; request capture required for HEAD correlation"},
        {"name":"http2","native":"frames, continuations and bounded HPACK headers"},
        {"name":"dns/dhcp/icmp","native":"messages and selected inventory evidence"},
        {"name":"tls/quic","native":"record/long-header metadata and TLS ClientHello","external":"TShark with session secrets for supported encrypted sessions"},
        {"name":"http3","native":"none","external":"TShark QUIC/HTTP3 dissectors; session secrets generally required"}
    ])
}
