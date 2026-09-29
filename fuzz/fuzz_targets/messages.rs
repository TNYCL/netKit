#![no_main]
use libfuzzer_sys::fuzz_target;
use netkit::{
    Engine, EngineConfig, ProtocolRegistry, Transport,
    protocols::{DecodeContext, DecodeResult},
};
fuzz_target!(|bytes: &[u8]| {
    if bytes.is_empty() || bytes.len() > 32768 {
        return;
    }
    let names = [
        "hl7", "astm", "poct", "dicom", "http", "http2", "dns", "dhcp", "tls", "quic", "icmp",
    ];
    let name = names[bytes[0] as usize % names.len()];
    let bytes = &bytes[1..];
    let engine = Engine::new(EngineConfig {
        max_message_bytes: 32768,
        ..Default::default()
    })
    .unwrap();
    let _ = engine.decode_message(name, bytes);
    let registry = ProtocolRegistry::default();
    let mut session = registry.get(name).unwrap().session();
    let context = DecodeContext {
        transport: Transport::Tcp,
        source_port: 0,
        destination_port: 0,
        max_message: 32768,
    };
    let mut pending = Vec::new();
    for chunk in bytes.chunks(31) {
        pending.extend_from_slice(chunk);
        for _ in 0..64 {
            match session.decode(&pending, context, false) {
                DecodeResult::Skip { consumed }
                | DecodeResult::Message { consumed, .. }
                | DecodeResult::Invalid { consumed, .. }
                    if consumed > 0 && consumed <= pending.len() =>
                {
                    pending.drain(..consumed);
                }
                _ => break,
            }
            if pending.is_empty() {
                break;
            }
        }
    }
    session.on_gap(None);
    session.on_close();
});
