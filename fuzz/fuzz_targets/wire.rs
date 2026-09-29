#![no_main]
use libfuzzer_sys::fuzz_target;
use netkit::{Engine, EngineConfig, Packet, Source};
fuzz_target!(|bytes: &[u8]| {
    if bytes.len() > 65536 {
        return;
    }
    let mut engine = Engine::new(EngineConfig {
        max_flows: 8,
        max_devices: 16,
        max_flow_bytes: 65536,
        max_message_bytes: 32768,
        max_total_bytes: 262144,
        max_events_per_packet: 32,
        ..Default::default()
    })
    .unwrap();
    let links = [1, 101, 105, 127, 113, 276, 0, 108];
    for (i, chunk) in bytes.chunks(1024).enumerate() {
        let packet = Packet {
            source: Source {
                sensor: "fuzz".into(),
                interface: 0,
                link_type: links[bytes.first().copied().unwrap_or(0) as usize % links.len()],
            },
            timestamp_ns: i as u64 * 1_000_000,
            original_len: chunk.len() as u32,
            data: chunk.to_vec(),
        };
        let _ = engine.ingest(&packet);
    }
    let _ = engine.finish();
});
