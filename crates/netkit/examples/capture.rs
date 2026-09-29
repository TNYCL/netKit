//! cargo run -p netkit --example capture -- <interface-name>
use netkit::{
    Engine, EngineConfig,
    capture::{CaptureOptions, Pcap},
};
use std::time::{Duration, Instant};
fn main() -> netkit::Result<()> {
    let pcap = Pcap::load()?;
    let Some(interface) = std::env::args().nth(1) else {
        for interface in pcap.interfaces()? {
            println!("{}", interface.name);
        }
        return Ok(());
    };
    let mut capture = pcap.open(&CaptureOptions {
        interface,
        ..Default::default()
    })?;
    let mut engine = Engine::new(EngineConfig::default())?;
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(10) {
        if let Some(packet) = capture.next_packet()? {
            for event in engine.ingest(&packet) {
                println!("{}", serde_json::to_string(&event)?);
            }
        } else {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    let stats = capture.statistics()?;
    for event in engine
        .record_capture_loss(
            capture.source().clone(),
            stats.dropped as u64,
            stats.interface_dropped as u64,
            0,
        )
        .into_iter()
        .chain(engine.finish())
    {
        println!("{}", serde_json::to_string(&event)?);
    }
    Ok(())
}
