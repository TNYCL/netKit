#![no_main]
use libfuzzer_sys::fuzz_target;
use netkit::pcap::CaptureReader;
use std::io::Cursor;
fuzz_target!(|bytes: &[u8]| {
    if bytes.len() > 1024 * 1024 {
        return;
    }
    if let Ok(mut reader) = CaptureReader::new(Cursor::new(bytes), "fuzz") {
        for _ in 0..4096 {
            match reader.next_packet() {
                Ok(Some(_)) => (),
                _ => break,
            }
        }
    }
});
