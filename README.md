# netKit

An embeddable network capture and protocol analysis framework written in Rust. It produces connection, device observation, application message, and diagnostic events from Ethernet and Wi-Fi traffic. The command-line tool is **`netkit`**; the project is **netKit**.

The library, CLI, and C ABI share the same analysis engine. The core is written in Rust, and C++ applications integrate through the [C header](include/netkit.h). No C++ implementation is required in the core. PCAP/PCAPNG file analysis works without a capture driver.

## Getting started

Requires Rust 1.86+ and a C linker for your platform. Use Visual Studio C++ Build Tools on Windows, or the standard development toolchain on Linux/macOS.

```powershell
cargo build --release --workspace
.\target\release\netkit.exe doctor
.\target\release\netkit.exe protocols
.\target\release\netkit.exe analyze tests\fixtures\clinical-network.pcapng
.\target\release\netkit.exe analyze tests\fixtures\clinical-network.pcapng --workers 4 --format jsonl
```

On Linux/macOS, use `./target/release/netkit` as the executable path. To install the CLI into Cargo's binary directory, which should be on your PATH:

```text
cargo install --path crates/netkit-cli --locked
netkit --help
```

Live capture on Windows uses a separately installed copy of [Npcap](https://npcap.com/guide/npcap-devguide.html). netKit builds without the Npcap SDK and loads `wpcap.dll` at runtime. Npcap is not bundled with this repository. Linux uses libpcap; macOS uses the system libpcap library. Permission to open a capture interface depends on the operating system and driver configuration.

## Commands

```text
netkit interfaces
netkit capture --all-interfaces --duration 60 --output network.pcapng --format jsonl
netkit capture -i 1 -i 2 --workers 4
netkit capture -i 1 --filter "host 192.168.1.37 and tcp" --count 1000
netkit capture -i 2 --monitor --duration 30 --packets
netkit devices --all-interfaces
netkit flows --read tests/fixtures/clinical-network.pcapng
netkit analyze network.pcapng --host 192.168.1.37 --format json
netkit read network.pcapng --protocol hl7
netkit analyze network.pcapng --decode-as astm
netkit decode tests/fixtures/synthetic.hl7 --protocol hl7
netkit config
netkit benchmark tests/fixtures/scale.pcapng --iterations 100 --format json
```

Live capture applies no IP or port filter by default. `--filter` applies a BPF expression at the capture backend; `--host` selects a specific address. `--protocol` filters output messages, while `--decode-as` forces a decoder. `--packets` also emits layer summaries for IP packets. `--output` writes raw PCAPNG; replacing an existing file requires `--overwrite`. `Ctrl+C` drains the queue and closes the output.

`devices` reports observed IP addresses and identity claims. `flows` reports bidirectional IP/port conversations, counters, and detected protocols. An IP address seen only as a destination is not proof of an online device; check the `evidence` field.

Active host and port discovery use explicit commands, separate from passive capture:

```text
netkit discover --network 192.168.1.0/24 --ports 80,443 --rate 50
netkit scan --target 192.168.1.37 --ports 1-65535 --tcp --rate 100
netkit scan --target 192.168.1.37 --ports 53,123 --udp
```

Established TCP connections and received UDP replies are reported as evidence. UDP silence produces `open_or_filtered`; a TCP timeout produces `no_response`. Scan scope, rate, concurrency, and total probe count are bounded. The regular `capture` and `devices` commands do not send scan probes.

## Traffic visibility

netKit processes all IP addresses and ports **within the packets delivered to the selected interfaces**. Observing unicast traffic between two other devices on a switched network requires a SPAN/mirror port, a network TAP, or a capture point along the traffic path. Being connected to the same network does not make every conversation visible.

Wi-Fi traffic in normal mode is commonly presented as Ethernet frames. Raw 802.11/Radiotap capture and monitor mode depend on hardware and driver support; switching to monitor mode can disconnect the Wi-Fi connection. Multi-interface capture opens each interface separately and preserves its source identity. The Linux `any` interface can be selected explicitly; `--all-interfaces` selects interfaces marked as up rather than `any` to reduce duplicate observations. Packets observed at different capture points are not automatically deduplicated.

Encrypted content is not automatically decrypted. Native TLS and QUIC analysis is limited to visible metadata. A separately installed TShark provides broader protocol coverage and can use a keylog file for supported sessions:

```text
netkit deep network.pcapng --keylog session.keylog --include-sensitive --format jsonl
```

This command passes through external TShark JSON output; the native event schema and redaction do not apply. See the [support matrix](docs/SUPPORT.md) for detailed coverage and limitations.

## Rust integration

```toml
[dependencies]
netkit = { path = "../netKit/crates/netkit" }
serde_json = "1"
```

```rust
use netkit::{Engine, EngineConfig, Result, pcap::CaptureReader};
use std::{fs::File, io::BufReader};

fn main() -> Result<()> {
    let mut engine = Engine::new(EngineConfig::default())?;
    let mut input = CaptureReader::new(
        BufReader::new(File::open("network.pcapng")?), "sensor-a"
    )?;
    while let Some(packet) = input.next_packet()? {
        for event in engine.ingest(&packet) {
            println!("{}", serde_json::to_string(&event)?);
        }
    }
    for event in engine.finish() {
        println!("{}", serde_json::to_string(&event)?);
    }
    Ok(())
}
```

Applications can supply their own `Packet` source, open a live interface through `capture::Pcap`, or use `pipeline::AnalysisPool`. Add custom protocols with the `Decoder` and `DecodeSession` traits. Decode application-provided message bytes with `Engine::decode_message` without opening a network connection. See the [API and architecture guide](docs/ARCHITECTURE.md), [runnable Rust examples](crates/netkit/examples), and [C++ example](examples/cpp/main.cpp).

```powershell
cargo run -p netkit --example decode
cmd /c tools\build_cpp.cmd
python tools\verify_ffi.py
```

## Validation and current status

The implementation includes capture-file readers and writers, a live capture backend, a flow engine, native decoders, a bounded parallel processing pipeline, active discovery, a CLI, and a C ABI. This does not imply complete support for every standard or device variant. Medical protocols are parsed structurally; vendor-profile conformance is not certified.

Synthetic captures, Rust tests, the ABI through the compiled DLL, and C++ compilation were verified locally on Windows x64. Real Npcap adapters, Linux/macOS live capture, TShark integration, a 24-hour hardware test, and comparisons against clinical devices were not validated in that environment. CI for all three platforms and a fuzz workflow are included in the repository; their presence alone is not evidence of successful execution. See the [validation record](docs/VALIDATION.md) for details.

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
cargo doc --workspace --no-deps
python tools/validate.py --seconds 120
```

Default output redacts HL7 segments, ASTM records, POCT XML fields, DICOM dataset values, and HTTP header values. Enable `--include-sensitive` or `EngineConfig.include_sensitive` to expose those details. Raw PCAPNG, IP/MAC addresses, hostnames, message control IDs, and custom decoder output are outside this redaction policy. Redaction does not guarantee anonymization or regulatory compliance. All test data in this repository is synthetic.

## License

netKit is dual-licensed under **MIT OR Apache-2.0**: [MIT](LICENSE-MIT), [Apache-2.0](LICENSE-APACHE). Commercial integration is permitted under those licenses. Dependencies retain their own licenses; Npcap and TShark are obtained separately. See the [contribution guide](CONTRIBUTING.md) and [security policy](SECURITY.md).
