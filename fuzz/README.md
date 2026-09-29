# Fuzzing

Use nightly Rust and `cargo-fuzz` on Linux/macOS. The normal workspace does not require a sanitizer or libFuzzer.

```sh
cargo install cargo-fuzz --locked
cargo +nightly fuzz run wire -- -max_total_time=60 -max_len=65536
cargo +nightly fuzz run messages -- -max_total_time=60 -max_len=32768
cargo +nightly fuzz run capture_file -- -max_total_time=60 -max_len=1048576
```

Targets cover link/IP/transport plus engine state, complete/incremental protocol messages, and capture-file readers. The first message byte selects a decoder. Seed `capture_file` with the synthetic PCAPNG fixtures; for protocol seeds prepend the decoder index (HL7=0, ASTM=1, POCT=2, DICOM=3, HTTP=4, HTTP2=5, DNS=6, DHCP=7, TLS=8, QUIC=9, ICMP=10). Use valid synthetic packet sequences alongside random wire mutation to exercise deep reconstruction states.

Local Windows deterministic parser/noise/truncation tests are separate from libFuzzer. A configured target or CI job is not evidence that a long fuzz campaign completed. Record actual execution duration and findings in the validation log. Keep corpora and artifacts local until reviewed for sensitive data.
