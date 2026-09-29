# Validation record

Local environment: Windows 11 x64 (build 26200), Rust/Cargo 1.98.1, Visual Studio 2022 Build Tools. Record date: 2026-09-29. Package metadata is `0.1.0`; that version is a local Cargo identifier, not a claim that the full product acceptance criteria are satisfied.

## Executed checks

| Check | Result |
|---|---|
| `cargo fmt --all -- --check` | Passed |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | Passed |
| `cargo test --workspace --locked` | 42 passed; the separate native fixture test is ignored in the default run |
| Native capture fixture test with `NETKIT_TEST_PCAP` | 1 passed; actual compiled C DLL, not a Rust substitute |
| `cargo doc --workspace --no-deps --locked` | Passed |
| `cargo build --release --workspace --locked` | Passed; CLI, dynamic/static C ABI libraries produced |
| MSVC C++17 sample linked to the release DLL | Passed; decoded a synthetic HL7 message with default masking |
| Python `ctypes` against the actual DLL | 9 header exports found; ABI version, message decode, packet ingestion and ownership exercised |
| CLI synthetic capture with 1 and 4 analysis workers | 25 packets, 12 messages; expected protocol coverage and default masking verified |
| Custom Rust decoder example | Passed; arbitrary protocol registration and framed message decoding |
| `cargo check --manifest-path fuzz/Cargo.toml --locked` | All 3 libFuzzer targets compiled on Windows; no long coverage-guided campaign executed |
| Runtime `doctor` | Offline analysis available; Npcap and TShark absent on this host |

The native capture fixture validates C struct layout, microsecond-to-nanosecond conversion, immediate packet copying, null/error paths, BPF failure cleanup, unsupported monitor handling, metadata rejection and library lifetime. It does **not** demonstrate real driver operation, kernel capture, Wi-Fi reception or packet loss accuracy.

The regression suite covers TCP sequence wrap, first-seen overlap, retransmission, retransmitted SYN, split/coalesced MLLP, arbitrary medical ports, incomplete application state at EOF, IP fragmentation/overlap, file byte order/length checks, Radiotap protected frames, ASTM checksum/sequence/duplicates, XML entity/DTD handling, HTTP smuggling ambiguity and HEAD response framing, HPACK invalid table updates, fragmented DICOM commands, bounded pixel skipping, DNS compression loops, NDP/router MAC evidence, parallel flow ordering, bounds and synthetic malformed/truncated parser input. Active discovery tests use loopback sockets only.

## Replay measurement

`netkit benchmark tests/fixtures/scale.pcapng --seconds 120 --format json` completed a two-minute local replay. The fixture contains 400 small Ethernet packets across 200 HL7 flows. The measured workload includes file reading, parser work, device/flow bookkeeping and event construction; it discards output instead of writing JSON. An engine is created and finished for each repetition. This is a repeated replay benchmark, **not** a continuous 24-hour engine/driver soak or a NIC throughput measurement.

The exact final run, packet/message counts, elapsed time, throughput and retained-payload peak are in [replay-result.json](replay-result.json). Retained payload excludes allocator capacity, metadata, event JSON, driver buffers and queues; it must not be presented as peak RSS. No 1 Gbit/s guarantee is inferred from this result.

## Reproduce

```text
python tools/validate.py --seconds 120
cargo check --manifest-path fuzz/Cargo.toml --locked
```

The script writes full local logs under `artifacts/validation/` and stops on a nonzero check result. Dependency downloads must be available before running in an offline environment. Windows native tests require MSVC Build Tools. Unix C++/native-fixture commands are in `.github/workflows/ci.yml`.

To build a local SDK ZIP after validation: `python tools/package.py`. It includes source, executable, C ABI libraries/header, documentation, synthetic fixtures, license notices and SHA-256 sidecar. An existing ZIP is replaced only with `--overwrite`; nothing is published. Npcap/TShark are excluded.

## Outstanding product acceptance

These are release acceptance items, not an abbreviated product scope or a promise that all protocols are already complete:

- Real Windows Npcap capture on Ethernet, Wi-Fi and loopback; concurrent interfaces, BPF behavior, permission failures, orderly cancellation and driver loss counters compared with an independent capture.
- Linux/macOS build and capture verification on the declared toolchain/runtime matrix. The checked-in CI has not run from this local repository. Rust 1.86 is the declared minimum and matches dependency metadata, but only Rust 1.98.1 was executed here.
- A 24-hour continuous capture/reconstruction test with timestamp-aligned sources, measured process RSS/CPU, reconnections, adversarial fragmentation, sustained backpressure and controlled loss.
- Coverage-guided, sanitizer-enabled fuzz campaigns and independent review of native ABI ownership and all network parsers.
- Licensed-standard/vendor-profile validation for clinical message semantics and real device interoperability, using synthetic or appropriately de-identified fixtures. Undefined-length DICOM sequences, unsupported transfer syntaxes and vendor POCT workflows remain explicit limits.
- Real TShark subprocess/decryption tests with a compatible installation and synthetic keylogs; native HTTP/3 and TLS decryption are not implemented.
- Public repository/security contact configuration, registry/package naming checks, dependency/license audit and release provenance before external publication.

Implementation/support gaps such as serial-port capture, OUI/LLDP/SSDP/NetBIOS enrichment, universal tunnel support, native async adapters, C-side capture orchestration and vendor semantic validators are recorded in [SUPPORT.md](SUPPORT.md) and [ARCHITECTURE.md](ARCHITECTURE.md). Existing Rust extension points let integrations supply these without changing the packet/flow core; extension points do not count as those features being implemented.
