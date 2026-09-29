# Contributing to netKit

Use Rust 1.86 or newer. Changes to decoders need synthetic byte fixtures proving framing, truncation, malformed lengths, split/coalesced messages, resource limits and privacy behavior. Preserve unknown/vendor fields when practical, and state unsupported variants explicitly in `docs/SUPPORT.md`. A parser accepting sample bytes is not proof of standards conformance.

Run `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace --locked`. Regenerate capture fixtures with `python tools/generate_fixtures.py`; all fixture data must be synthetic. Build the release DLL and run `python tools/verify_ffi.py` when changing the FFI. Header, exports, layout tests and C++ example must change together for ABI changes. Never unwind over the C boundary.

`fuzz/` contains cargo-fuzz targets for packet, stream, file and application-message surfaces. See its README. Keep reproducers small and commit a deterministic regression test for each parser defect. No unchecked allocation based on wire length; no unsafe code in parser/engine modules. Custom decoders must account for retained buffers.

Capture tests must name the OS, driver version, interface/link type, observation point, traffic generator and counter semantics. Performance reports must include packet size/protocol mix, loss, CPU/RSS, duration and whether I/O is included. Do not claim line-rate or all-platform support from synthetic file replay alone.

Changes are licensed MIT OR Apache-2.0 unless explicitly agreed otherwise. Third-party source and fixtures need compatible attribution and redistribution rights. The project name is netKit; crate/command identifiers use lowercase `netkit`. Registry names and public repository ownership have not been reserved by this local workspace.
