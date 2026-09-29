# Security reporting and data handling

Packet bytes, capture file fields and decoded strings are untrusted input. Use the configured resource limits and keep raw captures, TLS keylogs and unmasked clinical output out of public issues. Submit only synthetic or carefully minimized reproductions. No real patient data belongs in this repository.

This local project has no published security contact yet. Before public publication, the maintainer must configure a private vulnerability reporting channel. Do not post a working sensitive-data capture publicly to report a defect.

Expected boundaries: parsers do not execute input, XML DTD/entity declarations are rejected, the native driver is separately trusted executable code, and plugins run with their host's privileges. Masking is selective, not de-identification. Raw PCAPNG and external TShark output are unmasked. The default protocol metadata can still contain identifying operational information.

Coverage limitations, untested hardware and release acceptance checks are recorded in `docs/VALIDATION.md`. This SDK is an observer and integration component; no clinical diagnostic or treatment decision validation is claimed.
