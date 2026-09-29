# Protocol and platform support

This matrix distinguishes implemented native parsing from optional external parsing and unverified conformance. `netkit protocols --format json` exposes a compact runtime version. Unknown packets are retained in optional raw capture and observed as metadata/flows where their lower layers are understood.

| Area | Native implementation | Limits |
|---|---|---|
| Capture files | PCAP endian/microsecond/nanosecond variants; PCAPNG sections, interfaces, packet blocks; multi-interface nanosecond writer | No compressed capture reader; bounded block size; not every metadata option round-trips |
| Ethernet | Ethernet II, VLAN stacking, ARP | No generalized tunnel recursion or Ethernet FCS validation |
| Wi-Fi | 802.11/Radiotap, SSID, selected channel/signal metadata, unprotected non-aggregated data | Protected, fragmented and A-MSDU payloads remain opaque; no channel hopping/controller API |
| Other links | Raw IP, NULL/loopback, Linux SLL/SLL2 | Unsupported link types reported as opaque packet metadata |
| IPv4/IPv6 | Headers, supported IPv6 extension walk, bounded fragment reconstruction | No IPv6 jumbograms, IPsec decryption, full tunnel stack or checksum validation |
| TCP/UDP/ICMP | TCP reordering/retransmission/gaps, bidirectional flows, UDP boundaries, ICMP/NDP metadata | No active interception; unknown protocols remain unknown |
| HTTP/1.x | Headers, content length, chunked framing, pipelining, HEAD/CONNECT request correlation, close-delimited response at EOF | Body length rather than body extraction; upgrades/tunnels opaque; missing HEAD request can make response framing ambiguous |
| HTTP/2 | Preface, frame metadata, header continuation, bounded HPACK | Requires visible plaintext and header compression context; no complete stream/application state validator |
| DNS/mDNS/LLMNR | Names, bounded compression pointers, common RR values, UDP and TCP length framing | Default recognition uses port hints; force `dns` on unusual ports; not all RR types interpreted |
| DHCP | DHCPv4 cookie/options, client identity, hostname | DHCPv6 not native |
| TLS | Record metadata and reconstructed ClientHello SNI/ALPN/version extensions | No native decryption, certificate chain decoder, or cryptographic verification |
| QUIC | Long-header version/connection IDs | No native packet protection removal or HTTP/3; short-header traffic can remain unknown |
| HL7 v2.x | MLLP framing; generic ER7 delimiters, segments, fields, repetitions/components, known escapes, Z segments; ACK identifier/latency association | Structural parsing across v2 messages; no per-version/vendor conformance engine or full character-set conversion; UTF-8 validity exposed |
| ASTM E1381/E1394 | Control bytes, checksum, sequence/duplicate handling, ETB/ETX assembly, generic records | No serial-port capture backend; no device-specific clinical semantics or certified LIS01/LIS02 compliance |
| DICOM | Association/context negotiation, PDU/PDV, fragmented DIMSE command tags, selected dataset tags, streaming pixel skip | Explicit/implicit LE and explicit BE datasets; undefined-length nested sequences and unsupported syntax become opaque; no image codec, DICOMweb or full DIMSE transaction correlator |
| POCT1-A style XML | Bounded multi-document framing, XML names, paths, attributes, text/entity decoding | Generic structural XML, not a certified POCT workflow/state validator; also accepts other matching XML documents |
| Other protocols | Custom decoder API or separately installed TShark | A finite native decoder set cannot decode every protocol |

ASTM and HL7 input can also come from an application's serial/network stack using `decode_message` or a custom packet/session source. netKit does not operate a laboratory instrument, send protocol acknowledgments, or act as a DICOM/HL7 clinical endpoint.

## External dissectors

`netkit deep` launches a separately installed TShark without a shell, with bounded line and stderr buffers, and supports cancellation. It exposes the installed TShark build's dissectors, including HTTP/3 when the necessary capture/context/secrets are present. Providing a keylog does not guarantee a session can be decrypted. External outputs bypass native masking and therefore require `--include-sensitive`.

## Platform matrix

| Platform | Build design | Capture runtime | Local evidence |
|---|---|---|---|
| Windows x64 | Rust MSVC, runtime DLL loading | Npcap separately installed | Release build, SDK/CLI tests, compiled C++ and synthetic native ABI fixture passed; physical capture not run |
| Linux | Rust native toolchain, runtime `.so` loading | libpcap and appropriate capture permissions | CI configured; not executed in this Windows workspace |
| macOS | Rust native toolchain, system dylib loading | System libpcap and appropriate capture permissions | CI configured; not executed in this Windows workspace |

Wi-Fi monitor capability is queried per adapter. Hardware, driver, capture position and selected channel determine visibility. No blanket promise is made for every adapter or operating system version.

## Reference specifications

These links document wire formats and runtime behavior; inclusion does not assert certification or redistribute the standards themselves.

- [Npcap developer guide and monitor-mode behavior](https://npcap.com/guide/npcap-devguide.html)
- [libpcap upstream API documentation](https://github.com/the-tcpdump-group/libpcap)
- [DICOM PS3.8: Upper Layer Protocol](https://dicom.nema.org/medical/dicom/current/output/chtml/part08/chapter_9.html)
- [HL7 Version 2 standards](https://www.hl7.org/implement/standards/product_brief.cfm?product_id=185)
- [HTTP/1.1 RFC 9112](https://www.rfc-editor.org/rfc/rfc9112)
- [HTTP/2 RFC 9113](https://www.rfc-editor.org/rfc/rfc9113)
- [HPACK RFC 7541](https://www.rfc-editor.org/rfc/rfc7541)
- [IPv6 fragmentation RFC 8200](https://www.rfc-editor.org/rfc/rfc8200)
- [Wireshark TLS documentation](https://wiki.wireshark.org/TLS)

Licensed ASTM/CLSI standards and vendor integration guides are needed for formal profile verification. No proprietary standards text or real patient captures are bundled.
