use netkit::{
    packet::{self, Fragment, NetworkPacket},
    pcap::{CaptureReader, CaptureWriter},
    protocols::{DecodeContext, DecodeResult},
    stream::{FragmentCache, TcpStream},
    *,
};
use serde_json::json;
use std::{
    io::Cursor,
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
};

fn config() -> EngineConfig {
    EngineConfig {
        include_sensitive: true,
        ..Default::default()
    }
}
fn source() -> Source {
    Source {
        sensor: "test".into(),
        interface: 1,
        link_type: 1,
    }
}
fn packet(data: Vec<u8>) -> Packet {
    Packet {
        source: source(),
        timestamp_ns: 1_000_000_000,
        original_len: data.len() as u32,
        data,
    }
}
fn ip_packet(proto: u8, body: &[u8], frag: u16, id: u16) -> Packet {
    let mut b = vec![0; 14 + 20];
    b[..6].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
    b[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
    b[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    b[14] = 0x45;
    b[16..18].copy_from_slice(&((20 + body.len()) as u16).to_be_bytes());
    b[18..20].copy_from_slice(&id.to_be_bytes());
    b[20..22].copy_from_slice(&frag.to_be_bytes());
    b[22] = 64;
    b[23] = proto;
    b[26..30].copy_from_slice(&[192, 168, 1, 37]);
    b[30..34].copy_from_slice(&[192, 168, 1, 82]);
    b.extend(body);
    packet(b)
}
fn tcp(seq: u32, flags: u8, body: &[u8]) -> Packet {
    let mut b = vec![0; 20];
    b[..2].copy_from_slice(&51024u16.to_be_bytes());
    b[2..4].copy_from_slice(&5100u16.to_be_bytes());
    b[4..8].copy_from_slice(&seq.to_be_bytes());
    b[12] = 0x50;
    b[13] = flags;
    b.extend(body);
    ip_packet(6, &b, 0, 1)
}
fn messages(events: &[Event]) -> Vec<&Message> {
    events
        .iter()
        .filter_map(|e| match &e.kind {
            EventKind::MessageDecoded { message, .. } => Some(message),
            _ => None,
        })
        .collect()
}
const HL7:&[u8]=b"\x0bMSH|^~\\&|DEMO|LAB|NETKIT|TEST|20260929||ORU^R01|TEST-1|P|2.5\rPID|1||SYNTHETIC^^^TEST||EXAMPLE^PERSON\rOBX|1|ST|X||A\\F\\B~C\rZNT|custom\r\x1c\r";

#[test]
fn hl7_structure_delimiters_and_redaction() {
    let decoded = Engine::new(config())
        .unwrap()
        .decode_message("hl7", HL7)
        .unwrap();
    let m = &decoded[0];
    assert_eq!(m.fields["version"], "2.5");
    assert_eq!(m.fields["control_id"], "TEST-1");
    assert_eq!(m.fields["segments"][0]["fields"][0]["number"], 1);
    assert_eq!(m.fields["segments"][2]["fields"][4]["value"], "A|B~C");
    assert_eq!(m.fields["segments"][3]["id"], "ZNT");
    let masked = Engine::new(EngineConfig::default())
        .unwrap()
        .decode_message("hl7", HL7)
        .unwrap();
    let serialized = serde_json::to_string(&masked).unwrap();
    assert!(!serialized.contains("EXAMPLE"));
    assert!(!serialized.contains("SYNTHETIC"));
    assert!(serialized.contains("redacted"));
}
#[test]
fn arbitrary_port_out_of_order_retransmission_and_coalesced_mllp() {
    let mut e = Engine::new(config()).unwrap();
    e.ingest(&tcp(100, 2, &[]));
    let mut payload = HL7.to_vec();
    payload.extend(HL7);
    let split = 23;
    assert!(messages(&e.ingest(&tcp(101 + split as u32, 0x18, &payload[split..]))).is_empty());
    let events = e.ingest(&tcp(101, 0x18, &payload[..split]));
    assert_eq!(messages(&events).len(), 2);
    assert!(
        messages(&events)
            .iter()
            .all(|m| m.completeness == Completeness::Complete)
    );
    let dup = e.ingest(&tcp(101, 0x18, &payload[..split]));
    assert!(messages(&dup).is_empty());
    assert!(
        dup.iter()
            .any(|e| matches!(&e.kind,EventKind::Diagnostic{code,..}if code=="tcp_retransmission"))
    );
    assert_eq!(e.flows()[0].key.b.port, 5100);
}
#[test]
fn every_mllp_split_reconstructs_exactly_one_message() {
    for split in 1..HL7.len() {
        let mut e = Engine::new(config()).unwrap();
        e.ingest(&tcp(0, 2, &[]));
        let a = e.ingest(&tcp(1, 0x18, &HL7[..split]));
        let b = e.ingest(&tcp(1 + split as u32, 0x18, &HL7[split..]));
        assert_eq!(messages(&a).len() + messages(&b).len(), 1, "split {split}");
    }
}
#[test]
fn sequence_wrap_and_first_seen_overlap() {
    let mut s = TcpStream::default();
    s.push(u32::MAX - 2, true, false, &[], 1024);
    let pending = s.push(1, false, false, b"def", 1024);
    assert!(pending.chunks.is_empty());
    let overlap = s.push(2, false, false, b"XX", 1024);
    assert!(
        overlap
            .diagnostics
            .iter()
            .any(|(code, _)| code == "tcp_overlap_conflict")
    );
    let out = s.push(u32::MAX - 1, false, false, b"abc", 1024);
    assert_eq!(out.chunks.concat(), b"abcdef");
}
#[test]
fn unresolved_gap_and_resource_limits_are_visible() {
    let mut s = TcpStream::default();
    s.push(0, true, false, &[], 1024);
    s.push(8, false, false, b"later", 1024);
    assert!(s.finish().gap);
    let mut e = Engine::new(EngineConfig {
        max_flows: 1,
        ..Default::default()
    })
    .unwrap();
    e.ingest(&tcp(0, 2, &[]));
    let mut other = tcp(0, 2, &[]);
    other.data[34..36].copy_from_slice(&51025u16.to_be_bytes());
    let ev = e.ingest(&other);
    assert_eq!(e.flows().len(), 1);
    assert_eq!(e.statistics().resource_evictions, 1);
    assert!(ev.iter().any(|v|matches!(&v.kind,EventKind::FlowClosed{flow}if flow.close_reason.as_deref()==Some("flow_limit"))));
}
#[test]
fn ipv4_fragments_reassemble_before_tcp() {
    let whole = tcp(5, 0x18, HL7);
    let ip = &whole.data[34..];
    let cut = 32;
    let second = ip_packet(6, &ip[cut..], (cut / 8) as u16, 77);
    let first = ip_packet(6, &ip[..cut], 0x2000, 77);
    let mut e = Engine::new(config()).unwrap();
    assert!(messages(&e.ingest(&second)).is_empty());
    let ev = e.ingest(&first);
    assert_eq!(messages(&ev).len(), 1);
    assert_eq!(messages(&ev)[0].protocol, "hl7");
}
#[test]
fn fragment_overlap_is_rejected() {
    let mut cache = FragmentCache::new(4, 65536, 100);
    let make = |offset, payload: Vec<u8>| NetworkPacket {
        src: "::1".parse().unwrap(),
        dst: "::2".parse().unwrap(),
        protocol: 17,
        payload,
        fragment: Some(Fragment {
            id: 7,
            offset,
            more: true,
        }),
    };
    assert!(
        cache
            .push(&source(), &[], make(0, vec![1; 16]), 0)
            .packet
            .is_none()
    );
    let bad = cache.push(&source(), &[], make(8, vec![2; 8]), 1);
    assert_eq!(bad.diagnostics.len(), 1);
    assert_eq!(cache.buffered_bytes(), 0);
}
#[test]
fn pcapng_roundtrip_multisource_nanoseconds_and_empty_packet() {
    let mut a = tcp(0, 2, &[]);
    a.timestamp_ns = 123456789012345;
    let mut b = a.clone();
    b.source.interface = 8;
    b.source.link_type = 101;
    b.data = b.data[14..].to_vec();
    b.original_len = b.data.len() as u32;
    let mut w = CaptureWriter::new(Vec::new()).unwrap();
    w.write_packet(&a).unwrap();
    w.write_packet(&b).unwrap();
    let mut r = CaptureReader::new(Cursor::new(w.into_inner()), "roundtrip").unwrap();
    let aa = r.next_packet().unwrap().unwrap();
    let bb = r.next_packet().unwrap().unwrap();
    assert_eq!(aa.data, a.data);
    assert_eq!(aa.timestamp_ns, a.timestamp_ns);
    assert_eq!(bb.source.link_type, 101);
    assert_ne!(aa.source.interface, bb.source.interface);
    assert!(r.next_packet().unwrap().is_none());
}
#[test]
fn pcap_big_endian_and_nanoseconds() {
    let mut b = vec![0xa1, 0xb2, 0x3c, 0x4d];
    b.extend(2u16.to_be_bytes());
    b.extend(4u16.to_be_bytes());
    b.extend([0; 8]);
    b.extend(65535u32.to_be_bytes());
    b.extend(101u32.to_be_bytes());
    b.extend(7u32.to_be_bytes());
    b.extend(123u32.to_be_bytes());
    b.extend(1u32.to_be_bytes());
    b.extend(1u32.to_be_bytes());
    b.push(0x45);
    let p = CaptureReader::new(Cursor::new(b), "be")
        .unwrap()
        .next_packet()
        .unwrap()
        .unwrap();
    assert_eq!(p.timestamp_ns, 7_000_000_123);
    assert_eq!(p.data, vec![0x45]);
}
#[test]
fn truncated_and_oversized_capture_blocks_fail() {
    let mut w = CaptureWriter::new(Vec::new()).unwrap();
    w.write_packet(&tcp(0, 2, &[])).unwrap();
    let original = w.into_inner();
    for cut in [1, 3, 8, 12, 27, original.len() - 1] {
        let value = original[..cut].to_vec();
        let result = CaptureReader::new(Cursor::new(value), "bad");
        if let Ok(mut r) = result {
            assert!(r.next_packet().is_err());
        }
    }
    let mut bytes = original;
    bytes[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(CaptureReader::new(Cursor::new(bytes), "bad").is_err());
}
fn astm_frame(text: &[u8], last: bool, number: u8) -> Vec<u8> {
    let mut frame = vec![2, b'0' + number];
    frame.extend(text);
    frame.push(if last { 3 } else { 23 });
    let sum = frame[1..].iter().fold(0u8, |a, b| a.wrapping_add(*b));
    frame.extend(format!("{sum:02X}\r\n").bytes());
    frame
}
#[test]
fn astm_checksum_and_multiframe_records() {
    let mut bytes = astm_frame(b"H|\\^&|||DEMO\rP|1|", false, 1);
    bytes.extend(astm_frame(b"SYNTHETIC\rR|1|X|42\rL|1|N\r", true, 2));
    let engine = Engine::new(config()).unwrap();
    let result = engine.decode_message("astm", &bytes).unwrap();
    assert_eq!(result.len(), 2);
    assert_eq!(result[1].fields["message"]["records"][2]["type"], "R");
    bytes[5] ^= 1;
    assert!(engine.decode_message("astm", &bytes).is_err());
}

#[test]
fn astm_duplicates_sequence_wrap_and_missing_frames() {
    let first = astm_frame(b"H|\\^&\r", false, 7);
    let last = astm_frame(b"L|1|N\r", true, 0);
    let mut bytes = first.clone();
    bytes.extend(&first);
    bytes.extend(last);
    let engine = Engine::new(config()).unwrap();
    let result = engine.decode_message("astm", &bytes).unwrap();
    assert_eq!(result[1].fields["duplicate_frame"], true);
    assert_eq!(
        result[2].fields["message"]["records"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let mut missing = astm_frame(b"H|\\^&\r", false, 1);
    missing.extend(astm_frame(b"L|1|N\r", true, 3));
    assert!(engine.decode_message("astm", &missing).is_err());
}

#[test]
fn consumed_astm_intermediate_frame_is_reported_incomplete_at_eof() {
    let mut engine = Engine::new(config()).unwrap();
    engine.ingest(&tcp(0, 2, &[]));
    engine.ingest(&tcp(1, 0x18, &astm_frame(b"H|\\^&\r", false, 1)));
    let events = engine.finish();
    assert!(events.iter().any(
        |e| matches!(&e.kind,EventKind::Diagnostic{code,..} if code=="incomplete_protocol_state")
    ));
    assert!(
        events
            .iter()
            .any(|e| matches!(&e.kind,EventKind::FlowClosed{flow} if flow.partial))
    );
}
#[test]
fn poct_multiple_xml_documents_and_dtd_rejection() {
    let engine = Engine::new(config()).unwrap();
    let m = engine
        .decode_message(
            "poct",
            b"<HEL.R01><DEV device_id=\"TEST\"/></HEL.R01><ACK.R01/> ",
        )
        .unwrap();
    assert_eq!(m.len(), 2);
    assert_eq!(m[0].fields["message_type"], "HEL.R01");
    assert_eq!(
        m[0].fields["elements"][1]["attributes"]["device_id"],
        "TEST"
    );
    assert!(
        engine
            .decode_message(
                "poct",
                b"<!DOCTYPE a [<!ENTITY x SYSTEM 'file:///secret'>]><a>&x;</a>"
            )
            .is_err()
    );
}
#[test]
fn dicom_association_and_echo_command() {
    let mut body = vec![0; 68];
    body[..2].copy_from_slice(&1u16.to_be_bytes());
    body[4..20].fill(b' ');
    body[20..36].fill(b' ');
    body[4..8].copy_from_slice(b"PACS");
    body[20..23].copy_from_slice(b"SCU");
    let mut assoc = vec![1, 0];
    assoc.extend((body.len() as u32).to_be_bytes());
    assoc.extend(body);
    let m = Engine::new(config())
        .unwrap()
        .decode_message("dicom", &assoc)
        .unwrap();
    assert_eq!(m[0].fields["called_ae"], "PACS");
    let mut pdu = vec![4, 0];
    let command = [0, 0, 0, 1, 2, 0, 0, 0, 0x30, 0];
    pdu.extend(16u32.to_be_bytes());
    pdu.extend(12u32.to_be_bytes());
    pdu.extend([1, 3]);
    pdu.extend(command);
    let m = Engine::new(config())
        .unwrap()
        .decode_message("dicom", &pdu)
        .unwrap();
    assert_eq!(
        m[0].fields["pdvs"][0]["command_tags"]["tags"][0]["command"],
        "C-ECHO"
    );
}
#[test]
fn http_chunked_pipeline_and_smuggling_rejection() {
    let engine = Engine::new(config()).unwrap();
    let bytes=b"POST /x HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nX-Test: ok\r\n\r\nGET /y HTTP/1.1\r\nHost: example.test\r\n\r\n";
    let m = engine.decode_message("http", bytes).unwrap();
    assert_eq!(m.len(), 2);
    assert_eq!(m[0].fields["body_length"], 3);
    assert_eq!(m[1].fields["target"], "/y");
    assert!(
        engine
            .decode_message(
                "http",
                b"POST / HTTP/1.1\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n"
            )
            .is_err()
    );
}
#[test]
fn http2_hpack_rfc_indexed_headers_and_malformed_update() {
    let engine = Engine::new(config()).unwrap();
    let frame = [0, 0, 3, 1, 4, 0, 0, 0, 1, 0x82, 0x86, 0x84];
    let m = engine.decode_message("http2", &frame).unwrap();
    assert_eq!(
        m[0].fields["headers"][0],
        json!({"name":":method","value":"GET"})
    );
    let truncated_update = [0, 0, 1, 1, 4, 0, 0, 0, 1, 0x3f];
    assert!(engine.decode_message("http2", &truncated_update).is_err());
}
#[test]
fn dns_compression_and_pointer_cycle() {
    let mut dns = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
    dns.extend(b"\x07example\x04test\0\0\x01\0\x01");
    dns.extend([0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1]);
    let mut framed = (dns.len() as u16).to_be_bytes().to_vec();
    framed.extend(&dns);
    let m = Engine::new(config())
        .unwrap()
        .decode_message("dns", &framed)
        .unwrap();
    assert_eq!(m[0].fields["records"][0]["value"], "192.0.2.1");
    dns[12] = 0xc0;
    dns[13] = 12;
    let mut framed = (dns.len() as u16).to_be_bytes().to_vec();
    framed.extend(dns);
    assert!(
        Engine::new(config())
            .unwrap()
            .decode_message("dns", &framed)
            .is_err()
    );
}
#[test]
fn radiotap_and_protected_wifi_metadata() {
    let mut b = vec![0, 0, 8, 0, 0, 0, 0, 0];
    b.extend([0x08, 0x40]);
    b.extend([0; 22]);
    let mut p = packet(b);
    p.source.link_type = 127;
    let parsed = packet::parse(&p).unwrap();
    assert_eq!(parsed.layers["wifi"]["protected"], true);
    assert!(parsed.network.is_none());
}
struct Toy;
struct ToySession;
impl Decoder for Toy {
    fn name(&self) -> &str {
        "toy"
    }
    fn probe(&self, b: &[u8], _: DecodeContext) -> u8 {
        if b.starts_with(b"TOY:") { 100 } else { 0 }
    }
    fn session(&self) -> Box<dyn netkit::protocols::DecodeSession> {
        Box::new(ToySession)
    }
}
impl netkit::protocols::DecodeSession for ToySession {
    fn decode(&mut self, b: &[u8], _: DecodeContext, _: bool) -> DecodeResult {
        if let Some(n) = b.iter().position(|c| *c == b'\n') {
            DecodeResult::Message {
                consumed: n + 1,
                message: Message {
                    protocol: "toy".into(),
                    completeness: Completeness::Complete,
                    wire_len: n + 1,
                    fields: json!({"value":String::from_utf8_lossy(&b[4..n])}),
                },
            }
        } else {
            DecodeResult::NeedMore
        }
    }
}
#[test]
fn external_decoder_plugin_is_used_on_arbitrary_ports() {
    let mut registry = ProtocolRegistry::default();
    registry.register(Arc::new(Toy));
    let mut e = Engine::with_registry(config(), registry).unwrap();
    e.ingest(&tcp(1, 2, &[]));
    let ev = e.ingest(&tcp(2, 0x18, b"TOY:hello\n"));
    assert_eq!(messages(&ev)[0].fields["value"], "hello");
}
#[test]
fn parser_noise_and_every_truncation_do_not_panic() {
    let registry = ProtocolRegistry::default();
    let ctx = DecodeContext {
        transport: Transport::Tcp,
        source_port: 53,
        destination_port: 5000,
        max_message: 4096,
    };
    let mut seed = 0x5eed_u64;
    for size in 0..512 {
        let mut bytes = Vec::new();
        for _ in 0..size {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            bytes.push(seed as u8);
        }
        for name in registry.names() {
            let mut session = registry.get(&name).unwrap().session();
            let _ = session.decode(&bytes, ctx, true);
        }
        for link in [1, 0, 101, 105, 127, 113, 276] {
            let mut p = packet(bytes.clone());
            p.source.link_type = link;
            let _ = packet::parse(&p);
        }
    }
    let mut e = Engine::new(config()).unwrap();
    for n in 0..HL7.len() {
        let p = tcp(100, 0x18, &HL7[..n]);
        let _ = e.ingest(&p);
    }
    let _ = e.finish();
}
#[test]
fn tcp_ack_only_does_not_seed_wrong_sequence() {
    let mut stream = TcpStream::default();
    stream.push(500, false, false, &[], 1000);
    let result = stream.push(100, false, false, b"data", 1000);
    assert_eq!(result.chunks.concat(), b"data");
    assert!(stream.started_midstream);
}
#[test]
fn ip_addresses_are_not_assigned_router_macs() {
    let mut engine = Engine::new(config()).unwrap();
    engine.ingest(&tcp(1, 2, &[]));
    assert!(engine.devices().iter().all(|d| d.mac.is_none()));
    assert!(
        engine
            .devices()
            .iter()
            .any(|d| d.ip == IpAddr::V4(Ipv4Addr::new(192, 168, 1, 37)))
    );
}

#[test]
fn xml_entities_and_parent_text_are_preserved() {
    let messages = Engine::new(config())
        .unwrap()
        .decode_message(
            "poct",
            b"<OBS.R01>before<value>A&amp;B&#x21;</value>after</OBS.R01>",
        )
        .unwrap();
    assert_eq!(messages[0].fields["elements"][0]["text"], "beforeafter");
    assert_eq!(messages[0].fields["elements"][1]["text"], "A&B!");
}

#[test]
fn parallel_workers_preserve_flow_order_and_unique_event_ids() {
    let mut pool =
        netkit::pipeline::AnalysisPool::new(config(), ProtocolRegistry::default(), 4, 2).unwrap();
    let mut events = Vec::new();
    for host in 1..=40u8 {
        let mut syn = tcp(100, 2, &[]);
        syn.data[29] = host;
        pool.submit(syn, |event| {
            events.push(event);
            Ok(())
        })
        .unwrap();
        let split = HL7.len() / 2;
        for (seq, bytes) in [(101 + split as u32, &HL7[split..]), (101, &HL7[..split])] {
            let mut p = tcp(seq, 0x18, bytes);
            p.data[29] = host;
            pool.submit(p, |event| {
                events.push(event);
                Ok(())
            })
            .unwrap();
        }
    }
    pool.finish(|event| {
        events.push(event);
        Ok(())
    })
    .unwrap();
    assert_eq!(
        messages(&events)
            .iter()
            .filter(|m| m.protocol == "hl7")
            .count(),
        40
    );
    let unique: std::collections::HashSet<_> = events.iter().map(|e| e.sequence).collect();
    assert_eq!(unique.len(), events.len());
}

#[test]
fn dicom_fragmented_command_and_pixel_stream_remain_bounded() {
    fn pdu(kind: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![kind, 0];
        v.extend((body.len() as u32).to_be_bytes());
        v.extend(body);
        v
    }
    fn pdv(flags: u8, bytes: &[u8]) -> Vec<u8> {
        let mut v = ((bytes.len() + 2) as u32).to_be_bytes().to_vec();
        v.extend([1, flags]);
        v.extend(bytes);
        pdu(4, &v)
    }
    let registry = ProtocolRegistry::default();
    let mut session = registry.get("dicom").unwrap().session();
    let ctx = DecodeContext {
        transport: Transport::Tcp,
        source_port: 1,
        destination_port: 2,
        max_message: 4096,
    };
    let syntax = b"1.2.840.10008.1.2.1";
    let mut context = vec![1, 0, 0, 0, 0x40, 0];
    context.extend((syntax.len() as u16).to_be_bytes());
    context.extend(syntax);
    let mut ac = vec![0; 68];
    ac[..2].copy_from_slice(&1u16.to_be_bytes());
    ac.extend([0x21, 0]);
    ac.extend((context.len() as u16).to_be_bytes());
    ac.extend(context);
    assert!(matches!(
        session.decode(&pdu(2, &ac), ctx, false),
        DecodeResult::Message { .. }
    ));
    let command = [0, 0, 0, 1, 2, 0, 0, 0, 0x30, 0];
    let first = session.decode(&pdv(1, &command[..5]), ctx, false);
    assert!(matches!(first, DecodeResult::Message { .. }));
    let last = session.decode(&pdv(3, &command[5..]), ctx, false);
    match last {
        DecodeResult::Message { message, .. } => assert_eq!(
            message.fields["pdvs"][0]["command_tags"]["tags"][0]["command"],
            "C-ECHO"
        ),
        _ => panic!("expected command"),
    }
    let mut dataset = vec![0x10, 0, 0x10, 0, b'P', b'N', 8, 0];
    dataset.extend(b"TEST^ONE");
    dataset.extend([0xe0, 0x7f, 0x10, 0, b'O', b'B', 0, 0]);
    dataset.extend(200_000u32.to_le_bytes());
    dataset.extend(vec![0x42; 200_000]);
    let mut saw_pixel = false;
    let mut saw_name = false;
    let chunks: Vec<_> = dataset.chunks(511).collect();
    for (i, chunk) in chunks.iter().enumerate() {
        match session.decode(
            &pdv(if i + 1 == chunks.len() { 2 } else { 0 }, chunk),
            ctx,
            false,
        ) {
            DecodeResult::Message { message, .. } => {
                for tag in message.fields["pdvs"][0]["dataset_tags"]
                    .as_array()
                    .unwrap()
                {
                    saw_pixel |= tag["pixel_data_skipped"] == true;
                    saw_name |= tag["value"] == "TEST^ONE";
                }
                if i + 1 == chunks.len() {
                    assert_eq!(message.fields["pdvs"][0]["dataset_complete"], true);
                }
            }
            _ => panic!("expected dataset PDU"),
        };
        assert!(session.buffered_bytes() < 8192);
    }
    assert!(saw_pixel && saw_name);
}

#[test]
fn retransmitted_syn_does_not_reset_a_live_connection() {
    let mut engine = Engine::new(config()).unwrap();
    engine.ingest(&tcp(100, 2, &[]));
    engine.ingest(&tcp(101, 0x18, HL7));
    let events = engine.ingest(&tcp(100, 2, &[]));
    assert!(
        !events
            .iter()
            .any(|e| matches!(e.kind, EventKind::FlowClosed { .. }))
    );
}

#[test]
fn coalesced_messages_larger_than_buffer_are_consumed_incrementally() {
    let mut engine = Engine::new(EngineConfig {
        max_message_bytes: 256,
        max_flow_bytes: 1024,
        ..config()
    })
    .unwrap();
    engine.ingest(&tcp(0, 2, &[]));
    let payload = HL7.repeat(5);
    let events = engine.ingest(&tcp(1, 0x18, &payload));
    assert_eq!(messages(&events).len(), 5);
    assert_eq!(engine.statistics().stream_gaps, 0);
    assert!(engine.buffered_bytes() <= 1024);
}

#[test]
fn http_head_response_does_not_consume_the_next_response_as_body() {
    fn reverse(mut p: Packet) -> Packet {
        for i in 0..4 {
            p.data.swap(26 + i, 30 + i);
        }
        for i in 0..2 {
            p.data.swap(34 + i, 36 + i);
        }
        p
    }
    let mut e = Engine::new(config()).unwrap();
    e.ingest(&tcp(0, 2, &[]));
    e.ingest(&reverse(tcp(0, 0x12, &[])));
    e.ingest(&tcp(
        1,
        0x18,
        b"HEAD / HTTP/1.1\r\nHost: test\r\n\r\nGET / HTTP/1.1\r\nHost: test\r\n\r\n",
    ));
    let events=e.ingest(&reverse(tcp(1,0x18,b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nTEST")));
    let decoded = messages(&events);
    assert_eq!(decoded.len(), 2);
    assert_eq!(decoded[0].fields["body_length"], 0);
    assert_eq!(decoded[1].fields["body_length"], 4);
}

#[test]
fn ndp_solicitation_does_not_assign_sender_mac_to_the_target() {
    let mut data = vec![0; 14 + 40 + 32];
    data[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
    data[14] = 0x60;
    data[18..20].copy_from_slice(&32u16.to_be_bytes());
    data[20] = 58;
    data[21] = 255;
    let source: std::net::Ipv6Addr = "fe80::1".parse().unwrap();
    let target: std::net::Ipv6Addr = "fe80::2".parse().unwrap();
    data[22..38].copy_from_slice(&source.octets());
    data[38..54].copy_from_slice(&target.octets());
    data[54] = 135;
    data[62..78].copy_from_slice(&target.octets());
    data[78..86].copy_from_slice(&[1, 1, 2, 0, 0, 0, 0, 1]);
    let mut e = Engine::new(config()).unwrap();
    e.ingest(&packet(data.clone()));
    assert!(e.devices().iter().all(|d| d.mac.is_none()));
    data[54] = 136;
    data[78] = 2;
    e.ingest(&packet(data));
    assert_eq!(
        e.devices()
            .iter()
            .find(|d| d.ip == IpAddr::V6(target))
            .unwrap()
            .mac
            .as_deref(),
        Some("02:00:00:00:00:01")
    );
}

#[test]
fn finish_events_do_not_claim_an_unrelated_packet_id() {
    let mut e = Engine::new(config()).unwrap();
    e.ingest(&tcp(1, 0x18, b"unrecognized"));
    let mut other = tcp(2, 0x18, b"other");
    other.source.interface = 2;
    e.ingest(&other);
    for event in e.finish() {
        if matches!(event.kind, EventKind::MessageDecoded { .. }) {
            assert!(event.packet_id.is_none());
        }
    }
}
