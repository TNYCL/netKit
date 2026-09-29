use super::{DecodeResult, find, invalid, message, text};
use crate::packet::{be16, be32};
use quick_xml::{Reader, events::Event};
use serde_json::{Value, json};
include!("dicom_stream.rs");

fn unescape_hl7(s: &str, sep: [char; 5]) -> String {
    let parts: Vec<_> = s.split(sep[3]).collect();
    parts
        .iter()
        .enumerate()
        .map(|(i, p)| {
            if i % 2 == 0 {
                p.to_string()
            } else {
                match *p {
                    "F" => sep[0].to_string(),
                    "S" => sep[1].to_string(),
                    "R" => sep[2].to_string(),
                    "E" => sep[3].to_string(),
                    "T" => sep[4].to_string(),
                    v if v.starts_with('X') && v.len() % 2 == 1 => {
                        let bytes: Option<Vec<u8>> = v.as_bytes()[1..]
                            .chunks(2)
                            .map(|b| {
                                std::str::from_utf8(b)
                                    .ok()
                                    .and_then(|v| u8::from_str_radix(v, 16).ok())
                            })
                            .collect();
                        bytes
                            .map(|b| text(&b))
                            .unwrap_or_else(|| format!("{}{}{}", sep[3], p, sep[3]))
                    }
                    _ => format!("{}{}{}", sep[3], p, sep[3]),
                }
            }
        })
        .collect()
}

/// Parse HL7 ER7 without discarding custom segments, repeated fields or unknown
/// escape sequences. This is a structural parser, not a clinical validator.
pub fn parse_hl7(b: &[u8]) -> Result<Value, String> {
    if b.len() < 8 || !b.starts_with(b"MSH") {
        return Err("HL7 message must begin with MSH and encoding characters".into());
    }
    let sep = [
        b[3] as char,
        b[4] as char,
        b[5] as char,
        b[6] as char,
        b[7] as char,
    ];
    if sep.iter().any(|c| !c.is_ascii_graphic())
        || sep.iter().enumerate().any(|(i, c)| sep[..i].contains(c))
    {
        return Err("HL7 delimiters must be distinct printable ASCII".into());
    }
    if b.iter()
        .filter(|v| sep.iter().any(|s| *s as u8 == **v))
        .count()
        > 32768
    {
        return Err("HL7 field/component expansion limit exceeded".into());
    }
    let s = text(b);
    let mut segments = Vec::new();
    let mut count = 0usize;
    let mut message_type = String::new();
    let mut control_id = String::new();
    let mut version = String::new();
    let mut acknowledgement = Value::Null;
    for line in s.split('\r').filter(|s| !s.trim_matches('\n').is_empty()) {
        let line = line.trim_start_matches('\n');
        let raw: Vec<_> = line.split(sep[0]).collect();
        if raw[0].len() != 3
            || !raw[0]
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
        {
            return Err("invalid HL7 segment identifier".into());
        }
        let mut fields = Vec::new();
        if raw[0] == "MSH" {
            fields.push(json!({"number":1,"value":sep[0].to_string()}));
            message_type = raw.get(8).unwrap_or(&"").to_string();
            control_id = raw.get(9).unwrap_or(&"").to_string();
            version = raw.get(11).unwrap_or(&"").to_string();
        }
        if raw[0] == "MSA" {
            acknowledgement = json!({"code":raw.get(1),"control_id":raw.get(2),"text":raw.get(3)});
        }
        for (i, field) in raw.iter().enumerate().skip(1) {
            count += 1;
            if count > 32768 {
                return Err("HL7 field limit exceeded".into());
            }
            let number = if raw[0] == "MSH" { i + 1 } else { i };
            if raw[0] == "MSH" && i == 1 {
                fields.push(json!({"number":number,"value":field}));
                continue;
            }
            let repeats: Vec<Value> = field
                .split(sep[2])
                .map(|r| {
                    let components: Vec<Value> = r
                        .split(sep[1])
                        .map(|c| {
                            json!(
                                c.split(sep[4])
                                    .map(|s| unescape_hl7(s, sep))
                                    .collect::<Vec<_>>()
                            )
                        })
                        .collect();
                    json!(components)
                })
                .collect();
            fields.push(
                json!({"number":number,"value":unescape_hl7(field,sep),"repetitions":repeats}),
            );
        }
        segments.push(json!({"id":raw[0],"fields":fields}));
    }
    Ok(
        json!({"message_type":message_type,"control_id":control_id,"version":version,"acknowledgement":acknowledgement,"encoding_valid_utf8":std::str::from_utf8(b).is_ok(),"segments":segments}),
    )
}
pub fn hl7(b: &[u8], eof: bool) -> DecodeResult {
    let (start, end, used) = if b.first() == Some(&0x0b) {
        let Some(end) = find(&b[1..], &[0x1c, 0x0d]).map(|i| i + 1) else {
            return if eof {
                invalid(b.len(), "incomplete MLLP frame")
            } else {
                DecodeResult::NeedMore
            };
        };
        (1, end, end + 2)
    } else {
        if !eof {
            return DecodeResult::NeedMore;
        }
        (0, b.len(), b.len())
    };
    match parse_hl7(&b[start..end]) {
        Ok(fields) => message("hl7", used, fields),
        Err(e) => invalid(used, e),
    }
}

pub fn parse_astm_records(b: &[u8]) -> Value {
    let s = text(b);
    let separator = s.as_bytes().get(1).copied().unwrap_or(b'|') as char;
    let records: Vec<_> = s
        .split('\r')
        .filter(|s| !s.trim().is_empty())
        .map(|line| {
            let fields: Vec<_> = line.split(separator).collect();
            json!({"type":fields[0],"fields":fields.iter().skip(1).collect::<Vec<_>>()})
        })
        .collect();
    json!({"records":records})
}
#[derive(Default)]
pub struct AstmSession {
    assembly: Vec<u8>,
    previous: Vec<u8>,
    sequence: Option<u8>,
}
impl AstmSession {
    pub fn has_pending_message(&self) -> bool {
        !self.assembly.is_empty()
    }
    pub fn buffered_bytes(&self) -> usize {
        self.assembly.len() + self.previous.len()
    }
}
pub fn astm(b: &[u8], eof: bool, state: &mut AstmSession, max: usize) -> DecodeResult {
    let assembly = &mut state.assembly;
    if b.is_empty() {
        return DecodeResult::NeedMore;
    }
    if matches!(b[0], 0x05 | 0x06 | 0x15 | 0x04) {
        let control = match b[0] {
            5 => "ENQ",
            6 => "ACK",
            21 => "NAK",
            _ => "EOT",
        };
        let mut fields = json!({"control":control});
        if matches!(b[0], 4 | 5) && !assembly.is_empty() {
            fields["incomplete_records"] = parse_astm_records(assembly);
            assembly.clear();
        }
        if matches!(b[0], 4 | 5) {
            state.previous.clear();
            state.sequence = None;
        }
        return message("astm", 1, fields);
    }
    if b[0] != 2 {
        return if eof && b.starts_with(b"H|") {
            message("astm", b.len(), parse_astm_records(b))
        } else if eof {
            invalid(b.len(), "missing ASTM STX")
        } else {
            DecodeResult::NeedMore
        };
    }
    if b.len() < 3 {
        return DecodeResult::NeedMore;
    }
    if !(b'0'..=b'7').contains(&b[1]) {
        return invalid(2, "ASTM frame number must be 0..7");
    }
    let Some(end) = b
        .iter()
        .enumerate()
        .skip(2)
        .find_map(|(i, v)| if matches!(v, 3 | 23) { Some(i) } else { None })
    else {
        return DecodeResult::NeedMore;
    };
    if b.len() < end + 5 {
        return DecodeResult::NeedMore;
    }
    if b[end + 3..end + 5] != [13, 10] {
        return invalid(end + 5, "ASTM frame missing CR/LF");
    }
    let expected = b[1..=end].iter().fold(0u8, |a, v| a.wrapping_add(*v));
    let received = std::str::from_utf8(&b[end + 1..end + 3])
        .ok()
        .and_then(|s| u8::from_str_radix(s, 16).ok());
    if received != Some(expected) {
        assembly.clear();
        return invalid(
            end + 5,
            format!("ASTM checksum mismatch: expected {expected:02X}"),
        );
    }
    let sequence = b[1] - b'0';
    if state.sequence == Some(sequence) && state.previous == b[..end + 5] {
        return message(
            "astm",
            end + 5,
            json!({"frame_number":sequence,"checksum_valid":true,"duplicate_frame":true}),
        );
    }
    if state
        .sequence
        .is_some_and(|previous| sequence != (previous + 1) % 8)
    {
        assembly.clear();
        state.previous.clear();
        state.sequence = None;
        return invalid(end + 5, "ASTM missing or conflicting frame sequence");
    }
    state.sequence = Some(sequence);
    state.previous = b[..end + 5].to_vec();
    if assembly.len() + end - 2 > max {
        assembly.clear();
        return invalid(end + 5, "ASTM message exceeds configured bound");
    }
    assembly.extend(&b[2..end]);
    let mut fields =
        json!({"frame_number":b[1]-b'0',"checksum_valid":true,"final_frame":b[end]==3});
    if b[end] == 3 {
        fields["message"] = parse_astm_records(assembly);
        assembly.clear();
    }
    message("astm", end + 5, fields)
}

pub fn poct(b: &[u8], eof: bool, max: usize) -> DecodeResult {
    let whitespace = b.iter().take_while(|v| v.is_ascii_whitespace()).count();
    if whitespace > 0 {
        return DecodeResult::Skip {
            consumed: whitespace,
        };
    }
    if b.len() > max {
        return invalid(b.len(), "XML message limit exceeded");
    }
    let mut reader = Reader::from_reader(b);
    reader.config_mut().check_end_names = true;
    let mut depth = 0usize;
    let mut root = String::new();
    let mut elements = Vec::new();
    let mut stack: Vec<String> = Vec::new();
    let mut indices: Vec<usize> = Vec::new();
    let mut complete = None;
    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                // Determine empty tags from the original consumed bytes; Reader's
                // event enum is matched separately by checking the closing token.
                let end = reader.buffer_position() as usize;
                let empty = b.get(end.saturating_sub(2)..end) == Some(b"/>");
                let name = e.name().as_ref().to_owned();
                if root.is_empty() {
                    root = name.clone();
                }
                let mut attrs = serde_json::Map::new();
                for attr in e.attributes() {
                    match attr {
                        Ok(a) => match a.normalized_value(quick_xml::XmlVersion::Implicit1_0) {
                            Ok(v) => {
                                attrs.insert(a.key.as_ref().to_owned(), json!(v));
                            }
                            Err(e) => return invalid(end, e.to_string()),
                        },
                        Err(e) => return invalid(end, e.to_string()),
                    }
                }
                stack.push(name.clone());
                indices.push(elements.len());
                elements.push(json!({"path":stack.join("/"),"name":name,"attributes":attrs}));
                if elements.len() > 16384 || depth >= 64 {
                    return invalid(end, "XML element/depth limit exceeded");
                }
                if empty {
                    stack.pop();
                    indices.pop();
                    if depth == 0 {
                        complete = Some(end);
                        break;
                    }
                } else {
                    depth += 1;
                }
            }
            Ok(Event::End(_)) => {
                if depth == 0 {
                    return invalid(
                        reader.buffer_position() as usize,
                        "unexpected XML closing tag",
                    );
                }
                depth -= 1;
                stack.pop();
                indices.pop();
                if depth == 0 {
                    complete = Some(reader.buffer_position() as usize);
                    break;
                }
            }
            Ok(Event::Text(t)) => {
                append_xml_text(&mut elements, indices.last().copied(), t.as_ref());
            }
            Ok(Event::CData(t)) => {
                append_xml_text(&mut elements, indices.last().copied(), t.as_ref());
            }
            Ok(Event::DocType(_)) => {
                return invalid(
                    reader.buffer_position() as usize,
                    "XML DTDs are not accepted",
                );
            }
            Ok(Event::GeneralRef(r)) => {
                let name = r.as_ref();
                let character = match name {
                    "amp" => Some('&'),
                    "lt" => Some('<'),
                    "gt" => Some('>'),
                    "apos" => Some('\''),
                    "quot" => Some('"'),
                    _ => match r.resolve_char_ref() {
                        Ok(c) => c,
                        Err(e) => return invalid(reader.buffer_position() as usize, e.to_string()),
                    },
                };
                if let Some(character) = character {
                    append_xml_text(
                        &mut elements,
                        indices.last().copied(),
                        &character.to_string(),
                    );
                } else {
                    return invalid(reader.buffer_position() as usize, "unresolved XML entity");
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                return if eof {
                    invalid(b.len(), e.to_string())
                } else {
                    DecodeResult::NeedMore
                };
            }
            _ => (),
        }
    }
    match complete {
        Some(n) => message("poct", n, json!({"message_type":root,"elements":elements})),
        None if eof => invalid(b.len(), "incomplete XML document"),
        None => DecodeResult::NeedMore,
    }
}

fn append_xml_text(elements: &mut [Value], index: Option<usize>, value: &str) {
    if let Some(i) = index {
        let mut text = elements[i]["text"].as_str().unwrap_or("").to_owned();
        text.push_str(value);
        elements[i]["text"] = json!(text);
    }
}

pub fn dicom(b: &[u8], max: usize) -> DecodeResult {
    if b.len() < 6 {
        return DecodeResult::NeedMore;
    }
    let len = be32(&b[2..]) as usize;
    if len > max {
        return invalid(6, "DICOM PDU exceeds message bound");
    }
    if b.len() < 6 + len {
        return DecodeResult::NeedMore;
    }
    if !(1..=7).contains(&b[0]) || b[1] != 0 {
        return invalid(6 + len, "invalid DICOM PDU header");
    }
    let body = &b[6..6 + len];
    let mut fields = json!({"pdu_type":b[0],"pdu_name":match b[0]{1=>"A-ASSOCIATE-RQ",2=>"A-ASSOCIATE-AC",3=>"A-ASSOCIATE-RJ",4=>"P-DATA-TF",5=>"A-RELEASE-RQ",6=>"A-RELEASE-RP",_=>"A-ABORT"},"length":len});
    match b[0] {
        1 | 2 => {
            if body.len() < 68 {
                return invalid(6 + len, "short DICOM association");
            }
            fields["protocol_version"] = json!(be16(body));
            fields["called_ae"] = json!(text(&body[4..20]).trim());
            fields["calling_ae"] = json!(text(&body[20..36]).trim());
            match dicom_items(&body[68..], 0) {
                Ok(v) => fields["items"] = v,
                Err(e) => return invalid(6 + len, e),
            }
        }
        3 | 7 => {
            if len != 4 {
                return invalid(6 + len, "invalid DICOM reject/abort length");
            }
            fields["result"] = json!(body[1]);
            fields["source"] = json!(body[2]);
            fields["reason"] = json!(body[3]);
        }
        5 | 6 => {
            if len != 4 {
                return invalid(6 + len, "invalid DICOM release length");
            }
        }
        4 => {
            let mut pdvs = Vec::new();
            let mut p = 0;
            while p < body.len() {
                if p + 4 > body.len() {
                    return invalid(6 + len, "truncated PDV length");
                }
                let size = be32(&body[p..]) as usize;
                p += 4;
                if size < 2 || size > body.len() - p {
                    return invalid(6 + len, "invalid DICOM PDV length");
                }
                let value = &body[p + 2..p + size];
                let command = body[p + 1] & 1 != 0;
                let mut pdv = json!({"context_id":body[p],"command":command,"last_fragment":body[p+1]&2!=0,"data_length":value.len()});
                if command {
                    pdv["command_tags"] = dicom_command(value);
                }
                pdvs.push(pdv);
                if pdvs.len() > 16384 {
                    return invalid(6 + len, "DICOM PDV count limit");
                }
                p += size;
            }
            fields["pdvs"] = json!(pdvs);
        }
        _ => (),
    }
    message("dicom", 6 + len, fields)
}
fn dicom_items(b: &[u8], depth: usize) -> Result<Value, String> {
    if depth > 8 {
        return Err("DICOM item nesting limit".into());
    }
    let mut p = 0;
    let mut items = Vec::new();
    while p < b.len() {
        if p + 4 > b.len() {
            return Err("short DICOM item".into());
        }
        let kind = b[p];
        let len = be16(&b[p + 2..]) as usize;
        p += 4;
        if len > b.len() - p {
            return Err("DICOM item length exceeds PDU".into());
        }
        let v = &b[p..p + len];
        let mut item = json!({"type":kind,"length":len});
        match kind {
            0x10 | 0x30 | 0x40 | 0x52 | 0x55 => {
                item["value"] = json!(text(v).trim_end_matches('\0'))
            }
            0x20 | 0x21 => {
                if len < 4 {
                    return Err("short DICOM presentation context".into());
                }
                item["id"] = json!(v[0]);
                if kind == 0x21 {
                    item["result"] = json!(v[2]);
                }
                item["items"] = dicom_items(&v[4..], depth + 1)?;
            }
            0x50 => item["items"] = dicom_items(v, depth + 1)?,
            0x51 if len == 4 => item["max_pdu_length"] = json!(be32(v)),
            _ => (),
        }
        items.push(item);
        if items.len() > 4096 {
            return Err("DICOM item count limit".into());
        }
        p += len;
    }
    Ok(json!(items))
}
fn dicom_command(b: &[u8]) -> Value {
    let mut p = 0;
    let mut tags = Vec::new();
    while p + 8 <= b.len() {
        let group = u16::from_le_bytes([b[p], b[p + 1]]);
        let element = u16::from_le_bytes([b[p + 2], b[p + 3]]);
        let size = u32::from_le_bytes(b[p + 4..p + 8].try_into().unwrap()) as usize;
        p += 8;
        if size > b.len() - p {
            break;
        }
        let value = &b[p..p + size];
        let mut tag = json!({"tag":format!("{group:04X},{element:04X}"),"length":size});
        if group == 0 {
            if size == 2 {
                let v = u16::from_le_bytes([value[0], value[1]]);
                tag["value"] = json!(v);
                if element == 0x0100 {
                    tag["command"] = json!(match v & 0x7fff {
                        1 => "C-STORE",
                        0x10 => "C-GET",
                        0x20 => "C-FIND",
                        0x21 => "C-MOVE",
                        0x30 => "C-ECHO",
                        _ => "other",
                    });
                    tag["response"] = json!(v & 0x8000 != 0);
                }
            } else if matches!(element, 2 | 3 | 0x1000 | 0x1001) {
                tag["value"] = json!(text(value).trim_end_matches('\0'));
            }
        }
        tags.push(tag);
        p += size;
        if tags.len() > 4096 {
            break;
        }
    }
    json!({"tags":tags,"complete":p==b.len()})
}
