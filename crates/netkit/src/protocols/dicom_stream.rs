// Included by clinical.rs to keep DICOM's PDU and dataset layers together.
#[derive(Default)]
pub struct DicomSession {
    commands: std::collections::HashMap<u8, Vec<u8>>,
    datasets: std::collections::HashMap<u8, DatasetStream>,
    syntaxes: std::collections::HashMap<u8, String>,
}
impl DicomSession {
    pub fn has_pending_message(&self) -> bool {
        !self.commands.is_empty() || !self.datasets.is_empty()
    }
    pub fn buffered_bytes(&self) -> usize {
        self.commands.values().map(Vec::len).sum::<usize>()
            + self
                .datasets
                .values()
                .map(|d| d.header.len() + d.value.len() + 64)
                .sum::<usize>()
            + self.syntaxes.values().map(String::len).sum::<usize>()
    }
    pub fn on_peer_message(&mut self, m: &crate::Message) {
        if m.protocol != "dicom" || m.fields["pdu_type"] != 2 {
            return;
        }
        if let Some(items) = m.fields["items"].as_array() {
            for item in items {
                if item["type"] == 0x21 && item["result"] == 0 {
                    if let Some(id) = item["id"].as_u64() {
                        if let Some(sub) = item["items"].as_array() {
                            for syntax in sub {
                                if syntax["type"] == 0x40 {
                                    if let Some(uid) = syntax["value"].as_str() {
                                        if uid.len() <= 128 {
                                            self.syntaxes.insert(id as u8, uid.into());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    pub fn decode(&mut self, b: &[u8], max: usize) -> DecodeResult {
        let mut result = dicom(b, max);
        let DecodeResult::Message {
            message: msg,
            consumed,
        } = &mut result
        else {
            return result;
        };
        if b[0] == 2 {
            self.on_peer_message(msg);
        }
        if b[0] != 4 {
            return result;
        }
        let body = &b[6..*consumed];
        let mut p = 0;
        let mut index = 0;
        while p < body.len() {
            let size = be32(&body[p..]) as usize;
            p += 4;
            let context = body[p];
            let flags = body[p + 1];
            let value = &body[p + 2..p + size];
            let pdv = &mut msg.fields["pdvs"][index];
            if flags & 1 != 0 {
                if self.commands.len() >= 128 && !self.commands.contains_key(&context) {
                    return invalid(*consumed, "DICOM command context limit");
                }
                let pending = self.commands.entry(context).or_default();
                if pending.len() + value.len() > max {
                    self.commands.remove(&context);
                    return invalid(*consumed, "DICOM command assembly limit");
                }
                pending.extend(value);
                if flags & 2 != 0 {
                    let command = self.commands.remove(&context).unwrap();
                    pdv["command_tags"] = dicom_command(&command);
                    pdv["command_assembled_bytes"] = json!(command.len());
                } else {
                    pdv["command_tags"] = Value::Null;
                    pdv["command_pending"] = json!(true);
                }
            } else {
                let syntax = self.syntaxes.get(&context).cloned();
                pdv["transfer_syntax"] = json!(syntax);
                if let Some(syntax) = syntax {
                    if self.datasets.len() >= 128 && !self.datasets.contains_key(&context) {
                        return invalid(*consumed, "DICOM dataset context limit");
                    }
                    let stream = self
                        .datasets
                        .entry(context)
                        .or_insert_with(|| DatasetStream::new(&syntax));
                    let tags = stream.feed(value);
                    pdv["dataset_tags"] = json!(tags);
                    pdv["dataset_status"] = json!(stream.status);
                    if flags & 2 != 0 {
                        let state = self.datasets.remove(&context).unwrap();
                        pdv["dataset_complete"] = json!(
                            state.header.is_empty()
                                && state.remaining == 0
                                && state.status == "decoded"
                        );
                    }
                } else {
                    pdv["dataset_status"] = json!("transfer_syntax_not_observed");
                }
            }
            p += size;
            index += 1;
        }
        result
    }
}
struct DatasetStream {
    explicit: bool,
    big: bool,
    header: Vec<u8>,
    remaining: usize,
    tag: (u16, u16),
    vr: String,
    capture: bool,
    value: Vec<u8>,
    length: usize,
    status: &'static str,
}
impl DatasetStream {
    fn new(syntax: &str) -> Self {
        let known = syntax == "1.2.840.10008.1.2"
            || syntax == "1.2.840.10008.1.2.1"
            || syntax == "1.2.840.10008.1.2.2"
            || syntax.starts_with("1.2.840.10008.1.2.4.")
            || syntax == "1.2.840.10008.1.2.5";
        Self {
            explicit: syntax != "1.2.840.10008.1.2",
            big: syntax == "1.2.840.10008.1.2.2",
            header: Vec::new(),
            remaining: 0,
            tag: (0, 0),
            vr: String::new(),
            capture: false,
            value: Vec::new(),
            length: 0,
            status: if known {
                "decoded"
            } else {
                "unsupported_transfer_syntax"
            },
        }
    }
    fn u16(&self, b: &[u8]) -> u16 {
        if self.big {
            be16(b)
        } else {
            u16::from_le_bytes([b[0], b[1]])
        }
    }
    fn u32(&self, b: &[u8]) -> u32 {
        if self.big {
            be32(b)
        } else {
            u32::from_le_bytes(b[..4].try_into().unwrap())
        }
    }
    fn finish_value(&mut self) -> Value {
        let (group, element) = self.tag;
        let mut tag =
            json!({"tag":format!("{group:04X},{element:04X}"),"vr":self.vr,"length":self.length});
        if self.capture {
            tag["value"] = json!(text(&self.value).trim_end_matches(['\0', ' ']));
        }
        if group == 0x7fe0 && element == 0x0010 {
            tag["pixel_data_skipped"] = json!(true);
        }
        self.value.clear();
        tag
    }
    fn feed(&mut self, mut bytes: &[u8]) -> Vec<Value> {
        let mut tags = Vec::new();
        if self.status != "decoded" {
            return tags;
        }
        while !bytes.is_empty() {
            if self.remaining > 0 {
                let n = self.remaining.min(bytes.len());
                if self.capture {
                    self.value.extend(&bytes[..n]);
                }
                self.remaining -= n;
                bytes = &bytes[n..];
                if self.remaining == 0 {
                    tags.push(self.finish_value());
                }
                continue;
            }
            let mut header_size = 8;
            if self.header.len() < 8 {
                let n = (8 - self.header.len()).min(bytes.len());
                self.header.extend(&bytes[..n]);
                bytes = &bytes[n..];
                if self.header.len() < 8 {
                    break;
                }
            }
            let group = self.u16(&self.header);
            let element = self.u16(&self.header[2..]);
            if self.explicit && group != 0xfffe {
                self.vr = text(&self.header[4..6]);
                if !self.header[4..6].iter().all(u8::is_ascii_uppercase) {
                    self.status = "invalid_vr";
                    break;
                }
                if matches!(
                    self.vr.as_str(),
                    "OB" | "OD"
                        | "OF"
                        | "OL"
                        | "OV"
                        | "OW"
                        | "SQ"
                        | "UC"
                        | "UN"
                        | "UR"
                        | "UT"
                        | "SV"
                        | "UV"
                ) {
                    header_size = 12;
                }
            } else {
                self.vr = "implicit".into();
            }
            if self.header.len() < header_size {
                let n = (header_size - self.header.len()).min(bytes.len());
                self.header.extend(&bytes[..n]);
                bytes = &bytes[n..];
                if self.header.len() < header_size {
                    break;
                }
            }
            let len = if self.explicit && group != 0xfffe && header_size == 8 {
                self.u16(&self.header[6..]) as u32
            } else {
                self.u32(&self.header[header_size - 4..])
            };
            if len == u32::MAX {
                self.status = "undefined_length_sequence_or_encapsulated_data";
                self.header.clear();
                break;
            }
            self.tag = (group, element);
            self.length = len as usize;
            self.remaining = len as usize;
            self.capture = len <= 1024
                && matches!(
                    (group, element),
                    (0x0008, 0x0016)
                        | (0x0008, 0x0018)
                        | (0x0008, 0x0060)
                        | (0x0010, 0x0010)
                        | (0x0010, 0x0020)
                        | (0x0010, 0x0030)
                        | (0x0020, 0x000d)
                        | (0x0020, 0x000e)
                );
            self.header.clear();
            if self.remaining == 0 {
                tags.push(self.finish_value());
            }
            if tags.len() >= 4096 {
                self.status = "tag_count_limit";
                break;
            }
        }
        tags
    }
}
