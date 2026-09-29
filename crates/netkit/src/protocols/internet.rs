use super::{DecodeResult, find, invalid, message, text};
use crate::{
    Completeness,
    packet::{be16, be32},
};
use serde_json::{Value, json};
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Default)]
pub struct Http1 {
    requests: std::collections::VecDeque<String>,
    tunnel: bool,
    overflow: bool,
}
impl Http1 {
    pub fn buffered_bytes(&self) -> usize {
        self.requests.iter().map(|s| s.len() + 32).sum()
    }
    pub fn on_peer_message(&mut self, message: &crate::Message) {
        if message.fields["tunnel_established"] == true {
            self.tunnel = true;
        }
        if let Some(method) = message.fields["method"].as_str() {
            if self.requests.len() < 256 {
                self.requests.push_back(method.into());
            } else {
                self.overflow = true;
            }
        }
    }
    pub fn decode(&mut self, b: &[u8], eof: bool, max: usize) -> DecodeResult {
        if self.overflow {
            return invalid(b.len(), "HTTP request correlation limit");
        }
        if self.tunnel {
            return DecodeResult::Message {
                consumed: b.len(),
                message: crate::Message {
                    protocol: "http".into(),
                    completeness: Completeness::Opaque,
                    wire_len: b.len(),
                    fields: json!({"tunnel_data_length":b.len()}),
                },
            };
        }
        let mut result = http(b, eof, max, self.requests.front().map(String::as_str));
        if let DecodeResult::Message { message, .. } = &mut result {
            if message.fields["response"] == true {
                let status = message.fields["status"].as_u64().unwrap_or(0);
                if status == 101 || status >= 200 {
                    let method = self.requests.pop_front();
                    self.tunnel = status == 101
                        || method.as_deref() == Some("CONNECT") && (200..300).contains(&status);
                    message.fields["tunnel_established"] = json!(self.tunnel);
                }
            }
        }
        result
    }
}
fn http(b: &[u8], eof: bool, max: usize, request_method: Option<&str>) -> DecodeResult {
    let Some(end) = find(b, b"\r\n\r\n") else {
        return if b.len() > 65536 {
            invalid(b.len(), "HTTP header limit")
        } else {
            DecodeResult::NeedMore
        };
    };
    if end > 65536 {
        return invalid(end + 4, "HTTP header limit");
    }
    let head = text(&b[..end]);
    let mut lines = head.split("\r\n");
    let start = lines.next().unwrap_or("");
    let parts: Vec<_> = start.split_whitespace().collect();
    if parts.len() < 2 {
        return invalid(end + 4, "invalid HTTP start line");
    }
    let response = parts[0].starts_with("HTTP/1.");
    if !response && (parts.len() != 3 || !parts[2].starts_with("HTTP/1.")) {
        return invalid(end + 4, "unsupported HTTP version");
    }
    let mut headers = Vec::new();
    let mut length = None;
    let mut transfer = String::new();
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return invalid(end + 4, "invalid HTTP header");
        };
        if name.is_empty()
            || name
                .bytes()
                .any(|c| !c.is_ascii_graphic() || b"()<>@,;:\\\"/[]?={} \t".contains(&c))
        {
            return invalid(end + 4, "invalid HTTP header name");
        }
        let value = value.trim();
        let name = name.to_ascii_lowercase();
        if name == "content-length" {
            let Ok(n) = value.parse::<usize>() else {
                return invalid(end + 4, "invalid Content-Length");
            };
            if length.is_some_and(|old| old != n) {
                return invalid(end + 4, "conflicting Content-Length");
            }
            length = Some(n);
        }
        if name == "transfer-encoding" {
            if !transfer.is_empty() {
                transfer.push(',');
            }
            transfer.push_str(&value.to_ascii_lowercase());
        }
        headers.push(json!({"name":name,"value":value}));
    }
    if !transfer.is_empty() && length.is_some() {
        return invalid(end + 4, "ambiguous Transfer-Encoding and Content-Length");
    }
    let body_start = end + 4;
    let status = if response {
        parts[1].parse::<u16>().ok()
    } else {
        None
    };
    if response && !status.is_some_and(|n| (100..600).contains(&n)) {
        return invalid(end + 4, "invalid HTTP response status");
    }
    let no_body = status.is_some_and(|n| {
        (100..200).contains(&n)
            || n == 204
            || n == 304
            || request_method == Some("HEAD")
            || request_method == Some("CONNECT") && (200..300).contains(&n)
    });
    let (used, body_len) = if no_body {
        (body_start, 0)
    } else if !transfer.is_empty() {
        if transfer.split(',').next_back().map(str::trim) != Some("chunked") {
            return invalid(body_start, "unsupported transfer framing");
        }
        let mut p = body_start;
        let mut total = 0usize;
        loop {
            let Some(e) = find(&b[p..], b"\r\n").map(|n| p + n) else {
                return DecodeResult::NeedMore;
            };
            if e - p > 1024 {
                return invalid(e + 2, "chunk header too long");
            }
            let line = text(&b[p..e]);
            let raw = line.split(';').next().unwrap_or("").trim();
            let Ok(size) = usize::from_str_radix(raw, 16) else {
                return invalid(e + 2, "invalid chunk size");
            };
            p = e + 2;
            if size == 0 {
                if b.get(p..p + 2) == Some(b"\r\n") {
                    p += 2;
                    break;
                }
                let Some(t) = find(&b[p..], b"\r\n\r\n") else {
                    return DecodeResult::NeedMore;
                };
                if t > 65536 {
                    return invalid(p + t, "HTTP trailers too large");
                }
                p += t + 4;
                break;
            }
            if size > max || total > max - size {
                return invalid(p, "HTTP body limit");
            }
            total += size;
            if size > b.len().saturating_sub(p) || b.len() - p - size < 2 {
                return DecodeResult::NeedMore;
            }
            if b[p + size..p + size + 2] != [13, 10] {
                return invalid(p + size + 2, "chunk missing CR/LF");
            }
            p += size + 2;
        }
        (p, total)
    } else if let Some(n) = length {
        if n > max {
            return invalid(body_start, "HTTP body limit");
        }
        if b.len() - body_start < n {
            return DecodeResult::NeedMore;
        }
        (body_start + n, n)
    } else if response {
        if !eof {
            return DecodeResult::NeedMore;
        }
        (b.len(), b.len() - body_start)
    } else {
        (body_start, 0)
    };
    message(
        "http",
        used,
        json!({"start_line":start,"response":response,"method":if response{None}else{Some(parts[0])},"target":if response{None}else{Some(parts[1])},"status":status,"headers":headers,"body_length":body_len}),
    )
}

pub struct Http2 {
    decoder: hpack::Decoder<'static>,
    block: Vec<u8>,
    stream: Option<u32>,
}
impl Default for Http2 {
    fn default() -> Self {
        Self {
            decoder: hpack::Decoder::new(),
            block: Vec::new(),
            stream: None,
        }
    }
}
impl Http2 {
    pub fn has_pending_message(&self) -> bool {
        self.stream.is_some()
    }
    pub fn buffered_bytes(&self) -> usize {
        self.block.len() + 4096
    }
    pub fn decode(&mut self, b: &[u8], max: usize) -> DecodeResult {
        const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        if b.starts_with(PREFACE) {
            return message("http2", PREFACE.len(), json!({"preface":true}));
        }
        if b.len() < 9 {
            return DecodeResult::NeedMore;
        }
        let n = ((b[0] as usize) << 16) | ((b[1] as usize) << 8) | b[2] as usize;
        if n > max {
            return invalid(9, "HTTP/2 frame limit");
        }
        if b.len() < n + 9 {
            return DecodeResult::NeedMore;
        }
        let kind = b[3];
        let flags = b[4];
        let stream = be32(&b[5..]) & 0x7fffffff;
        let mut payload = &b[9..9 + n];
        let mut fields = json!({"frame_type":kind,"flags":flags,"stream_id":stream,"payload_length":n,"end_stream":flags&1!=0});
        if self.stream.is_some() && (kind != 9 || self.stream != Some(stream)) {
            self.block.clear();
            self.stream = None;
            return invalid(n + 9, "HTTP/2 missing matching CONTINUATION");
        }
        if matches!(kind, 0 | 1 | 2 | 3 | 5 | 9) && stream == 0 {
            return invalid(n + 9, "HTTP/2 frame requires nonzero stream");
        }
        if matches!(kind, 4 | 6 | 7) && stream != 0 {
            return invalid(n + 9, "HTTP/2 connection frame has stream ID");
        }
        if matches!(kind, 0 | 1 | 5) && flags & 8 != 0 {
            if payload.is_empty() {
                return invalid(n + 9, "missing HTTP/2 padding length");
            }
            let pad = payload[0] as usize;
            if pad >= payload.len() {
                return invalid(n + 9, "invalid HTTP/2 padding");
            }
            payload = &payload[1..payload.len() - pad];
        }
        if kind == 1 && flags & 0x20 != 0 {
            if payload.len() < 5 {
                return invalid(n + 9, "short HTTP/2 priority");
            }
            payload = &payload[5..];
        }
        if kind == 5 {
            if payload.len() < 4 {
                return invalid(n + 9, "short PUSH_PROMISE");
            }
            fields["promised_stream"] = json!(be32(payload) & 0x7fffffff);
            payload = &payload[4..];
        }
        if matches!(kind, 1 | 5 | 9) {
            if self.block.len() + payload.len() > max.min(65536) {
                self.block.clear();
                self.stream = None;
                return invalid(n + 9, "HPACK block limit");
            }
            self.block.extend(payload);
            if flags & 4 != 0 {
                if let Err(e) = validate_hpack(&self.block) {
                    self.block.clear();
                    self.stream = None;
                    return invalid(n + 9, e);
                }
                let mut headers = Vec::new();
                let mut size = 0usize;
                let mut overflow = false;
                let decoded = self.decoder.decode_with_cb(&self.block, |name, value| {
                    size = size.saturating_add(name.len() + value.len());
                    if size <= max.min(65536) && headers.len() < 1024 {
                        headers.push(json!({"name":text(&name),"value":text(&value)}));
                    } else {
                        overflow = true;
                    }
                });
                self.block.clear();
                self.stream = None;
                match decoded {
                    Ok(()) if !overflow => fields["headers"] = json!(headers),
                    Ok(()) => return invalid(n + 9, "decoded HPACK header limit"),
                    Err(e) => return invalid(n + 9, format!("HPACK: {e:?}")),
                }
            } else {
                self.stream = Some(stream);
                fields["header_block_pending"] = json!(true);
            }
        }
        if kind == 4 {
            if flags & 1 != 0 && n != 0 || flags & 1 == 0 && n % 6 != 0 {
                return invalid(n + 9, "invalid SETTINGS length");
            }
            fields["settings"] = json!(
                payload
                    .chunks_exact(6)
                    .map(|v| json!({"id":be16(v),"value":be32(&v[2..])}))
                    .collect::<Vec<_>>()
            );
        }
        if kind == 6 && n != 8 {
            return invalid(n + 9, "invalid PING length");
        }
        if kind == 3 {
            if n != 4 {
                return invalid(n + 9, "invalid RST_STREAM length");
            }
            fields["error_code"] = json!(be32(payload));
        }
        if kind == 7 {
            if n < 8 {
                return invalid(n + 9, "invalid GOAWAY length");
            }
            fields["last_stream"] = json!(be32(payload) & 0x7fffffff);
            fields["error_code"] = json!(be32(&payload[4..]));
        }
        message("http2", n + 9, fields)
    }
}
// Validate every HPACK representation before handing it to the dependency.
// This also bounds dynamic table updates (the dependency accepts arbitrary sizes).
fn hp_int(b: &[u8], p: &mut usize, bits: u8) -> Result<usize, String> {
    let first = *b.get(*p).ok_or("truncated HPACK integer")?;
    *p += 1;
    let mask = (1usize << bits) - 1;
    let mut n = first as usize & mask;
    if n < mask {
        return Ok(n);
    }
    let mut shift = 0;
    loop {
        let byte = *b.get(*p).ok_or("truncated HPACK integer continuation")?;
        *p += 1;
        if shift >= 28 {
            return Err("HPACK integer too large".into());
        }
        n = n
            .checked_add(((byte & 127) as usize) << shift)
            .ok_or("HPACK overflow")?;
        if byte & 128 == 0 {
            return Ok(n);
        }
        shift += 7;
    }
}
fn hp_str(b: &[u8], p: &mut usize) -> Result<(), String> {
    let n = hp_int(b, p, 7)?;
    if n > b.len() - *p {
        return Err("truncated HPACK string".into());
    }
    *p += n;
    Ok(())
}
fn validate_hpack(b: &[u8]) -> Result<(), String> {
    let mut p = 0;
    let mut fields = false;
    while p < b.len() {
        let tag = b[p];
        if tag & 128 != 0 {
            if hp_int(b, &mut p, 7)? == 0 {
                return Err("zero HPACK index".into());
            }
            fields = true;
        } else if tag & 0xe0 == 0x20 {
            if fields {
                return Err("late HPACK table-size update".into());
            }
            if hp_int(b, &mut p, 5)? > 4096 {
                return Err("HPACK table exceeds 4096-byte bound".into());
            }
        } else {
            let bits = if tag & 0x40 != 0 { 6 } else { 4 };
            let index = hp_int(b, &mut p, bits)?;
            if index == 0 {
                hp_str(b, &mut p)?;
            }
            hp_str(b, &mut p)?;
            fields = true;
        }
    }
    Ok(())
}

fn dns_name(b: &[u8], pos: &mut usize) -> Result<String, String> {
    let mut p = *pos;
    let mut end = None;
    let mut labels = Vec::new();
    let mut visited = Vec::new();
    let mut size = 0;
    loop {
        let len = *b.get(p).ok_or("truncated DNS name")?;
        if len & 0xc0 == 0xc0 {
            if p + 1 >= b.len() {
                return Err("short DNS pointer".into());
            }
            let target = (((len & 63) as usize) << 8) | b[p + 1] as usize;
            if target >= b.len() || visited.contains(&target) || visited.len() >= 32 {
                return Err("invalid/cyclic DNS pointer".into());
            }
            visited.push(target);
            end.get_or_insert(p + 2);
            p = target;
            continue;
        }
        if len & 0xc0 != 0 {
            return Err("unsupported DNS label type".into());
        }
        p += 1;
        if len == 0 {
            break;
        }
        let n = len as usize;
        if p + n > b.len() {
            return Err("DNS label exceeds message".into());
        }
        size += n + 1;
        if size > 255 {
            return Err("DNS name exceeds 255 bytes".into());
        }
        labels.push(text(&b[p..p + n]));
        p += n;
    }
    *pos = end.unwrap_or(p);
    Ok(labels.join("."))
}
pub fn dns(b: &[u8], tcp: bool) -> DecodeResult {
    let (data, used) = if tcp {
        if b.len() < 2 {
            return DecodeResult::NeedMore;
        }
        let n = be16(b) as usize;
        if b.len() < n + 2 {
            return DecodeResult::NeedMore;
        }
        (&b[2..n + 2], n + 2)
    } else {
        (b, b.len())
    };
    match dns_fields(data) {
        Ok(f) => message("dns", used, f),
        Err(e) => invalid(used, e),
    }
}
fn dns_fields(b: &[u8]) -> Result<Value, String> {
    if b.len() < 12 {
        return Err("short DNS header".into());
    }
    let counts = [be16(&b[4..]), be16(&b[6..]), be16(&b[8..]), be16(&b[10..])];
    if counts.iter().map(|v| *v as usize).sum::<usize>() > 4096 {
        return Err("DNS record count limit".into());
    }
    let mut p = 12;
    let mut questions = Vec::new();
    let mut records = Vec::new();
    for _ in 0..counts[0] {
        let name = dns_name(b, &mut p)?;
        if p + 4 > b.len() {
            return Err("short DNS question".into());
        }
        questions.push(json!({"name":name,"qtype":be16(&b[p..]),"class":be16(&b[p+2..])}));
        p += 4;
    }
    for (section, count) in ["answer", "authority", "additional"]
        .iter()
        .zip(&counts[1..])
    {
        for _ in 0..*count {
            let name = dns_name(b, &mut p)?;
            if p + 10 > b.len() {
                return Err("short DNS record".into());
            }
            let kind = be16(&b[p..]);
            let class = be16(&b[p + 2..]);
            let ttl = be32(&b[p + 4..]);
            let len = be16(&b[p + 8..]) as usize;
            p += 10;
            if len > b.len() - p {
                return Err("DNS RDATA exceeds message".into());
            }
            let v = &b[p..p + len];
            let value = match kind {
                1 if len == 4 => json!(Ipv4Addr::new(v[0], v[1], v[2], v[3]).to_string()),
                28 if len == 16 => {
                    json!(Ipv6Addr::from(<[u8; 16]>::try_from(v).unwrap()).to_string())
                }
                2 | 5 | 12 => {
                    let mut q = p;
                    let s = dns_name(b, &mut q)?;
                    if q > p + len {
                        return Err("DNS name exceeds RDATA".into());
                    }
                    json!(s)
                }
                15 if len >= 3 => {
                    let mut q = p + 2;
                    let host = dns_name(b, &mut q)?;
                    if q > p + len {
                        return Err("MX exceeds RDATA".into());
                    }
                    json!({"preference":be16(v),"host":host})
                }
                33 if len >= 7 => {
                    let mut q = p + 6;
                    let target = dns_name(b, &mut q)?;
                    if q > p + len {
                        return Err("SRV exceeds RDATA".into());
                    }
                    json!({"priority":be16(v),"weight":be16(&v[2..]),"port":be16(&v[4..]),"target":target})
                }
                16 => {
                    let mut q = 0;
                    let mut strings = Vec::new();
                    while q < len {
                        let n = v[q] as usize;
                        q += 1;
                        if q + n > len {
                            return Err("short DNS TXT".into());
                        }
                        strings.push(text(&v[q..q + n]));
                        q += n;
                    }
                    json!(strings)
                }
                _ => json!({"length":len}),
            };
            records.push(json!({"section":section,"name":name,"rrtype":kind,"class":class,"ttl":ttl,"value":value}));
            p += len;
        }
    }
    Ok(
        json!({"id":be16(b),"response":b[2]&0x80!=0,"rcode":b[3]&15,"questions":questions,"records":records}),
    )
}

pub fn dhcp(b: &[u8]) -> DecodeResult {
    if b.len() < 240 || b[236..240] != [99, 130, 83, 99] || b[2] > 16 {
        return invalid(b.len(), "invalid DHCPv4 message");
    }
    let ip = |p: usize| Ipv4Addr::new(b[p], b[p + 1], b[p + 2], b[p + 3]).to_string();
    let mut fields = json!({"operation":b[0],"transaction_id":be32(&b[4..]),"client_ip":ip(12),"your_ip":ip(16),"server_ip":ip(20),"client_mac":crate::packet::mac(&b[28..28+b[2]as usize])});
    let mut p = 240;
    let mut options = Vec::new();
    while p < b.len() {
        let kind = b[p];
        p += 1;
        if kind == 255 {
            break;
        }
        if kind == 0 {
            continue;
        }
        if p >= b.len() {
            return invalid(b.len(), "truncated DHCP option");
        }
        let n = b[p] as usize;
        p += 1;
        if p + n > b.len() {
            return invalid(b.len(), "DHCP option length");
        }
        let v = &b[p..p + n];
        match kind {
            12 => fields["hostname"] = json!(text(v)),
            53 if n == 1 => fields["message_type"] = json!(v[0]),
            50 if n == 4 => {
                fields["requested_ip"] = json!(Ipv4Addr::new(v[0], v[1], v[2], v[3]).to_string())
            }
            _ => (),
        }
        options.push(json!({"code":kind,"length":n}));
        p += n;
    }
    fields["options"] = json!(options);
    message("dhcp", b.len(), fields)
}
pub fn icmp(b: &[u8], _: u16) -> DecodeResult {
    if b.len() < 4 {
        return invalid(b.len(), "short ICMP message");
    }
    let mut fields = json!({"type":b[0],"code":b[1]});
    if matches!(b[0], 135 | 136) && b.len() >= 24 {
        fields["ndp_target"] =
            json!(Ipv6Addr::from(<[u8; 16]>::try_from(&b[8..24]).unwrap()).to_string());
        let mut p = 24;
        while p + 2 <= b.len() {
            let n = b[p + 1] as usize * 8;
            if n == 0 || p + n > b.len() {
                return invalid(b.len(), "invalid NDP option");
            }
            if matches!(b[p], 1 | 2) && n == 8 {
                fields["link_address"] = json!(crate::packet::mac(&b[p + 2..p + 8]));
                fields["link_address_option"] = json!(b[p]);
            }
            p += n;
        }
    }
    message("icmp", b.len(), fields)
}
pub fn tls(b: &[u8], handshake: &mut Vec<u8>, max: usize) -> DecodeResult {
    if b.len() < 5 {
        return DecodeResult::NeedMore;
    }
    let n = be16(&b[3..]) as usize;
    if n > 18432 {
        return invalid(5, "oversized TLS record");
    }
    if b.len() < n + 5 {
        return DecodeResult::NeedMore;
    }
    let mut fields = json!({"content_type":b[0],"legacy_version":be16(&b[1..]),"record_length":n});
    if b[0] == 22 {
        if handshake.len() + n > max {
            handshake.clear();
            return invalid(n + 5, "TLS handshake buffer limit");
        }
        handshake.extend(&b[5..5 + n]);
        let mut hellos = Vec::new();
        let mut used = 0;
        while handshake.len() - used >= 4 {
            let h = &handshake[used..];
            let len = ((h[1] as usize) << 16) | ((h[2] as usize) << 8) | h[3] as usize;
            if len > max {
                handshake.clear();
                return invalid(n + 5, "TLS handshake length limit");
            }
            if h.len() < len + 4 {
                break;
            }
            if h[0] == 1 {
                match client_hello(&h[4..4 + len]) {
                    Ok(v) => hellos.push(v),
                    Err(e) => return invalid(n + 5, e),
                }
            }
            used += len + 4;
        }
        handshake.drain(..used);
        fields["client_hellos"] = json!(hellos);
    }
    let mut result = message("tls", n + 5, fields);
    if b[0] == 23 {
        if let DecodeResult::Message { message, .. } = &mut result {
            message.completeness = Completeness::Encrypted;
        }
    }
    result
}
fn client_hello(b: &[u8]) -> Result<Value, String> {
    if b.len() < 35 {
        return Err("short ClientHello".into());
    }
    let mut p = 35 + b[34] as usize;
    if p + 2 > b.len() {
        return Err("invalid TLS session id".into());
    }
    let suites = be16(&b[p..]) as usize;
    p += 2;
    if suites % 2 != 0 || p + suites >= b.len() {
        return Err("invalid TLS cipher suites".into());
    }
    p += suites;
    let compression = b[p] as usize;
    p += 1 + compression;
    if p > b.len() {
        return Err("invalid TLS compression vector".into());
    }
    let mut fields = json!({"legacy_version":be16(b)});
    if p == b.len() {
        return Ok(fields);
    }
    if p + 2 > b.len() {
        return Err("short TLS extensions".into());
    }
    let end = p + 2 + be16(&b[p..]) as usize;
    p += 2;
    if end > b.len() {
        return Err("TLS extension length".into());
    }
    let mut extensions = Vec::new();
    while p < end {
        if p + 4 > end {
            return Err("truncated TLS extension".into());
        }
        let kind = be16(&b[p..]);
        let len = be16(&b[p + 2..]) as usize;
        p += 4;
        if p + len > end {
            return Err("TLS extension overflow".into());
        }
        let v = &b[p..p + len];
        extensions.push(kind);
        if kind == 0 && len >= 2 {
            let mut q = 2;
            let mut names = Vec::new();
            while q + 3 <= v.len() {
                let t = v[q];
                let n = be16(&v[q + 1..]) as usize;
                q += 3;
                if q + n > v.len() {
                    return Err("invalid TLS SNI".into());
                }
                if t == 0 {
                    names.push(text(&v[q..q + n]));
                }
                q += n;
            }
            fields["server_names"] = json!(names);
        }
        if kind == 16 && len >= 2 {
            let mut q = 2;
            let mut protocols = Vec::new();
            while q < v.len() {
                let n = v[q] as usize;
                q += 1;
                if q + n > v.len() {
                    return Err("invalid ALPN".into());
                }
                protocols.push(text(&v[q..q + n]));
                q += n;
            }
            fields["alpn"] = json!(protocols);
        }
        if kind == 43 && len >= 1 {
            fields["supported_versions"] =
                json!(v[1..].chunks_exact(2).map(be16).collect::<Vec<_>>());
        }
        p += len;
    }
    fields["extensions"] = json!(extensions);
    Ok(fields)
}
pub fn quic(b: &[u8]) -> DecodeResult {
    if b.len() < 7 || b[0] & 0x80 == 0 {
        return invalid(b.len(), "QUIC short headers require connection state");
    }
    let version = be32(&b[1..]);
    let dcid = b[5] as usize;
    if dcid > 20 || 6 + dcid >= b.len() {
        return invalid(b.len(), "invalid QUIC destination CID");
    }
    let scid = b[6 + dcid] as usize;
    if scid > 20 || 7 + dcid + scid > b.len() {
        return invalid(b.len(), "invalid QUIC source CID");
    }
    let hex = |s: &[u8]| s.iter().map(|n| format!("{n:02x}")).collect::<String>();
    let mut result = message(
        "quic",
        b.len(),
        json!({"version":version,"packet_type_bits":(b[0]>>4)&3,"destination_cid":hex(&b[6..6+dcid]),"source_cid":hex(&b[7+dcid..7+dcid+scid]),"payload_length":b.len()-7-dcid-scid}),
    );
    if let DecodeResult::Message { message, .. } = &mut result {
        message.completeness = Completeness::Encrypted;
    }
    result
}
