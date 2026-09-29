#![forbid(unsafe_code)]
//! Bounds-checked link, network and transport parsing. No packet data is trusted.
use crate::{Endpoint, Error, Packet, Result, Transport};
use serde_json::{Value, json};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone)]
pub struct Fragment {
    pub id: u32,
    pub offset: usize,
    pub more: bool,
}
#[derive(Debug, Clone)]
pub struct NetworkPacket {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub protocol: u8,
    pub payload: Vec<u8>,
    pub fragment: Option<Fragment>,
}
#[derive(Debug, Clone)]
pub struct ParsedPacket {
    pub layers: Value,
    pub vlans: Vec<u16>,
    pub source_mac: Option<String>,
    pub destination_mac: Option<String>,
    pub network: Option<NetworkPacket>,
    pub arp: Option<(IpAddr, String)>,
}
#[derive(Debug, Clone)]
pub struct TransportPacket {
    pub src: Endpoint,
    pub dst: Endpoint,
    pub transport: Transport,
    pub sequence: u32,
    pub flags: u8,
    pub payload: Vec<u8>,
}
fn invalid(s: &str) -> Error {
    Error::Invalid(s.into())
}
fn need(b: &[u8], n: usize) -> Result<()> {
    if b.len() < n {
        Err(invalid("truncated protocol header or payload"))
    } else {
        Ok(())
    }
}
pub(crate) fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}
pub(crate) fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}
pub fn mac(b: &[u8]) -> String {
    b.iter()
        .map(|x| format!("{x:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

pub fn parse(packet: &Packet) -> Result<ParsedPacket> {
    let mut result = ParsedPacket {
        layers: json!({"link_type":packet.source.link_type}),
        vlans: Vec::new(),
        source_mac: None,
        destination_mac: None,
        network: None,
        arp: None,
    };
    let mut b = packet.data.as_slice();
    let mut ether;
    match packet.source.link_type {
        1 => {
            need(b, 14)?;
            result.destination_mac = Some(mac(&b[..6]));
            result.source_mac = Some(mac(&b[6..12]));
            ether = be16(&b[12..]);
            b = &b[14..];
        }
        101 | 12 | 228 | 229 => {
            need(b, 1)?;
            ether = match b[0] >> 4 {
                4 => 0x0800,
                6 => 0x86dd,
                _ => return Err(invalid("unknown raw IP version")),
            };
        }
        0 | 108 => {
            need(b, 5)?;
            // IPv4/IPv6 version is authoritative across BSD address-family values.
            b = &b[4..];
            ether = match b[0] >> 4 {
                4 => 0x0800,
                6 => 0x86dd,
                _ => return Ok(result),
            };
        }
        113 => {
            need(b, 16)?;
            let addrlen = be16(&b[4..]) as usize;
            if addrlen == 6 {
                result.source_mac = Some(mac(&b[6..12]));
            }
            ether = be16(&b[14..]);
            b = &b[16..];
        }
        276 => {
            need(b, 20)?;
            if b[11] == 6 {
                result.source_mac = Some(mac(&b[12..18]));
            }
            ether = be16(b);
            result.layers["cooked_interface"] = json!(be32(&b[4..]));
            b = &b[20..];
        }
        105 | 127 => {
            let mut radio_flags = 0;
            if packet.source.link_type == 127 {
                need(b, 8)?;
                if b[0] != 0 {
                    return Err(invalid("unsupported Radiotap version"));
                }
                let len = u16::from_le_bytes([b[2], b[3]]) as usize;
                need(b, len)?;
                if len < 8 {
                    return Err(invalid("invalid Radiotap length"));
                }
                let mut pos = 4;
                let mut words = Vec::new();
                loop {
                    if pos + 4 > len || words.len() >= 8 {
                        return Err(invalid("Radiotap presence bitmap overflow"));
                    }
                    let word = u32::from_le_bytes(b[pos..pos + 4].try_into().unwrap());
                    words.push(word);
                    pos += 4;
                    if word & 0x80000000 == 0 {
                        break;
                    }
                }
                let layout = [
                    (8, 8),
                    (1, 1),
                    (1, 1),
                    (2, 4),
                    (2, 2),
                    (1, 1),
                    (1, 1),
                    (2, 2),
                    (2, 2),
                    (2, 2),
                    (1, 1),
                    (1, 1),
                    (1, 1),
                    (1, 1),
                    (2, 2),
                    (2, 2),
                    (1, 1),
                    (1, 1),
                ];
                for (bit, (align, size)) in layout.into_iter().enumerate() {
                    if words[0] & (1 << bit) == 0 {
                        continue;
                    }
                    pos = (pos + align - 1) & !(align - 1);
                    if pos + size > len {
                        return Err(invalid("Radiotap field exceeds header"));
                    }
                    match bit {
                        1 => radio_flags = b[pos],
                        3 => {
                            result.layers["frequency_mhz"] =
                                json!(u16::from_le_bytes([b[pos], b[pos + 1]]));
                        }
                        5 => {
                            result.layers["signal_dbm"] = json!(b[pos] as i8);
                        }
                        _ => (),
                    }
                    pos += size;
                }
                b = &b[len..];
                if radio_flags & 0x10 != 0 {
                    need(b, 4)?;
                    b = &b[..b.len() - 4];
                }
            }
            need(b, 2)?;
            let fc = u16::from_le_bytes([b[0], b[1]]);
            let kind = (fc >> 2) & 3;
            let subtype = (fc >> 4) & 15;
            result.layers["wifi"] = json!({"type":kind,"subtype":subtype,"protected":fc&0x4000!=0,"retry":fc&0x0800!=0});
            if kind == 1 {
                return Ok(result);
            }
            need(b, 24)?;
            let ds = (fc >> 8) & 3;
            let (src, dst, bssid) = match ds {
                0 => (&b[10..16], &b[4..10], Some(&b[16..22])),
                1 => (&b[10..16], &b[16..22], Some(&b[4..10])),
                2 => (&b[16..22], &b[4..10], Some(&b[10..16])),
                _ => {
                    need(b, 30)?;
                    (&b[24..30], &b[16..22], None)
                }
            };
            result.source_mac = Some(mac(src));
            result.destination_mac = Some(mac(dst));
            if let Some(v) = bssid {
                result.layers["wifi"]["bssid"] = json!(mac(v));
            }
            if kind == 0 {
                let start = match subtype {
                    8 | 5 => 36,
                    4 => 24,
                    _ => b.len(),
                };
                if start <= b.len() {
                    let mut p = start;
                    while p + 2 <= b.len() {
                        let id = b[p];
                        let n = b[p + 1] as usize;
                        p += 2;
                        if p + n > b.len() {
                            break;
                        }
                        if id == 0 && n <= 32 {
                            result.layers["wifi"]["ssid"] =
                                json!(String::from_utf8_lossy(&b[p..p + n]));
                            break;
                        }
                        p += n;
                    }
                }
                return Ok(result);
            }
            if kind != 2 || fc & 0x4000 != 0 {
                return Ok(result);
            }
            if fc & 0x0400 != 0 || b[22] & 15 != 0 {
                result.layers["wifi"]["fragmented"] = json!(true);
                return Ok(result);
            }
            let mut len = if ds == 3 { 30 } else { 24 };
            if subtype & 8 != 0 {
                need(b, len + 2)?;
                if b[len] & 0x80 != 0 {
                    result.layers["wifi"]["amsdu"] = json!(true);
                    return Ok(result);
                }
                len += 2;
                if fc & 0x8000 != 0 {
                    len += 4;
                }
            }
            if radio_flags & 0x20 != 0 {
                len = (len + 3) & !3;
            }
            need(b, len + 8)?;
            b = &b[len..];
            if b[..3] != [0xaa, 0xaa, 0x03] {
                return Ok(result);
            }
            ether = be16(&b[6..]);
            b = &b[8..];
        }
        _ => {
            result.layers["unsupported_link"] = json!(true);
            return Ok(result);
        }
    }
    for _ in 0..8 {
        if !matches!(ether, 0x8100 | 0x88a8 | 0x9100) {
            break;
        }
        need(b, 4)?;
        result.vlans.push(be16(b) & 0xfff);
        ether = be16(&b[2..]);
        b = &b[4..];
    }
    if matches!(ether, 0x8100 | 0x88a8 | 0x9100) {
        return Err(invalid("too many VLAN tags"));
    }
    result.layers["ether_type"] = json!(ether);
    result.layers["vlans"] = json!(result.vlans);
    result.layers["source_mac"] = json!(result.source_mac);
    result.layers["destination_mac"] = json!(result.destination_mac);
    result.network = match ether {
        0x0800 => Some(ipv4(b)?),
        0x86dd => Some(ipv6(b)?),
        0x0806 => {
            need(b, 28)?;
            if be16(b) == 1 && be16(&b[2..]) == 0x0800 && b[4] == 6 && b[5] == 4 {
                let ip = IpAddr::V4(Ipv4Addr::new(b[14], b[15], b[16], b[17]));
                let addr = mac(&b[8..14]);
                result.layers["arp"] = json!({"operation":be16(&b[6..]),"sender_ip":ip,"sender_mac":addr,"target_ip":Ipv4Addr::new(b[24],b[25],b[26],b[27])});
                result.arp = Some((ip, addr));
            }
            None
        }
        _ => None,
    };
    if let Some(n) = &result.network {
        result.layers["ip"] = json!({"source":n.src,"destination":n.dst,"protocol":n.protocol,"fragmented":n.fragment.is_some()});
    }
    Ok(result)
}

fn ipv4(b: &[u8]) -> Result<NetworkPacket> {
    need(b, 20)?;
    let h = (b[0] & 15) as usize * 4;
    let total = be16(&b[2..]) as usize;
    if b[0] >> 4 != 4 || h < 20 || total < h {
        return Err(invalid("invalid IPv4 header"));
    }
    need(b, total)?;
    let frag = be16(&b[6..]);
    Ok(NetworkPacket {
        src: Ipv4Addr::new(b[12], b[13], b[14], b[15]).into(),
        dst: Ipv4Addr::new(b[16], b[17], b[18], b[19]).into(),
        protocol: b[9],
        payload: b[h..total].to_vec(),
        fragment: if frag & 0x3fff != 0 {
            Some(Fragment {
                id: be16(&b[4..]) as u32,
                offset: (frag as usize & 0x1fff) * 8,
                more: frag & 0x2000 != 0,
            })
        } else {
            None
        },
    })
}
fn ipv6(b: &[u8]) -> Result<NetworkPacket> {
    need(b, 40)?;
    if b[0] >> 4 != 6 {
        return Err(invalid("invalid IPv6 version"));
    }
    let total = 40 + be16(&b[4..]) as usize;
    need(b, total)?;
    let src = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&b[8..24]).unwrap()));
    let dst = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&b[24..40]).unwrap()));
    let mut pos = 40;
    let mut next = b[6];
    let mut fragment = None;
    for _ in 0..16 {
        match next {
            0 | 43 | 60 => {
                need(&b[pos..total], 2)?;
                let size = (b[pos + 1] as usize + 1) * 8;
                need(&b[pos..total], size)?;
                next = b[pos];
                pos += size;
            }
            51 => {
                need(&b[pos..total], 2)?;
                let size = (b[pos + 1] as usize + 2) * 4;
                need(&b[pos..total], size)?;
                next = b[pos];
                pos += size;
            }
            44 => {
                need(&b[pos..total], 8)?;
                let bits = be16(&b[pos + 2..]);
                fragment = Some(Fragment {
                    id: be32(&b[pos + 4..]),
                    offset: (bits as usize >> 3) * 8,
                    more: bits & 1 != 0,
                });
                next = b[pos];
                pos += 8;
                break;
            }
            _ => break,
        }
    }
    if matches!(next, 0 | 43 | 60 | 51) {
        return Err(invalid("IPv6 extension chain limit exceeded"));
    }
    Ok(NetworkPacket {
        src,
        dst,
        protocol: next,
        payload: b[pos..total].to_vec(),
        fragment,
    })
}

pub fn transport(n: &NetworkPacket) -> Result<TransportPacket> {
    let mut b = n.payload.as_slice();
    let mut protocol = n.protocol;
    for _ in 0..16 {
        if matches!(protocol, 0 | 43 | 60 | 51) {
            need(b, 2)?;
            let len = if protocol == 51 {
                (b[1] as usize + 2) * 4
            } else {
                (b[1] as usize + 1) * 8
            };
            need(b, len)?;
            protocol = b[0];
            b = &b[len..];
        } else {
            break;
        }
    }
    let mut p = TransportPacket {
        src: Endpoint { ip: n.src, port: 0 },
        dst: Endpoint { ip: n.dst, port: 0 },
        transport: Transport::Other(protocol),
        sequence: 0,
        flags: 0,
        payload: Vec::new(),
    };
    match protocol {
        6 => {
            need(b, 20)?;
            let h = (b[12] >> 4) as usize * 4;
            if h < 20 {
                return Err(invalid("invalid TCP header length"));
            }
            need(b, h)?;
            p.src.port = be16(b);
            p.dst.port = be16(&b[2..]);
            p.sequence = be32(&b[4..]);
            p.flags = b[13];
            p.transport = Transport::Tcp;
            p.payload = b[h..].to_vec();
        }
        17 => {
            need(b, 8)?;
            let len = be16(&b[4..]) as usize;
            if len < 8 {
                return Err(invalid("invalid UDP length"));
            }
            need(b, len)?;
            p.src.port = be16(b);
            p.dst.port = be16(&b[2..]);
            p.transport = Transport::Udp;
            p.payload = b[8..len].to_vec();
        }
        1 | 58 => {
            need(b, 4)?;
            p.transport = Transport::Icmp;
            p.payload = b.to_vec();
        }
        _ => p.payload = b.to_vec(),
    }
    Ok(p)
}
