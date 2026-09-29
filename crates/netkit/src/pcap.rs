#![forbid(unsafe_code)]
//! Bounded streaming PCAP and PCAPNG I/O. Unknown PCAPNG blocks are skipped.
//! Every section has its own byte order, interfaces and clock resolution.
use crate::{Error, Packet, Result, Source};
use std::io::{Read, Write};

const MAX_BLOCK: usize = 16 * 1024 * 1024;
#[derive(Clone, Copy, Debug)]
enum Endian {
    Little,
    Big,
}
impl Endian {
    fn u16(self, b: &[u8]) -> u16 {
        let a = [b[0], b[1]];
        match self {
            Self::Little => u16::from_le_bytes(a),
            Self::Big => u16::from_be_bytes(a),
        }
    }
    fn u32(self, b: &[u8]) -> u32 {
        let a = [b[0], b[1], b[2], b[3]];
        match self {
            Self::Little => u32::from_le_bytes(a),
            Self::Big => u32::from_be_bytes(a),
        }
    }
    fn i64(self, b: &[u8]) -> i64 {
        let mut a = [0; 8];
        a.copy_from_slice(&b[..8]);
        match self {
            Self::Little => i64::from_le_bytes(a),
            Self::Big => i64::from_be_bytes(a),
        }
    }
}
#[derive(Clone, Debug)]
struct Interface {
    link: u32,
    snaplen: u32,
    units: u128,
    offset: i64,
}
enum Format {
    Pcap {
        endian: Endian,
        nano: bool,
        link: u32,
        snaplen: u32,
    },
    Pcapng {
        endian: Endian,
        interfaces: Vec<Interface>,
        section: u32,
    },
}
pub struct CaptureReader<R> {
    reader: R,
    sensor: String,
    format: Format,
}

fn read_four<R: Read>(r: &mut R) -> Result<Option<[u8; 4]>> {
    let mut b = [0; 4];
    match r.read(&mut b[..1]) {
        Ok(0) => return Ok(None),
        Ok(_) => (),
        Err(e) => return Err(e.into()),
    }
    r.read_exact(&mut b[1..])?;
    Ok(Some(b))
}
fn bad(s: &str) -> Error {
    Error::Invalid(s.into())
}

impl<R: Read> CaptureReader<R> {
    pub fn new(mut reader: R, sensor: impl Into<String>) -> Result<Self> {
        let magic = read_four(&mut reader)?.ok_or_else(|| bad("empty capture"))?;
        let sensor = sensor.into();
        if magic == [0x0a, 0x0d, 0x0d, 0x0a] {
            let mut this = Self {
                reader,
                sensor,
                format: Format::Pcapng {
                    endian: Endian::Little,
                    interfaces: Vec::new(),
                    section: 0,
                },
            };
            this.section()?;
            Ok(this)
        } else {
            let (endian, nano) = match magic {
                [0xd4, 0xc3, 0xb2, 0xa1] => (Endian::Little, false),
                [0xa1, 0xb2, 0xc3, 0xd4] => (Endian::Big, false),
                [0x4d, 0x3c, 0xb2, 0xa1] => (Endian::Little, true),
                [0xa1, 0xb2, 0x3c, 0x4d] => (Endian::Big, true),
                _ => return Err(bad("not a PCAP or PCAPNG file")),
            };
            let mut h = [0; 20];
            reader.read_exact(&mut h)?;
            if endian.u16(&h) != 2 || endian.u16(&h[2..]) != 4 {
                return Err(bad("unsupported PCAP version"));
            }
            let snaplen = endian.u32(&h[12..]);
            let link = endian.u32(&h[16..]) & 0xffff;
            Ok(Self {
                reader,
                sensor,
                format: Format::Pcap {
                    endian,
                    nano,
                    link,
                    snaplen,
                },
            })
        }
    }

    fn section(&mut self) -> Result<()> {
        let mut h = [0; 8];
        self.reader.read_exact(&mut h)?;
        let endian = match &h[4..] {
            [0x4d, 0x3c, 0x2b, 0x1a] => Endian::Little,
            [0x1a, 0x2b, 0x3c, 0x4d] => Endian::Big,
            _ => return Err(bad("PCAPNG byte-order magic")),
        };
        let len = endian.u32(&h) as usize;
        if !(28..=MAX_BLOCK).contains(&len) || len % 4 != 0 {
            return Err(bad("invalid PCAPNG section length"));
        }
        let mut rest = vec![0; len - 12];
        self.reader.read_exact(&mut rest)?;
        if endian.u32(&rest[rest.len() - 4..]) as usize != len {
            return Err(bad("PCAPNG section length mismatch"));
        }
        if endian.u16(&rest) != 1 {
            return Err(bad("unsupported PCAPNG major version"));
        }
        let section = match &self.format {
            Format::Pcapng { section, .. } => section
                .checked_add(1)
                .ok_or_else(|| bad("too many sections"))?,
            _ => 1,
        };
        self.format = Format::Pcapng {
            endian,
            interfaces: Vec::new(),
            section,
        };
        Ok(())
    }

    pub fn next_packet(&mut self) -> Result<Option<Packet>> {
        loop {
            let Some(tag) = read_four(&mut self.reader)? else {
                return Ok(None);
            };
            if let Format::Pcap {
                endian,
                nano,
                link,
                snaplen,
            } = self.format
            {
                let sec = endian.u32(&tag) as u64;
                let mut h = [0; 12];
                self.reader.read_exact(&mut h)?;
                let fraction = endian.u32(&h) as u64;
                if fraction >= if nano { 1_000_000_000 } else { 1_000_000 } {
                    return Err(bad("PCAP timestamp fraction out of range"));
                }
                let caplen = endian.u32(&h[4..]) as usize;
                let original_len = endian.u32(&h[8..]);
                if caplen > MAX_BLOCK
                    || caplen > original_len as usize
                    || (snaplen != 0 && caplen > snaplen as usize)
                {
                    return Err(bad("invalid PCAP captured length"));
                }
                let mut data = vec![0; caplen];
                self.reader.read_exact(&mut data)?;
                return Ok(Some(Packet {
                    source: Source {
                        sensor: self.sensor.clone(),
                        interface: 0,
                        link_type: link,
                    },
                    timestamp_ns: sec * 1_000_000_000 + fraction * if nano { 1 } else { 1000 },
                    original_len,
                    data,
                }));
            }
            if tag == [0x0a, 0x0d, 0x0d, 0x0a] {
                self.section()?;
                continue;
            }
            let Format::Pcapng {
                endian,
                interfaces,
                section,
            } = &mut self.format
            else {
                unreachable!()
            };
            let endian = *endian;
            let block_type = endian.u32(&tag);
            let mut lb = [0; 4];
            self.reader.read_exact(&mut lb)?;
            let len = endian.u32(&lb) as usize;
            if !(12..=MAX_BLOCK).contains(&len) || len % 4 != 0 {
                return Err(bad("invalid PCAPNG block length"));
            }
            let mut b = vec![0; len - 8];
            self.reader.read_exact(&mut b)?;
            if endian.u32(&b[b.len() - 4..]) as usize != len {
                return Err(bad("PCAPNG block length mismatch"));
            }
            let body = &b[..b.len() - 4];
            match block_type {
                1 => {
                    if body.len() < 8 || interfaces.len() >= 4096 {
                        return Err(bad("invalid or excessive PCAPNG interfaces"));
                    }
                    let mut iface = Interface {
                        link: endian.u16(body) as u32,
                        snaplen: endian.u32(&body[4..]),
                        units: 1_000_000,
                        offset: 0,
                    };
                    let mut pos = 8;
                    while pos + 4 <= body.len() {
                        let code = endian.u16(&body[pos..]);
                        let size = endian.u16(&body[pos + 2..]) as usize;
                        pos += 4;
                        if pos + size > body.len() {
                            return Err(bad("invalid PCAPNG option length"));
                        }
                        if code == 0 {
                            break;
                        }
                        if code == 9 && size == 1 {
                            let v = body[pos];
                            iface.units = if v & 0x80 != 0 {
                                2_u128.checked_pow((v & 0x7f) as u32)
                            } else {
                                10_u128.checked_pow(v as u32)
                            }
                            .ok_or_else(|| bad("timestamp resolution overflow"))?;
                        }
                        if code == 14 && size == 8 {
                            iface.offset = endian.i64(&body[pos..]);
                        }
                        pos += (size + 3) & !3;
                    }
                    interfaces.push(iface);
                }
                6 | 2 => {
                    if body.len() < 20 {
                        return Err(bad("short PCAPNG packet"));
                    }
                    let id = if block_type == 2 {
                        endian.u16(body) as u32
                    } else {
                        endian.u32(body)
                    };
                    let iface = interfaces
                        .get(id as usize)
                        .ok_or_else(|| bad("PCAPNG packet references missing interface"))?;
                    let ticks =
                        ((endian.u32(&body[4..]) as u64) << 32) | endian.u32(&body[8..]) as u64;
                    let caplen = endian.u32(&body[12..]) as usize;
                    let original_len = endian.u32(&body[16..]);
                    if caplen > original_len as usize
                        || (iface.snaplen > 0 && caplen > iface.snaplen as usize)
                        || 20 + ((caplen + 3) & !3) > body.len()
                    {
                        return Err(bad("PCAPNG captured length exceeds block"));
                    }
                    let ns = ((ticks as u128 * 1_000_000_000) / iface.units) as i128
                        + iface.offset as i128 * 1_000_000_000;
                    let timestamp_ns = u64::try_from(ns)
                        .map_err(|_| bad("timestamp outside unsigned nanosecond range"))?;
                    return Ok(Some(Packet {
                        source: Source {
                            sensor: format!("{}#{}", self.sensor, section),
                            interface: id,
                            link_type: iface.link,
                        },
                        timestamp_ns,
                        original_len,
                        data: body[20..20 + caplen].to_vec(),
                    }));
                }
                3 => {
                    if body.len() < 4 {
                        return Err(bad("short PCAPNG simple packet"));
                    }
                    let iface = interfaces
                        .first()
                        .ok_or_else(|| bad("simple packet has no interface"))?;
                    let original_len = endian.u32(body);
                    let caplen = if iface.snaplen == 0 {
                        original_len
                    } else {
                        original_len.min(iface.snaplen)
                    } as usize;
                    if 4 + ((caplen + 3) & !3) != body.len() {
                        return Err(bad("invalid simple packet length"));
                    }
                    return Ok(Some(Packet {
                        source: Source {
                            sensor: format!("{}#{}", self.sensor, section),
                            interface: 0,
                            link_type: iface.link,
                        },
                        timestamp_ns: 0,
                        original_len,
                        data: body[4..4 + caplen].to_vec(),
                    }));
                }
                _ => (),
            }
        }
    }
}

/// Writes PCAPNG, preserving source/interface distinctions and nanosecond clocks.
pub struct CaptureWriter<W> {
    writer: W,
    sources: Vec<Source>,
}
impl<W: Write> CaptureWriter<W> {
    pub fn new(writer: W) -> Result<Self> {
        let mut this = Self {
            writer,
            sources: Vec::new(),
        };
        let mut body = Vec::new();
        body.extend(0x1a2b3c4du32.to_le_bytes());
        body.extend(1u16.to_le_bytes());
        body.extend(0u16.to_le_bytes());
        body.extend((-1i64).to_le_bytes());
        this.block(0x0a0d0d0a, &body)?;
        Ok(this)
    }
    fn block(&mut self, kind: u32, body: &[u8]) -> Result<()> {
        let padded = (body.len() + 3) & !3;
        let len = u32::try_from(padded + 12).map_err(|_| bad("output block too large"))?;
        self.writer.write_all(&kind.to_le_bytes())?;
        self.writer.write_all(&len.to_le_bytes())?;
        self.writer.write_all(body)?;
        self.writer.write_all(&[0; 3][..padded - body.len()])?;
        self.writer.write_all(&len.to_le_bytes())?;
        Ok(())
    }
    pub fn write_packet(&mut self, packet: &Packet) -> Result<()> {
        if packet.data.len() > MAX_BLOCK - 64 || packet.data.len() > packet.original_len as usize {
            return Err(bad("invalid output packet size"));
        }
        let id = if let Some(i) = self.sources.iter().position(|s| s == &packet.source) {
            i as u32
        } else {
            if self.sources.len() >= 4096 {
                return Err(Error::Limit("too many output interfaces".into()));
            }
            let link = u16::try_from(packet.source.link_type)
                .map_err(|_| bad("link type exceeds PCAPNG range"))?;
            let mut b = Vec::new();
            b.extend(link.to_le_bytes());
            b.extend(0u16.to_le_bytes());
            b.extend((MAX_BLOCK as u32).to_le_bytes());
            b.extend(9u16.to_le_bytes());
            b.extend(1u16.to_le_bytes());
            b.extend([9, 0, 0, 0]);
            let name = format!("{}:{}", packet.source.sensor, packet.source.interface);
            if name.len() > 4096 {
                return Err(bad("source name too long"));
            }
            b.extend(2u16.to_le_bytes());
            b.extend((name.len() as u16).to_le_bytes());
            b.extend(name.as_bytes());
            while b.len() % 4 != 0 {
                b.push(0);
            }
            b.extend([0; 4]);
            self.block(1, &b)?;
            let id = self.sources.len() as u32;
            self.sources.push(packet.source.clone());
            id
        };
        let mut b = Vec::with_capacity(packet.data.len() + 20);
        b.extend(id.to_le_bytes());
        b.extend(((packet.timestamp_ns >> 32) as u32).to_le_bytes());
        b.extend((packet.timestamp_ns as u32).to_le_bytes());
        b.extend((packet.data.len() as u32).to_le_bytes());
        b.extend(packet.original_len.to_le_bytes());
        b.extend(&packet.data);
        self.block(6, &b)
    }
    pub fn flush(&mut self) -> Result<()> {
        self.writer.flush()?;
        Ok(())
    }
    pub fn into_inner(self) -> W {
        self.writer
    }
}
