#![forbid(unsafe_code)]
//! Bounded TCP reassembly with sequence wrap handling and a documented first-seen
//! overlap policy. Capture gaps are reported, never filled with invented bytes.
use crate::{
    Source,
    packet::{Fragment, NetworkPacket},
};
use std::{collections::HashMap, net::IpAddr};

#[derive(Default)]
pub struct TcpStream {
    initial: Option<u32>,
    next: Option<u32>,
    pending: Vec<(u32, Vec<u8>)>,
    fin: Option<u32>,
    pub started_midstream: bool,
    pub closed: bool,
}
#[derive(Default, Debug)]
pub struct StreamOutput {
    pub chunks: Vec<Vec<u8>>,
    pub diagnostics: Vec<(String, String)>,
    pub gap: bool,
    pub closed: bool,
}
impl TcpStream {
    pub fn initial_sequence(&self) -> Option<u32> {
        self.initial
    }
    pub fn buffered_bytes(&self) -> usize {
        self.pending.iter().map(|(_, v)| v.len()).sum()
    }
    pub fn push(
        &mut self,
        sequence: u32,
        syn: bool,
        fin: bool,
        data: &[u8],
        limit: usize,
    ) -> StreamOutput {
        let mut out = StreamOutput::default();
        if syn && self.initial.is_none() {
            self.initial = Some(sequence);
        }
        let mut start = sequence.wrapping_add(u32::from(syn));
        if self.next.is_none() && (syn || !data.is_empty() || fin) {
            self.next = Some(start);
            self.started_midstream = !syn;
            if !syn {
                out.diagnostics.push((
                    "midstream_capture".into(),
                    "TCP handshake was not observed; prior stream bytes are unknown".into(),
                ));
            }
        }
        let Some(mut next) = self.next else {
            return out;
        };
        if fin {
            self.fin = Some(start.wrapping_add(data.len() as u32));
        }
        let mut bytes = data;
        let delta = start.wrapping_sub(next) as i32;
        if delta < 0 {
            let skip = next.wrapping_sub(start) as usize;
            out.diagnostics.push((
                "tcp_retransmission".into(),
                format!(
                    "{} previously delivered bytes overlap",
                    skip.min(bytes.len())
                ),
            ));
            if skip >= bytes.len() {
                bytes = &[];
            } else {
                bytes = &bytes[skip..];
                start = next;
            }
        }
        if !bytes.is_empty() {
            if start.wrapping_sub(next) as usize > limit.saturating_mul(8)
                || self.buffered_bytes() + bytes.len() > limit
                || self.pending.len() >= 1024
            {
                out.gap = true;
                out.diagnostics.push((
                    "stream_gap".into(),
                    format!(
                        "reassembly bound reached; {} queued bytes discarded",
                        self.buffered_bytes()
                    ),
                ));
                self.pending.clear();
                next = start;
                self.next = Some(start);
            }
            // Split new ranges around already queued ranges: earlier observations win.
            let mut pieces = vec![(start, bytes.to_vec())];
            for (old_seq, old) in &self.pending {
                let old_start = old_seq.wrapping_sub(next) as usize;
                let old_end = old_start + old.len();
                let mut remaining = Vec::new();
                for (seq, v) in pieces {
                    let a = seq.wrapping_sub(next) as usize;
                    let z = a + v.len();
                    if a < old_end && old_start < z {
                        let lo = a.max(old_start);
                        let hi = z.min(old_end);
                        let conflict = v[lo - a..hi - a] != old[lo - old_start..hi - old_start];
                        out.diagnostics.push((
                            if conflict {
                                "tcp_overlap_conflict"
                            } else {
                                "tcp_retransmission"
                            }
                            .into(),
                            format!(
                                "{} overlapping queued bytes; first observation retained",
                                hi - lo
                            ),
                        ));
                        if a < lo {
                            remaining.push((seq, v[..lo - a].to_vec()));
                        }
                        if hi < z {
                            remaining
                                .push((seq.wrapping_add((hi - a) as u32), v[hi - a..].to_vec()));
                        }
                    } else {
                        remaining.push((seq, v));
                    }
                }
                pieces = remaining;
            }
            self.pending.extend(pieces);
            while let Some(index) = self.pending.iter().position(|(s, _)| *s == next) {
                let (_, v) = self.pending.swap_remove(index);
                next = next.wrapping_add(v.len() as u32);
                out.chunks.push(v);
            }
            self.next = Some(next);
        }
        if self.fin == Some(next) {
            self.closed = true;
            out.closed = true;
            self.next = Some(next.wrapping_add(1));
        }
        out
    }
    pub fn finish(&mut self) -> StreamOutput {
        let mut out = StreamOutput::default();
        if !self.pending.is_empty() {
            out.gap = true;
            out.diagnostics.push((
                "stream_gap".into(),
                format!(
                    "stream ended with {} out-of-order bytes after an unresolved gap",
                    self.buffered_bytes()
                ),
            ));
            self.pending.clear();
        }
        self.closed = true;
        out.closed = true;
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FragmentKey {
    source: Source,
    vlans: Vec<u16>,
    src: IpAddr,
    dst: IpAddr,
    protocol: u8,
    id: u32,
}
struct Datagram {
    network: NetworkPacket,
    pieces: Vec<(usize, Vec<u8>)>,
    total: Option<usize>,
    last: u64,
}
pub struct FragmentCache {
    entries: HashMap<FragmentKey, Datagram>,
    max_entries: usize,
    max_bytes: usize,
    timeout_ns: u64,
}
pub struct FragmentOutput {
    pub packet: Option<NetworkPacket>,
    pub diagnostics: Vec<String>,
}
impl FragmentCache {
    pub fn new(max_entries: usize, max_bytes: usize, timeout_ns: u64) -> Self {
        Self {
            entries: HashMap::new(),
            max_entries,
            max_bytes,
            timeout_ns,
        }
    }
    pub fn buffered_bytes(&self) -> usize {
        self.entries
            .values()
            .map(|d| d.pieces.iter().map(|(_, v)| v.len()).sum::<usize>())
            .sum()
    }
    pub fn expire(&mut self, now: u64) -> usize {
        let before = self.entries.len();
        self.entries
            .retain(|_, d| now.saturating_sub(d.last) <= self.timeout_ns);
        before - self.entries.len()
    }
    pub fn clear(&mut self) -> usize {
        let n = self.entries.len();
        self.entries.clear();
        n
    }
    pub fn push(
        &mut self,
        source: &Source,
        vlans: &[u16],
        network: NetworkPacket,
        now: u64,
    ) -> FragmentOutput {
        let mut out = FragmentOutput {
            packet: None,
            diagnostics: Vec::new(),
        };
        let Some(Fragment { id, offset, more }) = network.fragment.clone() else {
            out.packet = Some(network);
            return out;
        };
        let n = network.payload.len();
        if n == 0 || offset + n > 65535 || (more && n % 8 != 0) {
            out.diagnostics
                .push("invalid IP fragment alignment or size".into());
            return out;
        }
        let key = FragmentKey {
            source: source.clone(),
            vlans: vlans.to_vec(),
            src: network.src,
            dst: network.dst,
            protocol: network.protocol,
            id,
        };
        if self.buffered_bytes() + n > self.max_bytes
            || (!self.entries.contains_key(&key) && self.entries.len() >= self.max_entries)
        {
            if let Some(old) = self
                .entries
                .iter()
                .min_by_key(|(_, d)| d.last)
                .map(|(k, _)| k.clone())
            {
                self.entries.remove(&old);
                out.diagnostics
                    .push("fragment resource limit evicted an incomplete datagram".into());
            }
            if self.buffered_bytes() + n > self.max_bytes {
                out.diagnostics
                    .push("fragment exceeds total memory bound".into());
                return out;
            }
        }
        let mut clean = network.clone();
        clean.payload.clear();
        clean.fragment = None;
        let d = self.entries.entry(key.clone()).or_insert(Datagram {
            network: clean,
            pieces: Vec::new(),
            total: None,
            last: now,
        });
        d.last = d.last.max(now);
        if d.pieces.len() >= 1024
            || d.total.is_some_and(|total| offset + n > total)
            || (!more && d.total.is_some_and(|total| total != offset + n))
        {
            self.entries.remove(&key);
            out.diagnostics
                .push("inconsistent or excessive IP fragments".into());
            return out;
        }
        for (start, v) in &d.pieces {
            if offset < *start + v.len() && *start < offset + n {
                if network.src.is_ipv4() && offset == *start && network.payload == *v {
                    return out;
                }
                self.entries.remove(&key);
                out.diagnostics
                    .push("overlapping IP fragments rejected".into());
                return out;
            }
        }
        if !more {
            d.total = Some(offset + n);
        }
        d.pieces.push((offset, network.payload));
        d.pieces.sort_by_key(|(o, _)| *o);
        if let Some(total) = d.total {
            let mut cursor = 0;
            for (offset, v) in &d.pieces {
                if *offset != cursor {
                    return out;
                }
                cursor += v.len();
            }
            if cursor == total {
                let d = self.entries.remove(&key).unwrap();
                let mut result = d.network;
                result.payload = Vec::with_capacity(total);
                for (_, v) in d.pieces {
                    result.payload.extend(v);
                }
                out.packet = Some(result);
            }
        }
        out
    }
}
