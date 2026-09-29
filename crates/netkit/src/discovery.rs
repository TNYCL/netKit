//! Explicit, rate-limited active discovery. This module is never invoked by
//! passive capture. A lack of response is not interpreted as a closed UDP port.
use crate::{Error, Result};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    io,
    net::{IpAddr, SocketAddr, TcpStream, UdpSocket},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScanTransport {
    Tcp,
    Udp,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub address: IpAddr,
    pub port: u16,
    pub transport: ScanTransport,
    pub state: String,
    pub evidence: String,
    pub elapsed_ms: u64,
}
#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub addresses: Vec<IpAddr>,
    pub ports: Vec<u16>,
    pub transport: ScanTransport,
    pub timeout: Duration,
    pub concurrency: usize,
    pub rate_per_second: u32,
    pub max_probes: usize,
}
impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            addresses: Vec::new(),
            ports: vec![80, 443],
            transport: ScanTransport::Tcp,
            timeout: Duration::from_millis(500),
            concurrency: 32,
            rate_per_second: 100,
            max_probes: 1_000_000,
        }
    }
}
pub fn parse_ports(input: &str) -> Result<Vec<u16>> {
    let mut ports = BTreeSet::new();
    for part in input.split(',') {
        let part = part.trim();
        let (a, b) = if let Some((a, b)) = part.split_once('-') {
            (a.parse::<u16>(), b.parse::<u16>())
        } else {
            let n = part.parse::<u16>();
            (n.clone(), n)
        };
        let a = a.map_err(|_| Error::Invalid(format!("invalid port range: {part}")))?;
        let b = b.map_err(|_| Error::Invalid(format!("invalid port range: {part}")))?;
        if a == 0 || a > b {
            return Err(Error::Invalid(format!(
                "port range must be within 1..65535: {part}"
            )));
        }
        ports.extend(a..=b);
    }
    if ports.is_empty() {
        return Err(Error::Invalid("empty port selection".into()));
    }
    Ok(ports.into_iter().collect())
}
pub fn targets(input: &str, max_hosts: usize) -> Result<Vec<IpAddr>> {
    if max_hosts == 0 || max_hosts > 1_000_000 {
        return Err(Error::Invalid("max_hosts must be 1..1000000".into()));
    }
    if let Ok(ip) = input.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    let network = input
        .parse::<IpNet>()
        .map_err(|_| Error::Invalid("target must be an IP address or CIDR network".into()))?;
    let mut result = Vec::new();
    for ip in network.hosts().take(max_hosts + 1) {
        result.push(ip);
    }
    if result.len() > max_hosts {
        return Err(Error::Limit(format!(
            "network exceeds max_hosts={max_hosts}; choose a smaller scope"
        )));
    }
    Ok(result)
}
pub fn scan<F: FnMut(ScanResult)>(
    options: &ScanOptions,
    cancelled: Arc<AtomicBool>,
    mut receive: F,
) -> Result<()> {
    if options.addresses.is_empty()
        || options.ports.is_empty()
        || options.ports.contains(&0)
        || options.concurrency == 0
        || options.concurrency > 1024
        || options.rate_per_second == 0
        || options.rate_per_second > 100_000
        || options.timeout.is_zero()
        || options.timeout > Duration::from_secs(30)
    {
        return Err(Error::Invalid(
            "invalid discovery limits or empty targets".into(),
        ));
    }
    let total = options
        .addresses
        .len()
        .checked_mul(options.ports.len())
        .ok_or_else(|| Error::Limit("scan size overflow".into()))?;
    if total > options.max_probes {
        return Err(Error::Limit(format!(
            "{total} probes exceeds max_probes={}",
            options.max_probes
        )));
    }
    let next = AtomicUsize::new(0);
    let schedule = Mutex::new(Instant::now());
    let spacing = Duration::from_secs_f64(1.0 / options.rate_per_second as f64);
    let (tx, rx) = mpsc::sync_channel(options.concurrency * 2);
    thread::scope(|scope| {
        for _ in 0..options.concurrency.min(total) {
            let tx = tx.clone();
            let cancelled = cancelled.clone();
            let next = &next;
            let schedule = &schedule;
            scope.spawn(move || {
                while !cancelled.load(Ordering::Relaxed) {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    if index >= total {
                        break;
                    }
                    let when = {
                        let mut clock = schedule.lock().unwrap_or_else(|e| e.into_inner());
                        let when = (*clock).max(Instant::now());
                        *clock = when + spacing;
                        when
                    };
                    while Instant::now() < when && !cancelled.load(Ordering::Relaxed) {
                        thread::sleep((when - Instant::now()).min(Duration::from_millis(10)));
                    }
                    if cancelled.load(Ordering::Relaxed) {
                        break;
                    }
                    let address = options.addresses[index / options.ports.len()];
                    let port = options.ports[index % options.ports.len()];
                    let target = SocketAddr::new(address, port);
                    let start = Instant::now();
                    let (state, evidence) = match options.transport {
                        ScanTransport::Tcp => tcp(target, options.timeout),
                        ScanTransport::Udp => udp(target, options.timeout),
                    };
                    if tx
                        .send(ScanResult {
                            address,
                            port,
                            transport: options.transport,
                            state,
                            evidence,
                            elapsed_ms: start.elapsed().as_millis() as u64,
                        })
                        .is_err()
                    {
                        break;
                    }
                }
            });
        }
        drop(tx);
        for result in rx {
            receive(result);
        }
    });
    Ok(())
}
fn error_state(e: io::Error, udp: bool) -> (String, String) {
    let state = match e.kind() {
        io::ErrorKind::ConnectionRefused => "closed",
        io::ErrorKind::ConnectionReset if udp => "closed",
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => {
            if udp {
                "open_or_filtered"
            } else {
                "no_response"
            }
        }
        io::ErrorKind::PermissionDenied => "local_permission_denied",
        _ => "unreachable_or_error",
    };
    (state.into(), e.to_string())
}
fn tcp(target: SocketAddr, timeout: Duration) -> (String, String) {
    match TcpStream::connect_timeout(&target, timeout) {
        Ok(stream) => {
            let _ = stream.shutdown(std::net::Shutdown::Both);
            ("open".into(), "TCP connection established".into())
        }
        Err(e) => error_state(e, false),
    }
}
fn udp(target: SocketAddr, timeout: Duration) -> (String, String) {
    let result = (|| -> io::Result<usize> {
        let socket = UdpSocket::bind(if target.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        })?;
        socket.set_read_timeout(Some(timeout))?;
        socket.set_write_timeout(Some(timeout))?;
        socket.connect(target)?;
        let probe: Vec<u8> = match target.port() {
            53 => vec![0x4e, 0x4b, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1],
            123 => {
                let mut v = vec![0; 48];
                v[0] = 0x23;
                v
            }
            _ => Vec::new(),
        };
        socket.send(&probe)?;
        let mut reply = [0; 2048];
        socket.recv(&mut reply)
    })();
    match result {
        Ok(n) => (
            "open".into(),
            format!("received {n} bytes from the selected UDP endpoint"),
        ),
        Err(e) => error_state(e, true),
    }
}
