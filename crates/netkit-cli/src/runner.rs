use crate::{LiveArgs, output::Output};
use netkit::{
    capture::{CaptureOptions, Pcap},
    pcap::{CaptureReader, CaptureWriter},
    *,
};
use serde_json::json;
use std::{
    fs::{File, OpenOptions},
    io::{BufReader, BufWriter},
    net::IpAddr,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

#[derive(Clone, Copy)]
pub enum View {
    All,
    Devices,
    Flows,
}
fn show(output: &mut Output, events: Vec<Event>, view: View, protocol: Option<&str>) -> Result<()> {
    for event in events {
        let keep = match &event.kind {
            EventKind::Diagnostic { .. } | EventKind::Statistics { .. } => true,
            EventKind::DeviceObserved { .. } => {
                matches!(view, View::All | View::Devices) && protocol.is_none()
            }
            EventKind::FlowOpened { .. } | EventKind::FlowClosed { .. } => {
                matches!(view, View::All | View::Flows) && protocol.is_none()
            }
            EventKind::MessageDecoded { message, .. } => {
                matches!(view, View::All) && protocol.is_none_or(|p| p == message.protocol)
            }
            EventKind::PacketObserved { .. } => matches!(view, View::All) && protocol.is_none(),
        };
        if keep {
            output.emit(&event)?;
        }
    }
    Ok(())
}
fn matches_host(packet: &Packet, host: Option<IpAddr>) -> bool {
    let Some(host) = host else {
        return true;
    };
    match netkit::packet::parse(packet) {
        Ok(p) => {
            p.network.is_some_and(|n| n.src == host || n.dst == host)
                || p.arp.is_some_and(|(ip, _)| ip == host)
        }
        Err(_) => false,
    }
}
#[allow(clippy::too_many_arguments)]
pub fn offline(
    input: &Path,
    engine: &mut Engine,
    output: &mut Output,
    view: View,
    protocol: Option<&str>,
    host: Option<IpAddr>,
    count: u64,
    cancel: &AtomicBool,
    workers: usize,
) -> Result<()> {
    let mut pool = create_pool(engine, workers)?;
    let mut reader =
        CaptureReader::new(BufReader::new(File::open(input)?), input.to_string_lossy())?;
    let mut seen = 0;
    while !cancel.load(Ordering::Relaxed) {
        let Some(packet) = reader.next_packet()? else {
            break;
        };
        if !matches_host(&packet, host) {
            continue;
        }
        process(engine, &mut pool, packet, output, view, protocol)?;
        seen += 1;
        if count > 0 && seen >= count {
            break;
        }
    }
    finish(engine, pool, output, view, protocol)
}
fn create_pool(engine: &Engine, workers: usize) -> Result<Option<netkit::pipeline::AnalysisPool>> {
    if workers == 1 {
        return Ok(None);
    }
    netkit::pipeline::AnalysisPool::new(
        engine.config().clone(),
        ProtocolRegistry::default(),
        workers,
        8,
    )
    .map(Some)
}
fn process(
    engine: &mut Engine,
    pool: &mut Option<netkit::pipeline::AnalysisPool>,
    packet: Packet,
    output: &mut Output,
    view: View,
    protocol: Option<&str>,
) -> Result<()> {
    if let Some(pool) = pool {
        pool.submit(packet, |event| show(output, vec![event], view, protocol))
    } else {
        show(output, engine.ingest(&packet), view, protocol)
    }
}
fn finish(
    engine: &mut Engine,
    pool: Option<netkit::pipeline::AnalysisPool>,
    output: &mut Output,
    view: View,
    protocol: Option<&str>,
) -> Result<()> {
    if let Some(pool) = pool {
        pool.finish(|event| show(output, vec![event], view, protocol))
    } else {
        show(output, engine.finish(), view, protocol)
    }
}
enum LiveItem {
    Packet(Packet),
    Warning(Source, String),
    Loss(Source, u64, u64, u64),
    Error(String),
}
pub fn live(
    args: &LiveArgs,
    engine: &mut Engine,
    output: &mut Output,
    view: View,
    cancel: Arc<AtomicBool>,
) -> Result<()> {
    if let Some(input) = &args.read {
        if args.filter.is_some() {
            return Err(Error::Invalid(
                "BPF --filter applies to live capture; use --host or --protocol offline".into(),
            ));
        }
        return offline(
            input,
            engine,
            output,
            view,
            args.protocol.as_deref(),
            args.host,
            args.count,
            &cancel,
            args.workers,
        );
    }
    if args.queue_capacity == 0 || args.queue_capacity > 65536 {
        return Err(Error::Invalid("queue-capacity must be 1..65536".into()));
    }
    let pcap = Pcap::load()?;
    let mut pool = create_pool(engine, args.workers)?;
    let available = pcap.interfaces()?;
    let mut selected = Vec::new();
    if args.all_interfaces {
        selected = available
            .iter()
            .filter(|i| i.name != "any" && i.up)
            .cloned()
            .collect();
    } else {
        for selector in &args.interface {
            let found: Vec<_> = available
                .iter()
                .filter(|i| {
                    i.name == *selector
                        || i.description.as_ref() == Some(selector)
                        || selector.parse::<usize>().ok() == Some(i.id)
                })
                .collect();
            if found.len() != 1 {
                return Err(Error::Invalid(format!(
                    "interface '{selector}' is missing or ambiguous; run netkit interfaces"
                )));
            }
            if !selected
                .iter()
                .any(|i: &netkit::capture::Interface| i.id == found[0].id)
            {
                selected.push(found[0].clone());
            }
        }
    }
    if selected.is_empty() {
        return Err(Error::Invalid(
            "select --interface <id/name> or --all-interfaces".into(),
        ));
    }
    if args.queue_capacity.saturating_mul(args.snaplen as usize) > 512 * 1024 * 1024 {
        return Err(Error::Limit(
            "capture queue could exceed 512 MiB; reduce snaplen or queue capacity".into(),
        ));
    }
    let mut writer = if let Some(path) = &args.output {
        let file = if args.overwrite {
            File::create(path)?
        } else {
            OpenOptions::new().write(true).create_new(true).open(path)?
        };
        Some(CaptureWriter::new(BufWriter::new(file))?)
    } else {
        None
    };
    let (tx, rx) = mpsc::sync_channel(args.queue_capacity);
    let start = Instant::now();
    let total = Arc::new(AtomicU64::new(0));
    let mut failure = None;
    thread::scope(|scope| {
        for interface in selected {
            let tx = tx.clone();
            let pcap = pcap.clone();
            let cancel = cancel.clone();
            let total = total.clone();
            let filter = match (&args.filter, args.host) {
                (Some(f), Some(ip)) => Some(format!("({f}) and host {ip}")),
                (Some(f), None) => Some(f.clone()),
                (None, Some(ip)) => Some(format!("host {ip}")),
                _ => None,
            };
            let options = CaptureOptions {
                interface: interface.name,
                sensor: args.sensor.clone(),
                interface_id: interface.id as u32,
                snaplen: args.snaplen,
                promiscuous: !args.no_promiscuous,
                monitor: args.monitor,
                filter,
                ..Default::default()
            };
            scope.spawn(move || {
                let mut capture = match pcap.open(&options) {
                    Ok(v) => v,
                    Err(e) => {
                        let _ = tx.send(LiveItem::Error(e.to_string()));
                        cancel.store(true, Ordering::Relaxed);
                        return;
                    }
                };
                if let Some(w) = &capture.activation_warning {
                    let _ = tx.send(LiveItem::Warning(capture.source().clone(), w.clone()));
                }
                let mut drops = 0u64;
                while !cancel.load(Ordering::Relaxed)
                    && (args.duration == 0 || start.elapsed() < Duration::from_secs(args.duration))
                {
                    match capture.next_packet() {
                        Ok(Some(packet)) => {
                            let index = total.fetch_add(1, Ordering::Relaxed);
                            if args.count > 0 && index >= args.count {
                                cancel.store(true, Ordering::Relaxed);
                                break;
                            }
                            match tx.try_send(LiveItem::Packet(packet)) {
                                Ok(()) => (),
                                Err(mpsc::TrySendError::Full(_)) => drops += 1,
                                Err(mpsc::TrySendError::Disconnected(_)) => break,
                            }
                            if args.count > 0 && index + 1 >= args.count {
                                cancel.store(true, Ordering::Relaxed);
                            }
                        }
                        Ok(None) => thread::sleep(Duration::from_millis(5)),
                        Err(e) => {
                            let _ = tx.send(LiveItem::Error(e.to_string()));
                            cancel.store(true, Ordering::Relaxed);
                            break;
                        }
                    }
                }
                match capture.statistics() {
                    Ok(s) => {
                        let _ = tx.send(LiveItem::Loss(
                            capture.source().clone(),
                            s.dropped as u64,
                            s.interface_dropped as u64,
                            drops,
                        ));
                    }
                    Err(e) => {
                        let _ = tx.send(LiveItem::Warning(
                            capture.source().clone(),
                            format!("capture statistics unavailable: {e}"),
                        ));
                        let _ = tx.send(LiveItem::Loss(capture.source().clone(), 0, 0, drops));
                    }
                }
            });
        }
        drop(tx);
        for item in rx {
            if failure.is_some() {
                continue;
            }
            let result=match item{
            LiveItem::Packet(packet)=>{if let Some(writer)=&mut writer{if let Err(e)=writer.write_packet(&packet){failure=Some(e);cancel.store(true,Ordering::Relaxed);continue;}}process(engine,&mut pool,packet,output,view,args.protocol.as_deref())},
            LiveItem::Warning(source,detail)=>output.emit(&json!({"type":"diagnostic","code":"capture_warning","source":source,"detail":detail})),
            LiveItem::Loss(source,driver,interface,queue)=>show(output,engine.record_capture_loss(source,driver,interface,queue),view,None),
            LiveItem::Error(e)=>Err(Error::Capture(e)),
        };
            if let Err(e) = result {
                failure = Some(e);
                cancel.store(true, Ordering::Relaxed);
            }
        }
    });
    if let Some(writer) = &mut writer {
        writer.flush()?;
    }
    finish(engine, pool, output, view, args.protocol.as_deref())?;
    if let Some(error) = failure {
        return Err(error);
    }
    Ok(())
}
pub fn benchmark(
    input: &Path,
    config: EngineConfig,
    iterations: u64,
    seconds: Option<u64>,
    cancel: &AtomicBool,
    output: &mut Output,
) -> Result<()> {
    if iterations == 0 || seconds == Some(0) {
        return Err(Error::Invalid(
            "benchmark duration/iterations must be positive".into(),
        ));
    }
    let start = Instant::now();
    let mut runs = 0u64;
    let mut packets = 0u64;
    let mut bytes = 0u64;
    let mut messages = 0u64;
    let mut peak = 0usize;
    loop {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        let mut engine = Engine::new(config.clone())?;
        let mut reader = CaptureReader::new(BufReader::new(File::open(input)?), "benchmark")?;
        while let Some(packet) = reader.next_packet()? {
            let _ = engine.ingest(&packet);
            peak = peak.max(engine.buffered_bytes());
            if cancel.load(Ordering::Relaxed) {
                break;
            }
        }
        let _ = engine.finish();
        packets += engine.statistics().packets;
        bytes += engine.statistics().captured_bytes;
        messages += engine.statistics().messages;
        runs += 1;
        if seconds.map_or(runs >= iterations, |s| {
            start.elapsed() >= Duration::from_secs(s)
        }) {
            break;
        }
    }
    let elapsed = start.elapsed().as_secs_f64();
    output.emit(&json!({"runs":runs,"packets":packets,"bytes":bytes,"messages":messages,"elapsed_seconds":elapsed,"packets_per_second":packets as f64/elapsed,"megabits_per_second":bytes as f64*8.0/elapsed/1_000_000.0,"peak_buffered_payload_bytes":peak,"includes_file_io":true,"os":std::env::consts::OS,"architecture":std::env::consts::ARCH}))
}
