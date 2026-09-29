#![forbid(unsafe_code)]
//! Bounded, flow-affine analysis workers. Input is backpressured; output is
//! consumed while submitting to avoid producer/consumer deadlock. Ordering is
//! preserved per network conversation, not across unrelated conversations.
use crate::{Engine, EngineConfig, Error, Event, Packet, ProtocolRegistry, Result, packet};
use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender, TrySendError},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

pub struct AnalysisPool {
    inputs: Vec<SyncSender<Packet>>,
    output: Option<Receiver<Result<Vec<Event>>>>,
    workers: Vec<JoinHandle<()>>,
    stop: Arc<AtomicBool>,
    max_packet: usize,
}
impl AnalysisPool {
    /// `max_total_bytes`, max_flows and max_devices are divided between workers.
    /// Input queues are an additional bounded allocation: workers * queue * max_packet.
    pub fn new(
        config: EngineConfig,
        registry: ProtocolRegistry,
        workers: usize,
        queue: usize,
    ) -> Result<Self> {
        if workers == 0 || workers > 64 || queue == 0 || queue > 4096 {
            return Err(Error::Invalid(
                "workers must be 1..64 and queue capacity 1..4096".into(),
            ));
        }
        if workers
            .saturating_mul(queue)
            .saturating_mul(config.max_packet_bytes)
            > 512 * 1024 * 1024
        {
            return Err(Error::Limit(
                "analysis input queues could exceed 512 MiB".into(),
            ));
        }
        let mut per_worker = config.clone();
        per_worker.max_total_bytes /= workers;
        per_worker.max_flows /= workers;
        per_worker.max_devices /= workers;
        per_worker.validate()?;
        let mut engines = Vec::new();
        for worker in 0..workers {
            let mut engine = Engine::with_registry(per_worker.clone(), registry.clone())?;
            engine.set_namespace(worker as u16 + 1);
            engines.push(engine);
        }
        let (output_tx, output) = mpsc::sync_channel(workers * 2);
        let stop = Arc::new(AtomicBool::new(false));
        let mut inputs = Vec::new();
        let mut handles = Vec::new();
        for mut engine in engines {
            let (tx, rx) = mpsc::sync_channel::<Packet>(queue);
            inputs.push(tx);
            let output_tx = output_tx.clone();
            let stop = stop.clone();
            handles.push(thread::spawn(move || {
                for packet in rx {
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    let events = engine.ingest(&packet);
                    if output_tx.send(Ok(events)).is_err() {
                        return;
                    }
                }
                if !stop.load(Ordering::Relaxed) {
                    let _ = output_tx.send(Ok(engine.finish()));
                }
            }));
        }
        drop(output_tx);
        Ok(Self {
            inputs,
            output: Some(output),
            workers: handles,
            stop,
            max_packet: config.max_packet_bytes,
        })
    }
    fn shard(&self, packet: &Packet) -> usize {
        let mut hasher = DefaultHasher::new();
        packet.source.hash(&mut hasher);
        if let Ok(parsed) = packet::parse(packet) {
            parsed.vlans.hash(&mut hasher);
            if let Some(network) = parsed.network {
                // Include both directions in one shard, and omit transport ports so
                // non-initial IP fragments follow the same worker as their flow.
                let (a, b) = if network.src <= network.dst {
                    (network.src, network.dst)
                } else {
                    (network.dst, network.src)
                };
                a.hash(&mut hasher);
                b.hash(&mut hasher);
            }
        }
        hasher.finish() as usize % self.inputs.len()
    }
    pub fn submit<F: FnMut(Event) -> Result<()>>(
        &mut self,
        mut packet: Packet,
        mut emit: F,
    ) -> Result<()> {
        if packet.data.len() > self.max_packet {
            return Err(Error::Limit("packet exceeds worker input bound".into()));
        }
        let shard = self.shard(&packet);
        loop {
            self.drain(&mut emit)?;
            match self.inputs[shard].try_send(packet) {
                Ok(()) => break,
                Err(TrySendError::Full(p)) => {
                    packet = p;
                    match self
                        .output
                        .as_ref()
                        .unwrap()
                        .recv_timeout(Duration::from_millis(10))
                    {
                        Ok(events) => {
                            for event in events? {
                                emit(event)?;
                            }
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => (),
                        Err(_) => {
                            return Err(Error::Unavailable("analysis workers disconnected".into()));
                        }
                    }
                }
                Err(_) => return Err(Error::Unavailable("analysis worker disconnected".into())),
            }
        }
        self.drain(emit)
    }
    pub fn drain<F: FnMut(Event) -> Result<()>>(&mut self, mut emit: F) -> Result<()> {
        while let Ok(events) = self.output.as_ref().unwrap().try_recv() {
            for event in events? {
                emit(event)?;
            }
        }
        Ok(())
    }
    pub fn finish<F: FnMut(Event) -> Result<()>>(mut self, mut emit: F) -> Result<()> {
        self.inputs.clear();
        let output = self.output.take().unwrap();
        let mut failure = None;
        for batch in output {
            match batch {
                Ok(events) => {
                    for event in events {
                        if failure.is_none() {
                            if let Err(e) = emit(event) {
                                failure = Some(e);
                                self.stop.store(true, Ordering::Relaxed);
                            }
                        }
                    }
                }
                Err(e) => {
                    failure = Some(e);
                    self.stop.store(true, Ordering::Relaxed);
                }
            }
        }
        for worker in self.workers.drain(..) {
            if worker.join().is_err() {
                failure = Some(Error::Unavailable("analysis worker panicked".into()));
            }
        }
        if let Some(e) = failure {
            Err(e)
        } else {
            Ok(())
        }
    }
}
impl Drop for AnalysisPool {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.inputs.clear();
        self.output.take();
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}
