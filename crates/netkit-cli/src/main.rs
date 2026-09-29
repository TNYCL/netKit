mod output;
mod runner;
use clap::{Args, Parser, Subcommand, ValueEnum};
use netkit::{
    capture::Pcap,
    discovery::{self, ScanOptions, ScanTransport},
    tshark, *,
};
use output::Output;
use runner::{View, live, offline};
use serde::Deserialize;
use serde_json::json;
use std::{
    fs::File,
    io::{self, Read},
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

#[derive(Parser)]
#[command(
    name = "netkit",
    version,
    about = "netKit — capture, reconstruct and understand network traffic",
    after_help = "Capture sees traffic delivered to the selected interfaces. Active discovery is a separate command."
)]
struct Cli {
    #[arg(long, global = true, value_enum, default_value = "table")]
    format: Format,
    /// TOML configuration; explicitly supplied flags override its settings.
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    /// Include medical fields and potentially sensitive application headers.
    #[arg(long, global = true)]
    include_sensitive: bool,
    #[command(subcommand)]
    command: Commands,
}
#[derive(Clone, Copy, ValueEnum, PartialEq, Eq)]
enum Format {
    Table,
    Json,
    Jsonl,
}
#[derive(Subcommand)]
enum Commands {
    /// List capture interfaces and monitor-mode capabilities.
    Interfaces,
    /// Capture packets and optionally save PCAPNG while decoding.
    Capture(LiveArgs),
    /// Observe devices passively from live traffic or a capture file.
    Devices(LiveArgs),
    /// Observe bidirectional connections and their protocols.
    Flows(LiveArgs),
    /// Read PCAP/PCAPNG without capture drivers.
    #[command(alias = "read")]
    Analyze(AnalyzeArgs),
    /// Decode application-provided message bytes from a file.
    Decode {
        input: PathBuf,
        #[arg(long)]
        protocol: String,
    },
    /// Explicitly probe a selected network for responsive TCP hosts.
    Discover(DiscoverArgs),
    /// Explicitly probe selected TCP or UDP ports.
    Scan(ScanArgs),
    /// Show native/external protocol support and its limitations.
    Protocols,
    /// Check runtime prerequisites without capturing or scanning.
    Doctor,
    /// Print a TOML configuration template.
    Config,
    /// Run a separately installed TShark, optionally with TLS secrets.
    Deep(DeepArgs),
    /// Replay a capture for benchmark or soak validation.
    Benchmark {
        input: PathBuf,
        #[arg(long, default_value_t = 1)]
        iterations: u64,
        #[arg(long)]
        seconds: Option<u64>,
    },
}
#[derive(Args, Clone)]
pub(crate) struct LiveArgs {
    /// Analysis workers; the same conversation always stays on one worker.
    #[arg(long, default_value_t = 1)]
    workers: usize,
    /// Interface ID, name or exact description. Repeat to combine interfaces.
    #[arg(short = 'i', long, conflicts_with = "all_interfaces")]
    interface: Vec<String>,
    #[arg(long)]
    all_interfaces: bool,
    #[arg(long,conflicts_with_all=["interface","all_interfaces","monitor","output"])]
    read: Option<PathBuf>,
    #[arg(long)]
    filter: Option<String>,
    #[arg(long)]
    host: Option<IpAddr>,
    /// Select output messages; does not force the decoder.
    #[arg(long)]
    protocol: Option<String>,
    #[arg(long)]
    decode_as: Option<String>,
    #[arg(long, alias = "write")]
    output: Option<PathBuf>,
    #[arg(long)]
    overwrite: bool,
    #[arg(long, default_value_t = 0)]
    count: u64,
    #[arg(long, default_value_t = 0)]
    duration: u64,
    #[arg(long, default_value_t = 262144)]
    snaplen: u32,
    #[arg(long)]
    monitor: bool,
    #[arg(long)]
    no_promiscuous: bool,
    #[arg(long, default_value = "local")]
    sensor: String,
    #[arg(long, default_value_t = 256)]
    queue_capacity: usize,
    #[arg(long)]
    packets: bool,
}
#[derive(Args)]
struct AnalyzeArgs {
    #[arg(long, default_value_t = 1)]
    workers: usize,
    input: PathBuf,
    #[arg(long)]
    protocol: Option<String>,
    #[arg(long)]
    decode_as: Option<String>,
    #[arg(long)]
    host: Option<IpAddr>,
    #[arg(long)]
    packets: bool,
    #[arg(long, default_value_t = 0)]
    count: u64,
}
#[derive(Args)]
struct DiscoverArgs {
    #[arg(long)]
    network: String,
    #[arg(long, default_value = "80,443,22,445")]
    ports: String,
    #[command(flatten)]
    limits: ScanLimits,
}
#[derive(Args)]
struct ScanArgs {
    #[arg(long)]
    target: String,
    #[arg(long, default_value = "80,443")]
    ports: String,
    #[arg(long, conflicts_with = "udp")]
    tcp: bool,
    #[arg(long)]
    udp: bool,
    #[command(flatten)]
    limits: ScanLimits,
}
#[derive(Args)]
struct ScanLimits {
    #[arg(long, default_value_t = 500)]
    timeout_ms: u64,
    #[arg(long, default_value_t = 32)]
    concurrency: usize,
    #[arg(long, default_value_t = 100)]
    rate: u32,
    #[arg(long, default_value_t = 4096)]
    max_hosts: usize,
    #[arg(long, default_value_t = 1000000)]
    max_probes: usize,
}
#[derive(Args)]
struct DeepArgs {
    input: PathBuf,
    #[arg(long)]
    keylog: Option<PathBuf>,
    #[arg(long)]
    display_filter: Option<String>,
    #[arg(long, default_value = "tshark")]
    tshark: PathBuf,
}
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Configuration {
    engine: EngineConfig,
}

fn active(
    target: &str,
    ports: &str,
    limits: &ScanLimits,
    transport: ScanTransport,
    discover: bool,
    output: &mut Output,
    cancel: Arc<AtomicBool>,
) -> Result<()> {
    let options = ScanOptions {
        addresses: discovery::targets(target, limits.max_hosts)?,
        ports: discovery::parse_ports(ports)?,
        transport,
        timeout: Duration::from_millis(limits.timeout_ms),
        concurrency: limits.concurrency,
        rate_per_second: limits.rate,
        max_probes: limits.max_probes,
    };
    let mut output_error = None;
    let mut observed = std::collections::BTreeSet::new();
    discovery::scan(&options, cancel.clone(), |result| {
        if discover
            && (!matches!(result.state.as_str(), "open" | "closed")
                || !observed.insert(result.address))
        {
            return;
        }
        if output_error.is_none() {
            if let Err(e) = output.emit(&result) {
                output_error = Some(e);
                cancel.store(true, Ordering::Relaxed);
            }
        }
    })?;
    if let Some(e) = output_error {
        return Err(e);
    }
    Ok(())
}
fn run(cli: Cli, cancel: Arc<AtomicBool>) -> Result<()> {
    let mut config = if let Some(path) = &cli.config {
        let mut raw = String::new();
        File::open(path)?.take(65537).read_to_string(&mut raw)?;
        if raw.len() > 65536 {
            return Err(Error::Limit("configuration exceeds 64 KiB".into()));
        }
        toml::from_str::<Configuration>(&raw)
            .map_err(|e| Error::Invalid(format!("configuration: {e}")))?
            .engine
    } else {
        EngineConfig::default()
    };
    if cli.include_sensitive {
        config.include_sensitive = true;
    }
    if matches!(cli.command, Commands::Config) {
        println!(
            "# netKit: scans are explicit commands; capture is passive.\n[engine]\n{}",
            toml::to_string_pretty(&config).map_err(|e| Error::Invalid(e.to_string()))?
        );
        return Ok(());
    }
    let mut output = Output::new(cli.format)?;
    let result = (|| -> Result<()> {
        match cli.command {
            Commands::Interfaces => {
                for interface in Pcap::load()?.interfaces()? {
                    output.emit(&interface)?;
                }
            }
            Commands::Doctor => {
                let capture = match Pcap::load() {
                    Ok(p) => {
                        json!({"available":true,"version":p.version(),"interfaces":p.interfaces().map(|v|v.len()).ok()})
                    }
                    Err(e) => json!({"available":false,"reason":e.to_string()}),
                };
                output.emit(&json!({"product":"netKit","version":env!("CARGO_PKG_VERSION"),"os":std::env::consts::OS,"architecture":std::env::consts::ARCH,"offline_analysis":true,"capture":capture,"tshark":tshark::version(Path::new("tshark")).ok()}))?;
            }
            Commands::Protocols => {
                for protocol in netkit::protocols::support().as_array().unwrap() {
                    output.emit(protocol)?;
                }
            }
            Commands::Capture(args) => {
                config.emit_packets |= args.packets;
                config.protocol = args.decode_as.clone().or(config.protocol);
                live(
                    &args,
                    &mut Engine::new(config)?,
                    &mut output,
                    View::All,
                    cancel,
                )?;
            }
            Commands::Devices(args) => {
                config.protocol = args.decode_as.clone().or(config.protocol);
                live(
                    &args,
                    &mut Engine::new(config)?,
                    &mut output,
                    View::Devices,
                    cancel,
                )?;
            }
            Commands::Flows(args) => {
                config.protocol = args.decode_as.clone().or(config.protocol);
                live(
                    &args,
                    &mut Engine::new(config)?,
                    &mut output,
                    View::Flows,
                    cancel,
                )?;
            }
            Commands::Analyze(args) => {
                config.emit_packets |= args.packets;
                config.protocol = args.decode_as.or(config.protocol);
                offline(
                    &args.input,
                    &mut Engine::new(config)?,
                    &mut output,
                    View::All,
                    args.protocol.as_deref(),
                    args.host,
                    args.count,
                    &cancel,
                    args.workers,
                )?;
            }
            Commands::Decode { input, protocol } => {
                let mut data = Vec::new();
                File::open(input)?
                    .take(config.max_message_bytes as u64 + 1)
                    .read_to_end(&mut data)?;
                for message in Engine::new(config)?.decode_message(&protocol, &data)? {
                    output.emit(&message)?;
                }
            }
            Commands::Discover(args) => active(
                &args.network,
                &args.ports,
                &args.limits,
                ScanTransport::Tcp,
                true,
                &mut output,
                cancel,
            )?,
            Commands::Scan(args) => active(
                &args.target,
                &args.ports,
                &args.limits,
                if args.udp {
                    ScanTransport::Udp
                } else {
                    ScanTransport::Tcp
                },
                false,
                &mut output,
                cancel,
            )?,
            Commands::Deep(args) => {
                if !config.include_sensitive {
                    return Err(Error::Invalid("external dissectors expose unmasked payloads; select --include-sensitive explicitly for netkit deep".into()));
                }
                let mut options = tshark::TsharkOptions::new(args.input);
                options.executable = args.tshark;
                options.keylog = args.keylog;
                options.display_filter = args.display_filter;
                tshark::analyze(&options, cancel, |v| output.emit(&v))?;
            }
            Commands::Benchmark {
                input,
                iterations,
                seconds,
            } => runner::benchmark(&input, config, iterations, seconds, &cancel, &mut output)?,
            Commands::Config => unreachable!(),
        }
        Ok(())
    })();
    let finish = output.finish();
    result.and(finish)
}
fn main() {
    let cli = Cli::parse();
    let cancelled = Arc::new(AtomicBool::new(false));
    let c = cancelled.clone();
    if let Err(e) = ctrlc::set_handler(move || c.store(true, Ordering::Relaxed)) {
        eprintln!("netkit: cannot install cancellation handler: {e}");
        std::process::exit(1);
    }
    if let Err(e) = run(cli, cancelled) {
        if matches!(&e,Error::Io(e) if e.kind()==io::ErrorKind::BrokenPipe) {
            return;
        }
        eprintln!("netkit: {e}");
        std::process::exit(match e {
            Error::Invalid(_) => 2,
            Error::Unavailable(_) => 3,
            Error::Capture(_) => 4,
            Error::Limit(_) => 5,
            _ => 1,
        });
    }
}
