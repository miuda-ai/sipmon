mod analyze;
mod capture;
mod config;
mod correlate;
mod decode;
mod diagnostics;
mod error;
mod export;
mod filter;
mod model;
#[cfg(test)]
mod selftest;
mod store;
mod ui;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use capture::CaptureSource;
use config::{Bucket, Config};
use correlate::Correlator;
use diagnostics::Severity;
use store::evlog::{
    Event, EvlogReader, EvlogWriter, decode_payload, parse_rtcp_rtt_ms, parse_stream_summary,
};
use store::registry::{FocusHint, Snapshot};
use ui::app::RecordState;

#[derive(Parser)]
#[command(
    name = "sipmon",
    version,
    about = "SIP/RTP signaling & media quality monitor (passive, pcap-based)"
)]
struct Cli {
    /// Default capture source: a .pcap/.pcapng file to analyze, or a .evlog to
    /// replay. Equivalent to `sipmon file -r FILE` / `sipmon replay FILE`.
    #[arg(value_name = "FILE")]
    file: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Option<Cmd>,

    // ---- common options ----
    /// Headless: no TUI, print final per-call JSON (for default FILE mode)
    #[arg(long)]
    no_tui: bool,
    /// In-memory only: no event-log writer thread, no continuous files
    #[arg(long)]
    dry_run: bool,
    /// Max retained calls (evict oldest terminated first)
    #[arg(long, default_value = "100000")]
    max_calls: usize,
    /// Drop idle/terminated calls after N minutes (0 = keep until --max-calls).
    /// Live/record default 15. File/replay ignore this and retain the capture.
    #[arg(long, default_value = "15")]
    call_ttl_mins: u64,
    /// Max retained RTP streams
    #[arg(long, default_value = "50000")]
    max_streams: usize,
    /// Max retained diagnostics (ring)
    #[arg(long, default_value = "50000")]
    max_diagnostics: usize,
    /// Minimum diagnostic level: info|warn|critical
    #[arg(long, default_value = "warn")]
    diag_level: String,
    /// Comma-separated TURN server IPs (optional; also auto-learned)
    #[arg(long, value_delimiter = ',')]
    turn_servers: Vec<std::net::IpAddr>,
    /// Comma-separated local (monitored) machine IPs; anchors Call Detail flow
    /// so the local endpoint is always on the right with ingress/egress arrows.
    /// Defaults to this host's own interface addresses.
    #[arg(long, value_delimiter = ',')]
    local_ips: Vec<std::net::IpAddr>,
    /// Truncate stored raw SIP messages to N bytes
    #[arg(long)]
    raw_truncate: Option<usize>,
    /// Heatmap bucket granularity: 15m|1h|1d
    #[arg(long, default_value = "15m")]
    bucket: String,
    /// Write the binary event log to this path
    #[arg(short = 'w', long)]
    evlog: Option<PathBuf>,
    /// Export final snapshot as JSONL on exit
    #[arg(long)]
    export_jsonl: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Live capture from a network interface
    Live {
        /// Interface to capture on (default: any)
        #[arg(short = 'i', long, default_value = "any")]
        interface: String,
        /// BPF filter
        #[arg(short = 'f', long)]
        filter: Option<String>,
        /// Disable RTP/RTCP analysis
        #[arg(long)]
        no_media: bool,
    },
    /// Analyze a pcap/pcapng file
    File {
        #[arg(short = 'r', long)]
        read: String,
        /// Replay speed multiplier (e.g. 1 = real-time)
        #[arg(long)]
        rate: Option<f64>,
        /// Print structured events to stdout (M0 verification)
        #[arg(long)]
        print_events: bool,
        /// Headless: no TUI, print final per-call JSON
        #[arg(long)]
        no_tui: bool,
    },
    /// Record a live capture into a binary event log (live TUI by default,
    /// daemonizable with `-d`)
    Record {
        /// Interface to capture on (default: any)
        #[arg(short = 'i', long, default_value = "any")]
        interface: String,
        /// BPF filter
        #[arg(short = 'f', long)]
        filter: Option<String>,
        /// Disable RTP/RTCP analysis
        #[arg(long)]
        no_media: bool,
        /// No live UI: headless recording only
        #[arg(long)]
        headless: bool,
        /// Event-log output path (required)
        #[arg(short = 'w', long)]
        evlog: PathBuf,
        /// Run as a background daemon
        #[arg(short = 'd', long)]
        daemon: bool,
        /// Write the daemon PID to this file
        #[arg(long)]
        pidfile: Option<PathBuf>,
        /// Daemon stderr/tracing log file (default: /dev/null)
        #[arg(long)]
        logfile: Option<PathBuf>,
    },
    /// Replay a sipmon event log
    Replay {
        /// Event log to replay
        #[arg(value_name = "FILE")]
        file: Option<PathBuf>,
        /// Alias for FILE
        #[arg(short = 'l', long = "evlog", value_name = "FILE")]
        evlog: Option<PathBuf>,
        #[arg(long)]
        no_tui: bool,
    },
    /// Query one Call-ID from an event log (script friendly)
    Query {
        #[arg(short = 'l', long)]
        evlog: String,
        #[arg(short = 'c', long)]
        call_id: String,
    },
    /// Summarize an event log: ASR/traffic/reliability + 5-minute call-availability and network tables
    Stats {
        /// Event log to summarize
        #[arg(value_name = "FILE")]
        file: Option<PathBuf>,
        /// Alias for FILE
        #[arg(short = 'l', long = "evlog", value_name = "FILE")]
        evlog: Option<PathBuf>,
        /// Emit JSON instead of the text table
        #[arg(long)]
        json: bool,
        /// How many IPs to rank by loss% (default 50)
        #[arg(long, default_value_t = crate::store::evstats::DEFAULT_TOP_IPS)]
        top: usize,
    },
    /// Export an event log to JSONL
    Export {
        #[arg(short = 'l', long)]
        evlog: String,
        #[arg(long)]
        jsonl: Option<PathBuf>,
        /// Filter from (unix seconds)
        #[arg(long)]
        from: Option<u64>,
        /// Filter to (unix seconds)
        #[arg(long)]
        to: Option<u64>,
    },
}

struct Shared {
    snap: Arc<Mutex<Arc<Snapshot>>>,
    pause: Arc<AtomicBool>,
    focus: Arc<Mutex<Option<FocusHint>>>,
    /// Current UI filter query (rule syntax, see `filter.rs`): the pipeline
    /// pins matching calls so filter results survive TTL eviction and the
    /// recent-calls snapshot window.
    search: Arc<Mutex<Option<String>>>,
    quit: Arc<AtomicBool>,
    clear: Arc<AtomicBool>,
    /// Live event-log recording state for the TUI top-bar indicator.
    record: RecordState,
}

impl Shared {
    fn new() -> Self {
        Self {
            snap: Arc::new(Mutex::new(Arc::new(Snapshot::default()))),
            pause: Arc::new(AtomicBool::new(false)),
            focus: Arc::new(Mutex::new(None)),
            search: Arc::new(Mutex::new(None)),
            quit: Arc::new(AtomicBool::new(false)),
            clear: Arc::new(AtomicBool::new(false)),
            record: RecordState::default(),
        }
    }
}

fn main() -> Result<()> {
    // Never die on a closed pipe (e.g. `sipmon ... | head`): ignore SIGPIPE.
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }

    // `sipmon -` == stdin pcap stream mode.
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("-") {
        let rest: Vec<String> = args.iter().skip(2).cloned().collect();
        let no_tui = rest.iter().any(|a| a == "--no-tui");
        let cli = Cli::parse_from(std::iter::once("sipmon".to_string()).chain(rest));
        return run_stdin(cli, want_tui(no_tui));
    }

    let cli = Cli::parse();
    let cfg = build_config(&cli);
    let global_no_tui = cli.no_tui;

    match cli.cmd {
        Some(Cmd::Live {
            interface,
            filter,
            no_media,
        }) => {
            let mut c = cfg.clone();
            c.bpf = filter;
            c.no_media = no_media;
            let source = capture::live::LiveSource::open(&interface, c.bpf.as_deref())?;
            run_capture_loop(
                Box::new(source),
                c,
                format!("live:{interface}"),
                want_tui(false),
                false,
                false,
                true,
            )
        }
        Some(Cmd::File {
            read,
            rate,
            print_events,
            no_tui,
        }) => {
            let mut cfg = cfg;
            cfg.call_ttl_secs = 0; // offline: retain the whole capture
            let source = capture::file::FileSource::open(&read, rate)?;
            run_capture_loop(
                Box::new(source),
                cfg,
                format!("file:{read}"),
                want_tui(no_tui || global_no_tui),
                print_events,
                false,
                false,
            )
        }
        Some(Cmd::Record {
            interface,
            filter,
            no_media,
            evlog,
            daemon,
            pidfile,
            logfile,
            headless,
        }) => {
            let mut c = cfg.clone();
            c.bpf = filter;
            c.no_media = no_media;
            run_record(
                c,
                &interface,
                &evlog,
                daemon,
                pidfile.as_deref(),
                logfile.as_deref(),
                headless || global_no_tui,
            )
        }
        Some(Cmd::Replay {
            file,
            evlog,
            no_tui,
        }) => {
            let mut cfg = cfg;
            cfg.call_ttl_secs = 0;
            let path = take_evlog(file, evlog)?;
            run_replay(&cfg, &path, want_tui(no_tui || global_no_tui))
        }
        Some(Cmd::Query { evlog, call_id }) => run_query(&evlog, &call_id),
        Some(Cmd::Stats {
            file,
            evlog,
            json,
            top,
        }) => run_stats(&take_evlog(file, evlog)?, json, top),
        Some(Cmd::Export {
            evlog,
            jsonl,
            from,
            to,
        }) => run_export(&cfg, &evlog, jsonl, from, to),
        None => {
            // No subcommand: a bare FILE defaults to the matching mode,
            // otherwise start a live capture on the default interface.
            if let Some(path) = cli.file {
                return run_default_file(&cfg, &path, global_no_tui);
            }
            let source = capture::live::LiveSource::open("any", cfg.bpf.as_deref())?;
            run_capture_loop(
                Box::new(source),
                cfg,
                "live:any".to_string(),
                want_tui(false),
                false,
                false,
                true,
            )
        }
    }
}

/// Default FILE mode: a .pcap/.pcapng is analyzed like `file -r`, a .evlog is
/// replayed like `replay -l`, a .jsonl snapshot export is loaded for viewing.
fn run_default_file(cfg: &Config, path: &std::path::Path, no_tui: bool) -> Result<()> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    match ext.as_str() {
        "pcap" | "pcapng" => {
            let mut cfg = cfg.clone();
            cfg.call_ttl_secs = 0;
            let source = capture::file::FileSource::open(&path.to_string_lossy(), None)?;
            run_capture_loop(
                Box::new(source),
                cfg,
                format!("file:{}", path.display()),
                want_tui(no_tui),
                false,
                false,
                false,
            )
        }
        "evlog" => {
            let mut cfg = cfg.clone();
            cfg.call_ttl_secs = 0;
            run_replay(&cfg, &path.to_string_lossy(), want_tui(no_tui))
        }
        "jsonl" => run_jsonl_view(cfg, path, want_tui(no_tui)),
        _ => anyhow::bail!(
            "unrecognized file type '{ext}': pass `file -r FILE` for pcap/pcapng, `replay FILE` for an evlog, or a .jsonl snapshot export"
        ),
    }
}

/// Decide whether to launch the TUI: explicit --no-tui wins, otherwise require
/// a tty so piped/CI invocations fall back to headless output.
fn want_tui(explicit_no_tui: bool) -> bool {
    use std::io::IsTerminal;
    !explicit_no_tui && std::io::stdout().is_terminal()
}

/// `replay`/`stats` accept a positional FILE or the older `-l/--evlog` flag.
fn take_evlog(file: Option<PathBuf>, flag: Option<PathBuf>) -> Result<String> {
    file.or(flag)
        .map(|p| p.to_string_lossy().into_owned())
        .ok_or_else(|| anyhow::anyhow!("missing event log FILE (example: sipmon stats cap.evlog)"))
}

fn build_config(cli: &Cli) -> Config {
    let mut c = Config {
        raw_truncate: cli.raw_truncate,
        dry_run: cli.dry_run,
        max_calls: cli.max_calls,
        call_ttl_secs: cli.call_ttl_mins.saturating_mul(60),
        max_streams: cli.max_streams,
        max_diagnostics: cli.max_diagnostics,
        diag_level: cli.diag_level.clone(),
        turn_servers: cli.turn_servers.clone(),
        local_ips: config::resolve_local_ips(&cli.local_ips),
        bucket: Bucket::from_str_lossy(&cli.bucket),
        export_jsonl: cli.export_jsonl.clone(),
        evlog: cli.evlog.clone(),
        ..Config::default()
    };
    if c.dry_run {
        // Dry-run: pure in-memory analysis; no continuous files. Explicit
        // `export` subcommand remains allowed, and exit-time export flags are
        // also honored only if the user passed them explicitly — keep them.
        c.evlog = None;
    }
    c
}

fn run_stdin(cli: Cli, with_tui: bool) -> Result<()> {
    let mut cfg = build_config(&cli);
    cfg.call_ttl_secs = 0;
    let source = unsafe { capture::stdin::StdinSource::open()? };
    run_capture_loop(
        Box::new(source),
        cfg,
        "stdin".to_string(),
        with_tui,
        false,
        false,
        false,
    )
}

/// Record mode: live capture → binary event log, with an optional live TUI.
/// On a tty the live monitor runs while recording; `--headless` (or a
/// non-tty / `-d` daemon context) makes it headless. Same pipeline as
/// `live`/`file`, but it always writes the evlog and never prints per-call
/// JSON.
fn run_record(
    mut cfg: Config,
    interface: &str,
    evlog: &std::path::Path,
    daemon: bool,
    pidfile: Option<&std::path::Path>,
    logfile: Option<&std::path::Path>,
    explicit_headless: bool,
) -> Result<()> {
    if daemon {
        daemonize(logfile)?;
    }
    install_signal_handlers();
    if let Some(p) = pidfile {
        write_pidfile(p)?;
    }

    cfg.evlog = Some(evlog.to_path_buf());
    cfg.dry_run = false; // record always persists

    let source = capture::live::LiveSource::open(interface, cfg.bpf.as_deref())?;
    run_capture_loop(
        Box::new(source),
        cfg,
        format!("record:{interface}"),
        want_tui(explicit_headless),
        false,
        true,
        false,
    )
}

/// A signal (SIGTERM/SIGINT) sets this; the capture loop polls it so the evlog
/// writer can flush and shut down cleanly.
#[cfg(unix)]
static QUIT_SIG: AtomicBool = AtomicBool::new(false);

#[cfg(unix)]
extern "C" fn on_terminate(_: libc::c_int) {
    QUIT_SIG.store(true, Ordering::SeqCst);
}

#[cfg(unix)]
fn install_signal_handlers() {
    unsafe {
        libc::signal(
            libc::SIGTERM,
            on_terminate as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGINT,
            on_terminate as *const () as libc::sighandler_t,
        );
    }
}

#[cfg(unix)]
fn quit_sig_raised() -> bool {
    QUIT_SIG.load(Ordering::SeqCst)
}

#[cfg(not(unix))]
fn quit_sig_raised() -> bool {
    false
}

/// Classic double-fork daemonization. stdio is redirected to `logfile`
/// (default /dev/null). The working directory is left unchanged so relative
/// evlog paths keep working. The logfile is opened before forking so open
/// errors are reported to the invoking shell.
#[cfg(unix)]
fn daemonize(logfile: Option<&std::path::Path>) -> Result<()> {
    use std::os::fd::AsRawFd;
    let devnull = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")?;
    let out = match logfile {
        Some(p) => std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(p)?,
        None => devnull.try_clone()?,
    };
    unsafe {
        match libc::fork() {
            -1 => anyhow::bail!("daemonize: first fork failed"),
            0 => {}
            _ => std::process::exit(0),
        }
        if libc::setsid() < 0 {
            anyhow::bail!("daemonize: setsid failed");
        }
        match libc::fork() {
            -1 => anyhow::bail!("daemonize: second fork failed"),
            0 => {}
            _ => std::process::exit(0),
        }
        libc::dup2(devnull.as_raw_fd(), 0); // stdin
        libc::dup2(out.as_raw_fd(), 1); // stdout
        libc::dup2(out.as_raw_fd(), 2); // stderr
    }
    Ok(())
}

#[cfg(not(unix))]
fn daemonize(_logfile: Option<&std::path::Path>) -> Result<()> {
    anyhow::bail!("daemon mode (-d) is only supported on Unix")
}

fn write_pidfile(path: &std::path::Path) -> Result<()> {
    std::fs::write(path, format!("{}\n", std::process::id()))?;
    Ok(())
}

/// Core pipeline: pull frames → correlate → publish snapshots (+ evlog).
fn run_capture_loop(
    source: Box<dyn CaptureSource>,
    mut cfg: Config,
    name: String,
    with_tui: bool,
    print_events: bool,
    quiet: bool,
    print_stats: bool,
) -> Result<()> {
    // Headless record: the evlog already holds every SIP/stream/teardown
    // event, so keep completed calls out of RAM.
    if !with_tui && quiet {
        cfg.keep_terminated = false;
    }
    let shared = Arc::new(Shared::new());
    let evlog_path: Option<PathBuf> = if cfg.dry_run { None } else { cfg.evlog.clone() };
    if let Some(p) = &evlog_path {
        // Advertise the recording so the TUI top bar can show it.
        if let Ok(mut path) = shared.record.path.lock() {
            *path = Some(p.clone());
        }
        shared.record.active.store(true, Ordering::Relaxed);
    }

    let mut corr = Correlator::new(&cfg, name.clone());
    // Session report on exit: TUI sessions print the full in-memory stats
    // (same output as `sipmon stats`); `--print-stats` runs do too.
    if with_tui || print_stats {
        corr.enable_session_stats();
    }
    let writer = match &evlog_path {
        Some(p) => Some(EvlogWriter::create(p)?),
        None => None,
    };

    let mut source = source;
    let mut last_publish = std::time::Instant::now();

    // TUI runs on the main thread; pipeline runs on a worker.
    let shared2 = shared.clone();
    let handle = std::thread::spawn(move || {
        let mut corr = corr;
        let mut writer = writer;
        // Reused event buffer for the hot drain (Correlator::drain_events_into
        // keeps its capacity across frames instead of regrowing a Vec).
        let mut evbuf: Vec<store::evlog::Event> = Vec::new();
        // Shutdown signal: unblocks capture and lets the loop exit.
        source.set_stop(shared2.quit.clone());
        // Idle-skip bookkeeping: republish only when traffic or focus changed.
        let mut last_pub_pkts = u64::MAX;
        let mut last_pub_focus: Option<FocusHint> = Some(FocusHint::primary("\u{0}init"));
        let mut last_pub_search: Option<String> = None;
        let mut exhausted = false;
        loop {
            if quit_sig_raised() {
                shared2.quit.store(true, Ordering::Relaxed);
            }
            if shared2.quit.load(Ordering::Relaxed) {
                break;
            }
            if shared2.pause.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
            if shared2.clear.swap(false, Ordering::Relaxed) {
                // `x` in the TUI: reset the in-memory state, then republish.
                corr.clear();
                publish(&shared2, &mut corr, false);
            }
            let mut ts = 0u64;
            if !source.next_frame(&mut |frame_ts, linktype, data| {
                ts = frame_ts;
                corr.ingest_frame(frame_ts, linktype, data);
            }) {
                if !exhausted {
                    // Source EOF: final flush + full-fidelity publish so the
                    // UI/export sees the complete capture.
                    exhausted = true;
                    corr.maybe_periodic_flush(corr.reg.last_us.unwrap_or(0));
                    corr.drain_events_into(&mut evbuf);
                    for ev in &evbuf {
                        if let Some(w) = writer.as_mut() {
                            let _ = w.write(ev);
                        }
                    }
                    flush_recorder(&mut writer, &shared2.record);
                    publish(&shared2, &mut corr, true);
                }
                if with_tui {
                    // Capture finished but the TUI is still open: keep the
                    // worker alive so focus/search changes (Enter on a call,
                    // typing a query) are republished into the snapshot.
                    let cur_focus = shared2.focus.lock().ok().and_then(|f| f.clone());
                    let cur_search = shared2.search.lock().ok().and_then(|s| s.clone());
                    if cur_focus != last_pub_focus || cur_search != last_pub_search {
                        publish(&shared2, &mut corr, true);
                        last_pub_focus = cur_focus;
                        last_pub_search = cur_search;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                    continue;
                }
                break;
            }
            corr.maybe_periodic_flush(ts);

            // Drain evlog events.
            corr.drain_events_into(&mut evbuf);
            for ev in &evbuf {
                if print_events {
                    print_event(ev);
                }
                if let Some(w) = writer.as_mut() {
                    let _ = w.write(ev);
                }
            }

            if last_publish.elapsed() >= Duration::from_millis(if with_tui { 100 } else { 1000 }) {
                if with_tui {
                    let cur_pkts = corr.reg.pkts_total;
                    let cur_focus = shared2.focus.lock().ok().and_then(|f| f.clone());
                    let cur_search = shared2.search.lock().ok().and_then(|s| s.clone());
                    if cur_pkts != last_pub_pkts
                        || cur_focus != last_pub_focus
                        || cur_search != last_pub_search
                    {
                        publish(&shared2, &mut corr, false);
                        last_pub_pkts = cur_pkts;
                        last_pub_focus = cur_focus;
                        last_pub_search = cur_search;
                    }
                }
                // Monitor-side drop accounting: packets the kernel/libpcap
                // ring lost look like RTP seq gaps and would be booked as
                // network loss. Surface the counter so the operator can tell
                // monitor drops from real loss.
                if let Some((_recv, dropped)) = source.pcap_stats()
                    && dropped > corr.reg.pkts_dropped
                {
                    tracing::warn!(
                        dropped,
                        "monitor dropped packets (capture ring overflow): loss stats may be overstated"
                    );
                    corr.reg.pkts_dropped = dropped;
                }
                flush_recorder(&mut writer, &shared2.record);
                last_publish = std::time::Instant::now();
            }
        }
        corr.maybe_periodic_flush(corr.reg.last_us.unwrap_or(0));
        corr.drain_events_into(&mut evbuf);
        for ev in &evbuf {
            if let Some(w) = writer.as_mut() {
                let _ = w.write(ev);
            }
        }
        flush_recorder(&mut writer, &shared2.record);
        // Final publish: full fidelity (all calls + all streams) for
        // headless output and exports.
        publish(&shared2, &mut corr, true);
        corr.take_session_stats()
    });

    let session_stats = if with_tui {
        run_tui(shared.clone(), &cfg.local_ips)?;
        shared.quit.store(true, Ordering::Relaxed);
        handle
            .join()
            .map_err(|_| anyhow::anyhow!("pipeline thread panicked"))?
    } else {
        handle
            .join()
            .map_err(|_| anyhow::anyhow!("pipeline thread panicked"))?
    };
    // Headless: print final per-call JSON lines (unless quiet, e.g. record).
    if !with_tui && !quiet && !print_stats {
        let snap = shared.snap.lock().unwrap().clone();
        for c in &snap.calls {
            println!(
                "{}",
                serde_json::json!({"kind": "call", "call_id": c.call_id, "state": c.state.label(), "pdd_ms": c.pdd_ms, "setup_ms": c.setup_ms, "warn": c.warn_count, "crit": c.critical_count})
            );
        }
    }
    // Session report on exit: everything the correlator saw in memory.
    if let Some(acc) = session_stats {
        print!(
            "{}",
            acc.finish(name, 0, None, store::evstats::DEFAULT_TOP_IPS)
                .render_text()
        );
    }

    final_exports(&cfg, &shared)?;
    Ok(())
}

/// Flush the evlog writer and publish its byte count to the TUI top bar.
fn flush_recorder(writer: &mut Option<EvlogWriter<std::fs::File>>, record: &RecordState) {
    if let Some(w) = writer.as_mut() {
        let _ = w.flush();
        record.bytes.store(w.bytes_written(), Ordering::Relaxed);
    }
}

fn publish(shared: &Shared, corr: &mut Correlator, full: bool) {
    let focus = shared.focus.lock().ok().and_then(|f| f.clone());
    corr.set_focus(focus);
    let search = shared.search.lock().ok().and_then(|s| s.clone());
    corr.set_search(search);
    let snap = if full {
        corr.reg.snapshot_full()
    } else {
        corr.reg.snapshot(500)
    };
    if let Ok(mut s) = shared.snap.lock() {
        *s = Arc::new(snap);
    }
}

fn print_event(ev: &Event) {
    let j = match ev {
        Event::SipMsg(e) => serde_json::json!({
            "type": "sip", "ts_us": e.ts_us, "call_id": e.call_id,
            "method": e.method, "status": e.status,
            "src": e.flow.src.to_string(), "dst": e.flow.dst.to_string(),
            "cseq": e.cseq, "branch": e.branch,
        }),
        Event::Txn(e) => {
            serde_json::json!({"type":"txn","ts_us":e.ts_us,"call_id":e.call_id,"method":e.method,"code":e.response_code,"delay_ms":e.delay_ms})
        }
        Event::Call(e) => {
            serde_json::json!({"type":"call","ts_us":e.ts_us,"call_id":e.call_id,"kind":format!("{:?}", e.kind),"state":e.state,"pdd_ms":e.pdd_ms,"setup_ms":e.setup_ms,"hangup":e.hangup_code})
        }
        Event::StreamSnap(e) => {
            serde_json::json!({"type":"stream","ts_us":e.ts_us,"call_id":e.call_id,"ssrc":format!("{:#x}",e.ssrc),"packets":e.packets,"lost":e.lost,"loss_pct":(e.loss_pct*100.0).round()/100.0,"jitter_ms":e.jitter_ms,"mos":e.mos})
        }
        Event::RtcpRtt(e) => {
            serde_json::json!({"type":"rtcp_rtt","ts_us":e.ts_us,"call_id":e.call_id,"ssrc":format!("{:#x}",e.ssrc),"rtt_ms":e.rtt_ms,"oneway_ms":e.oneway_ms})
        }
        Event::HealthBucket(e) => {
            serde_json::json!({"type":"bucket","bucket_us":e.bucket_us,"key":e.dim_key,"metrics":e.metrics})
        }
        Event::Error(e) => {
            serde_json::json!({"type":"error","ts_us":e.ts_us,"kind":e.kind,"msg":e.msg})
        }
        Event::Diag(e) => {
            serde_json::json!({"type":"diag","ts_us":e.ts_us,"call_id":e.call_id,"severity":e.severity,"code":e.code,"message":e.message})
        }
    };
    println!("{j}");
}

fn final_exports(cfg: &Config, shared: &Shared) -> Result<()> {
    let snap = shared.snap.lock().unwrap().clone();
    if let Some(p) = &cfg.export_jsonl {
        export::jsonl::export_snapshot(p, &snap)
            .with_context(|| format!("export jsonl {}", p.display()))?;
        eprintln!("exported {}", p.display());
    }
    Ok(())
}

// ----------------------------- replay -----------------------------

/// Apply one evlog record to the correlator. Undecodable bodies are skipped.
fn replay_apply(corr: &mut Correlator, ty: u8, ts: u64, payload: &[u8]) {
    match ty {
        1 => {
            if let Ok(Event::SipMsg(e)) = decode_payload(ty, ts, payload) {
                corr.ingest_sip(capture::replay::evt_to_sipmsg(&e));
            }
        }
        4 => {
            if let Ok(s) = parse_stream_summary(payload) {
                // Event Log is a 1000-line ring: only keep snaps that actually
                // lost packets (the rest is noise and format!-alloc on every
                // 5s flush of every stream).
                if s.lost > 0 {
                    let cid = s.call_id.as_deref().unwrap_or("");
                    corr.reg.push_event(format!(
                        "stream {cid} ssrc={:#x} pkts={} loss={:.1}%",
                        s.ssrc, s.packets, s.loss_pct
                    ));
                }
                corr.replay_stream_summary(ts, &s);
                corr.reg.import_stream_snap(ts, s);
            }
        }
        5 => {
            if let Ok(rtt) = parse_rtcp_rtt_ms(payload) {
                corr.replay_rtt_sample(ts, rtt);
            }
        }
        8 => {
            if let Ok(Event::Diag(e)) = decode_payload(ty, ts, payload) {
                corr.reg
                    .push_event(format!("[{}] {} {}", e.severity, e.code, e.message));
                // Restore the diagnostic so the Call Detail pane and the
                // per-call Diag column show it after a replay.
                let severity = match e.severity {
                    0 => Severity::Info,
                    1 => Severity::Warn,
                    _ => Severity::Critical,
                };
                if let Some(c) = corr.reg.calls.get_mut(&e.call_id) {
                    match severity {
                        Severity::Critical => c.critical_count += 1,
                        Severity::Warn => c.warn_count += 1,
                        Severity::Info => {}
                    }
                }
                corr.reg.diagnostics.push_back(diagnostics::Diagnostic {
                    ts_us: e.ts_us,
                    call_id: e.call_id.clone(),
                    severity,
                    code: diagnostics::code_from_str(&e.code),
                    message: e.message.clone(),
                });
                while corr.reg.diagnostics.len() > corr.reg.max_diagnostics {
                    corr.reg.diagnostics.pop_front();
                }
            }
        }
        _ => {}
    }
}

fn run_replay(cfg: &Config, evlog: &str, with_tui: bool) -> Result<()> {
    let mut reader = EvlogReader::open(evlog)?;
    let shared = Arc::new(Shared::new());
    let mut corr = Correlator::new(cfg, format!("replay:{evlog}"));
    // Restore the recording machine's UTC offset so the UI can render the
    // original local wall-clock ("当时的时间") instead of guessing at replay time.
    corr.reg.tz_offset_secs = reader.tz_offset_secs();
    // Replay never writes an evlog; skip cloning every SIP raw into a discarded
    // SipMsgEvt (that clone dominated CPU on multi-MB recordings).
    corr.disable_evlog_emit();
    // TUI sessions print the full session report on exit, straight from the
    // replayed events (no evlog re-scan).
    if with_tui {
        corr.enable_session_stats();
    }
    let tz = reader.tz_offset_secs();

    let shared2 = shared.clone();
    let handle = std::thread::spawn(move || {
        let mut corr = corr;
        let mut last_pub_focus: Option<FocusHint> = Some(FocusHint::primary("\u{0}init"));
        let mut last_pub_search: Option<String> = None;
        let mut last_publish = Instant::now();
        let mut done = false;
        loop {
            if shared2.quit.load(Ordering::Relaxed) {
                break;
            }
            if shared2.pause.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
            if shared2.clear.swap(false, Ordering::Relaxed) {
                corr.clear();
                publish(&shared2, &mut corr, false);
            }
            match reader.next_raw() {
                Ok(Some((ty, ts, payload))) => {
                    // Anchor the session start on the first record so the flow's
                    // already-recorded-duration delta matches the recording.
                    corr.reg.ensure_start(ts);
                    replay_apply(&mut corr, ty, ts, payload);
                    // Keep the TUI live while ingesting a large evlog.
                    if with_tui && last_publish.elapsed() >= Duration::from_millis(200) {
                        // Pick up calls ingested since the last publish as
                        // search pins (replay has no periodic flush cycle).
                        if corr.reg.search_hint.is_some() {
                            corr.reg.refresh_search_matches();
                        }
                        publish(&shared2, &mut corr, false);
                        last_publish = Instant::now();
                    }
                }
                Ok(None) | Err(_) => {
                    // Clean EOF, truncated tail (kill mid-write), or a framing
                    // error we cannot resync: keep what was ingested.
                    if !done {
                        done = true;
                        publish(&shared2, &mut corr, true);
                    }
                    if with_tui {
                        // Replay finished but the TUI is still open: keep the
                        // worker alive so focus/search changes are republished
                        // into the snapshot.
                        let cur_focus = shared2.focus.lock().ok().and_then(|f| f.clone());
                        let cur_search = shared2.search.lock().ok().and_then(|s| s.clone());
                        if cur_focus != last_pub_focus || cur_search != last_pub_search {
                            publish(&shared2, &mut corr, true);
                            last_pub_focus = cur_focus;
                            last_pub_search = cur_search;
                        }
                        std::thread::sleep(Duration::from_millis(50));
                        continue;
                    }
                    break;
                }
            }
        }
        publish(&shared2, &mut corr, true);
        corr.take_session_stats()
    });

    if with_tui {
        run_tui(shared.clone(), &cfg.local_ips)?;
        shared.quit.store(true, Ordering::Relaxed);
    }
    let session_stats = handle
        .join()
        .map_err(|_| anyhow::anyhow!("replay thread panicked"))?;
    if let Some(acc) = session_stats {
        // TUI exit: print the full in-memory report (same as `sipmon stats`).
        print!(
            "{}",
            acc.finish(
                format!("replay:{evlog}"),
                0,
                tz,
                store::evstats::DEFAULT_TOP_IPS
            )
            .render_text()
        );
    } else {
        let snap = shared.snap.lock().unwrap().clone();
        for c in &snap.calls {
            println!(
                "{}",
                serde_json::json!({"kind":"call","call_id":c.call_id,"state":c.state.label(),"pdd_ms":c.pdd_ms,"setup_ms":c.setup_ms,"warn":c.warn_count,"crit":c.critical_count})
            );
        }
    }
    final_exports(cfg, &shared)?;
    Ok(())
}

// ----------------------------- jsonl snapshot view -----------------------------

/// View a JSONL snapshot export: load it once and show it in the TUI (or print
/// the per-call lines headless). Unlike replay, there is no event stream — the
/// full snapshot is published immediately and a worker only re-publishes when
/// the UI focuses a call so the Call Detail page gets its per-call diagnostics.
fn run_jsonl_view(cfg: &Config, path: &std::path::Path, with_tui: bool) -> Result<()> {
    let base = export::jsonl::import_snapshot(path)?;
    let shared = Arc::new(Shared::new());
    *shared.snap.lock().unwrap() = Arc::new(base.clone());

    let shared2 = shared.clone();
    let handle = std::thread::spawn(move || {
        let mut last_pub_focus: Option<FocusHint> = Some(FocusHint::primary("\u{0}init"));
        loop {
            if shared2.quit.load(Ordering::Relaxed) {
                break;
            }
            if shared2.pause.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
            if shared2.clear.swap(false, Ordering::Relaxed)
                && let Ok(mut s) = shared2.snap.lock()
            {
                *s = Arc::new(store::registry::Snapshot::default());
            }
            let cur_focus = shared2.focus.lock().ok().and_then(|f| f.clone());
            if cur_focus != last_pub_focus {
                publish_jsonl(&shared2, &base, cur_focus.as_ref());
                last_pub_focus = cur_focus;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    });

    if with_tui {
        run_tui(shared.clone(), &cfg.local_ips)?;
        shared.quit.store(true, Ordering::Relaxed);
        handle
            .join()
            .map_err(|_| anyhow::anyhow!("jsonl view thread panicked"))?;
    } else {
        shared.quit.store(true, Ordering::Relaxed);
        handle
            .join()
            .map_err(|_| anyhow::anyhow!("jsonl view thread panicked"))?;
        let snap = shared.snap.lock().unwrap().clone();
        for c in &snap.calls {
            println!(
                "{}",
                serde_json::json!({"kind":"call","call_id":c.call_id,"state":c.state.label(),"pdd_ms":c.pdd_ms,"setup_ms":c.setup_ms,"warn":c.warn_count,"crit":c.critical_count})
            );
        }
    }
    final_exports(cfg, &shared)?;
    Ok(())
}

/// Rebuild the published snapshot for a jsonl view, filling in the focused
/// call's detail (streams/messages are not present in the export, so the detail
/// is limited to its diagnostics).
fn publish_jsonl(shared: &Shared, base: &store::registry::Snapshot, focus: Option<&FocusHint>) {
    let mut snap = base.clone();
    snap.focus = focus.and_then(|h| build_jsonl_focus(base, &h.primary));
    if let Ok(mut s) = shared.snap.lock() {
        *s = Arc::new(snap);
    }
}

fn build_jsonl_focus(
    base: &store::registry::Snapshot,
    call_id: &str,
) -> Option<store::registry::Focus> {
    let call = base.calls.iter().find(|c| c.call_id == call_id)?;
    Some(store::registry::Focus {
        call_id: call.call_id.clone(),
        state: Some(call.state),
        from_user: call.from_user.clone(),
        to_user: call.to_user.clone(),
        caller_ua: None,
        callee_ua: None,
        caller_addr: None,
        caller_ip: None,
        callee_addr: None,
        messages: Vec::new(),
        legs: Vec::new(),
        b2bua: None,
        streams: Vec::new(),
        diagnostics: base
            .diagnostics
            .iter()
            .filter(|d| d.call_id == call_id)
            .cloned()
            .collect(),
        negotiated_endpoints: Vec::new(),
        pdd_ms: call.pdd_ms,
        setup_ms: call.setup_ms,
        ring_ms: call.ring_ms,
        early_media: call.early_media,
        invite_ts: call.invite_ts,
        trying_ts: None,
        ringing_ts: None,
        answer_ts: None,
        bye_ts: None,
        end_ts: None,
        hangup_by: call.hangup_by,
        hangup_code: call.hangup_code,
        hangup_reason: None,
    })
}

// ----------------------------- query -----------------------------

fn run_query(evlog: &str, call_id: &str) -> Result<()> {
    let mut reader = EvlogReader::open(evlog)?;
    let mut found = 0usize;
    let mut streams = 0usize;
    let mut rtts = 0usize;
    loop {
        let (ty, ts, payload) = match reader.next_raw() {
            Ok(Some(rec)) => rec,
            Ok(None) | Err(_) => break,
        };
        match ty {
            1 => {
                if let Ok(Event::SipMsg(e)) = decode_payload(ty, ts, payload)
                    && e.call_id == call_id
                {
                    found += 1;
                    let label = if e.is_request {
                        e.method.clone().unwrap_or_default()
                    } else {
                        e.status.map(|s| s.to_string()).unwrap_or_default()
                    };
                    println!(
                        "{}",
                        serde_json::json!({
                            "ts_us": e.ts_us, "msg": label,
                            "src": e.flow.src.to_string(), "dst": e.flow.dst.to_string(),
                            "cseq": e.cseq, "branch": e.branch,
                            "from_tag": e.from_tag, "to_tag": e.to_tag,
                            "raw_len": e.raw.len(),
                        })
                    );
                }
            }
            4 => {
                if let Ok(s) = parse_stream_summary(payload)
                    && s.call_id.as_deref() == Some(call_id)
                {
                    streams += 1;
                    println!(
                        "{}",
                        serde_json::json!({
                            "ts_us": ts, "stream": format!("{:#x}", s.ssrc),
                            "codec": s.codec, "packets": s.packets, "lost": s.lost,
                            "loss_pct": s.loss_pct, "jitter_ms": s.jitter_ms, "mos": s.mos,
                        })
                    );
                }
            }
            5 => {
                if let Ok(Event::RtcpRtt(e)) = decode_payload(ty, ts, payload)
                    && e.call_id == call_id
                {
                    rtts += 1;
                    println!(
                        "{}",
                        serde_json::json!({"ts_us": e.ts_us, "ssrc": format!("{:#x}", e.ssrc), "rtt_ms": e.rtt_ms, "oneway_ms": e.oneway_ms})
                    );
                }
            }
            8 => {
                if let Ok(Event::Diag(e)) = decode_payload(ty, ts, payload)
                    && e.call_id == call_id
                {
                    println!(
                        "{}",
                        serde_json::json!({"ts_us": e.ts_us, "diag": e.code, "severity": e.severity, "message": e.message})
                    );
                }
            }
            _ => {}
        }
    }
    eprintln!("query: {found} sip msgs, {streams} stream snaps, {rtts} rtt samples for {call_id}");
    Ok(())
}

// ----------------------------- stats -----------------------------

fn run_stats(evlog: &str, json: bool, top: usize) -> Result<()> {
    let t0 = Instant::now();
    let stats = store::evstats::scan_path(evlog, top)?;
    let elapsed = t0.elapsed();
    if json {
        println!("{}", stats.to_json());
    } else {
        print!("{}", stats.render_text());
    }
    eprintln!(
        "stats: {} events in {:.2}s",
        stats.events.total(),
        elapsed.as_secs_f64()
    );
    Ok(())
}

// ----------------------------- export -----------------------------

fn run_export(
    cfg: &Config,
    evlog: &str,
    jsonl: Option<PathBuf>,
    from: Option<u64>,
    to: Option<u64>,
) -> Result<()> {
    let mut reader = EvlogReader::open(evlog)?;
    let mut corr = Correlator::new(cfg, "export".into());

    let mut streams_extra = Vec::new();
    let mut diags_extra = Vec::new();
    let mut buckets_extra = Vec::new();

    loop {
        let (ty, ts, payload) = match reader.next_raw() {
            Ok(Some(rec)) => rec,
            Ok(None) | Err(_) => break,
        };
        let in_range = from.map(|f| ts >= f * 1_000_000).unwrap_or(true)
            && to.map(|t| ts <= t * 1_000_000).unwrap_or(true);
        match ty {
            1 => {
                if in_range && let Ok(Event::SipMsg(e)) = decode_payload(ty, ts, payload) {
                    corr.ingest_sip(capture::replay::evt_to_sipmsg(&e));
                    // Replay never writes an evlog; drop the re-emitted events
                    // immediately or `pending_events` grows with every message.
                    corr.take_events();
                }
            }
            4 => {
                if in_range && let Ok(s) = parse_stream_summary(payload) {
                    streams_extra.push(s);
                }
            }
            8 => {
                if in_range && let Ok(Event::Diag(e)) = decode_payload(ty, ts, payload) {
                    diags_extra.push(diagnostics::Diagnostic {
                        ts_us: e.ts_us,
                        call_id: e.call_id.clone(),
                        severity: match e.severity {
                            0 => Severity::Info,
                            1 => Severity::Warn,
                            _ => Severity::Critical,
                        },
                        code: diagnostics::code_from_str(&e.code),
                        message: e.message.clone(),
                    });
                }
            }
            6 => {
                if let Ok(Event::HealthBucket(e)) = decode_payload(ty, ts, payload) {
                    buckets_extra.push((e.bucket_us, e.dim_key.clone(), e.metrics.clone()));
                }
            }
            _ => {}
        }
    }

    let mut snap = corr.reg.snapshot_full();
    snap.streams.extend(streams_extra);
    snap.diagnostics.extend(diags_extra);
    snap.buckets.extend(buckets_extra);

    if let Some(p) = jsonl.as_ref() {
        export::jsonl::export_snapshot(p, &snap)?;
        eprintln!("exported {}", p.display());
    }
    if jsonl.is_none() {
        eprintln!("nothing to do: pass --jsonl");
    }
    Ok(())
}

// ----------------------------- TUI -----------------------------

fn run_tui(shared: Arc<Shared>, local_ips: &[std::net::IpAddr]) -> Result<()> {
    let mut terminal =
        ratatui::Terminal::new(ratatui::backend::CrosstermBackend::new(std::io::stdout()))?;
    crossterm::terminal::enable_raw_mode()?;
    crossterm::execute!(std::io::stdout(), crossterm::terminal::EnterAlternateScreen)?;

    let mut app = ui::app::App::new(
        shared.snap.clone(),
        shared.pause.clone(),
        shared.focus.clone(),
        shared.clear.clone(),
        shared.record.clone(),
    );
    app.local_ips = local_ips.to_vec();
    app.search_pin = shared.search.clone();
    let r = (|| -> Result<()> {
        loop {
            terminal.draw(|f| ui::render(f, &mut app))?;
            if !app.poll(Duration::from_millis(100)) {
                break;
            }
        }
        Ok(())
    })();

    crossterm::execute!(std::io::stdout(), crossterm::terminal::LeaveAlternateScreen)?;
    crossterm::terminal::disable_raw_mode()?;
    r
}
