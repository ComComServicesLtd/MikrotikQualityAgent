//! Agent entrypoint.
//!
//! Brings up the reflector immediately — an agent must be answerable by its
//! peers even before it has successfully talked to the controller — then runs
//! the controller loop alongside it.

use std::process::ExitCode;
use std::sync::Arc;

use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::{watch, Mutex};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use mqagent::agent::Agent;
use mqagent::cli;
use mqagent::config::Config;
use mqagent::probe::reflector::{Reflector, Registry};

fn main() -> ExitCode {
    let parsed = match cli::parse(std::env::args()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}\n");
            eprintln!("{}", cli::USAGE);
            return ExitCode::from(2);
        }
    };

    // No sub-command on the command line: consult MQ_MODE. RouterOS does not
    // reliably forward a container's `cmd` into argv, so on that platform the
    // environment is the only dependable way to select a mode.
    let command = match parsed {
        cli::Command::Agent => match cli::from_env(|k| std::env::var(k).ok()) {
            Some(Ok(c)) => c,
            Some(Err(e)) => {
                eprintln!("error: {e}");
                return ExitCode::from(2);
            }
            None => cli::Command::Agent,
        },
        other => other,
    };

    match command {
        cli::Command::Help => {
            println!("{}", cli::USAGE);
            ExitCode::SUCCESS
        }
        // Standalone modes take an explicit session ID and need no controller,
        // so the data plane can be exercised against real hardware before the
        // control plane exists.
        cli::Command::Reflect(args) => standalone(cli::run_reflect(args)),
        cli::Command::Probe(args) => standalone(cli::run_probe(*args)),
        cli::Command::Discover(args) => standalone(cli::run_discover(*args)),
        cli::Command::Trace(args) => standalone(cli::run_trace(*args)),
        cli::Command::Scan(args) => standalone(cli::run_scan(*args)),
        cli::Command::TwampReflect(args) => standalone(cli::run_twamp_reflect(args)),
        cli::Command::TwampProbe(args) => standalone(cli::run_twamp_probe(*args)),
        cli::Command::Btest(args) => standalone(cli::run_btest(*args)),
        cli::Command::Capture(args) => standalone(cli::run_capture(*args)),
        cli::Command::Agent => run_managed(),
    }
}

/// Run a one-shot sub-command on a small runtime.
fn standalone<F>(fut: F) -> ExitCode
where
    F: std::future::Future<Output = anyhow::Result<()>>,
{
    init_logging(&std::env::var("MQ_LOG").unwrap_or_else(|_| "warn".into()));

    let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("failed to start runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    match rt.block_on(fut) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run_managed() -> ExitCode {
    // Config is read before the runtime starts so a misconfiguration fails
    // instantly with a clear message, rather than after a tokio backtrace.
    let cfg = match Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("configuration error: {e}");
            eprintln!("\nRequired environment variables:");
            eprintln!("  MQ_CONTROLLER_URL   controller base URL (http:// or https://)");
            eprintln!("  MQ_AGENT_NAME       unique name for this agent");
            eprintln!("  MQ_AGENT_GROUP      mesh group this agent belongs to");
            eprintln!("  MQ_ENROLMENT_TOKEN  pre-shared registration token");
            return ExitCode::from(2);
        }
    };

    init_logging(&cfg.log_filter);

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        // Two workers is plenty for one reflector and a handful of sessions,
        // and leaves CPU for RouterOS itself on a 4-core armv7 board where the
        // router's forwarding path is the thing we must not disturb.
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            error!(error = %e, "failed to start async runtime");
            return ExitCode::FAILURE;
        }
    };

    match runtime.block_on(run(cfg)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!(error = %e, "agent exited with an error");
            ExitCode::FAILURE
        }
    }
}

fn init_logging(filter: &str) {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_new(filter).unwrap_or_else(|_| EnvFilter::new("info")))
        // RouterOS stamps its own log entries, and `logging=yes` on the
        // container routes stdout straight into `/log`. A second timestamp per
        // line would just be noise in a small log buffer.
        .without_time()
        .with_target(false)
        .init();
}

async fn run(cfg: Config) -> anyhow::Result<()> {
    info!(
        name = %cfg.name,
        group = %cfg.group,
        probe_bind = %cfg.probe_bind,
        bandwidth_test = cfg.can_bandwidth_test(),
        version = env!("CARGO_PKG_VERSION"),
        "starting agent"
    );

    if !cfg.can_bandwidth_test() {
        warn!(
            "RouterOS API not configured — throughput tasks will be skipped. \
             Set MQ_ROUTEROS_HOST/USER/PASS to enable bandwidth-test offload."
        );
    }

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // The reflector comes up first and unconditionally. A peer's measurement of
    // this agent must not depend on this agent's own controller connectivity —
    // otherwise a controller outage would look like a network fault between
    // every pair of agents.
    let registry = Arc::new(Mutex::new(Registry::new()));
    let reflector = Reflector::bind(cfg.probe_bind, registry.clone()).await?;
    let bound = reflector.local_addr()?;
    info!(addr = %bound, "reflector listening");

    let reflector_task = tokio::spawn(reflector.run(shutdown_rx.clone()));

    // A managed agent answers TWAMP too when configured, so that switching a
    // standalone responder into the mesh does not take that service away.
    let mut twamp_task = None;
    if let Some(tport) = cfg.twamp_port {
        use mqagent::probe::twamp::{AllowList, TwampReflector};
        let mut allow =
            if cfg.twamp_peers.is_empty() { AllowList::open() } else { AllowList::new() };
        for p in &cfg.twamp_peers {
            allow.allow(*p);
        }
        let open = cfg.twamp_peers.is_empty();
        let tbind: std::net::SocketAddr = ([0, 0, 0, 0], tport).into();
        match TwampReflector::bind(tbind, Arc::new(Mutex::new(allow))).await {
            Ok(tr) => {
                info!(addr = %tr.local_addr()?, open, "TWAMP-Light responder listening");
                if open {
                    warn!("TWAMP is answering any source — set MQ_TWAMP_PEERS to restrict it");
                }
                twamp_task = Some(tokio::spawn(tr.run(shutdown_rx.clone())));
            }
            // Not fatal: the agent's own measurement work is unaffected, and
            // losing the whole agent over an interop extra would be worse.
            Err(e) => warn!(error = %e, port = tport, "could not start the TWAMP responder"),
        }
    }

    // Enrolment may block for a long time if the controller is down, so the
    // reflector is already serving peers by this point — a peer's measurement
    // of us must not depend on our own controller connectivity.
    let mut enrol_shutdown = shutdown_rx.clone();
    let agent = tokio::select! {
        res = Agent::enrol(cfg, registry.clone(), &mut enrol_shutdown) => res?,
        _ = wait_for_shutdown() => {
            let _ = shutdown_tx.send(true);
            let _ = reflector_task.await;
            return Ok(());
        }
    };

    let agent_task = tokio::spawn(agent.run(shutdown_rx.clone()));

    wait_for_shutdown().await;
    info!("shutdown requested, stopping");

    let _ = shutdown_tx.send(true);
    if let Err(e) = agent_task.await {
        warn!(error = %e, "agent loop did not stop cleanly");
    }
    if let Err(e) = reflector_task.await {
        warn!(error = %e, "reflector task did not stop cleanly");
    }
    if let Some(t) = twamp_task {
        let _ = t.await;
    }

    Ok(())
}

/// Wait for SIGTERM or SIGINT.
///
/// RouterOS sends SIGTERM on `/container/stop` (the `stop-signal` property,
/// default 15) and then waits `stop-time` before killing. Handling it means
/// in-flight results get a chance to be submitted rather than lost.
async fn wait_for_shutdown() {
    let mut term = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
            error!(error = %e, "cannot listen for SIGTERM");
            return;
        }
    };
    let mut int = match signal(SignalKind::interrupt()) {
        Ok(s) => s,
        Err(e) => {
            error!(error = %e, "cannot listen for SIGINT");
            return;
        }
    };

    tokio::select! {
        _ = term.recv() => info!("received SIGTERM"),
        _ = int.recv()  => info!("received SIGINT"),
    }
}
