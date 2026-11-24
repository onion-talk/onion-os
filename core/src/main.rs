//! OnionOS v1.0.0 Binary, Single-Container Supervisor & Multicall CLI Entrypoint
//! Supports `onion-os`, `onion-pqc`, `onion-clean` and `onion-osint` via `argv[0]` symlinks or subcommands.

use std::env;
use std::fs;
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use onion_os::{
    build_router, forensics, osint, run_deterministic_self_test, supervisor, vault, AppConfig,
    AppState, ONIONOS_VERSION,
};
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

fn harden_process_anti_forensics() {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: PR_SET_DUMPABLE with arg2=0 disables core dumps and ptrace attach on Linux.
        unsafe {
            let _ = libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        }
    }

    #[cfg(unix)]
    {
        // SAFETY: getrlimit/setrlimit use a valid stack-allocated rlimit struct to zero soft core size.
        unsafe {
            let mut rlim = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if libc::getrlimit(libc::RLIMIT_CORE, &mut rlim) == 0 {
                rlim.rlim_cur = 0;
                let _ = libc::setrlimit(libc::RLIMIT_CORE, &rlim);
            }
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    harden_process_anti_forensics();

    let raw_args: Vec<String> = env::args().collect();
    let argv0 = raw_args.first().map(String::as_str).unwrap_or("onion-os");
    let prog_stem = Path::new(argv0)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("onion-os")
        .to_ascii_lowercase();

    let args = if raw_args.len() > 1 {
        &raw_args[1..]
    } else {
        &[][..]
    };

    let result = match prog_stem.as_str() {
        "onion-pqc" => dispatch_pqc_cli(args),
        "onion-clean" => dispatch_clean_cli(args),
        "onion-osint" => dispatch_osint_cli(args).await,
        _ => dispatch_root_cli(args).await,
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err_msg) => {
            eprintln!("{err_msg}");
            ExitCode::FAILURE
        }
    }
}

async fn dispatch_root_cli(args: &[String]) -> Result<(), String> {
    let Some(first) = args.first().map(String::as_str) else {
        return run_http_compositor().await;
    };

    match first {
        "serve" | "--serve" => run_http_compositor().await,
        "browser-agent" | "--browser-agent" => supervisor::run_browser_agent_cli().await,
        "--self-test" | "self-test" => {
            let report = run_deterministic_self_test().await?;
            let pretty =
                serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?;
            println!("{pretty}");
            Ok(())
        }
        "--healthcheck" | "healthcheck" => run_cli_healthcheck().await,
        "--version" | "-V" | "version" => {
            println!("onion-os {ONIONOS_VERSION}");
            Ok(())
        }
        "--help" | "-h" | "help" => {
            print_usage();
            Ok(())
        }
        "pqc" => dispatch_pqc_cli(&args[1..]),
        "clean" => dispatch_clean_cli(&args[1..]),
        "osint" => dispatch_osint_cli(&args[1..]).await,
        other => Err(format!(
            "Unknown onion-os command '{other}'. Run 'onion-os --help' for usage."
        )),
    }
}

fn dispatch_pqc_cli(args: &[String]) -> Result<(), String> {
    let sub = args.first().map(String::as_str).unwrap_or("help");
    match sub {
        "keygen" => {
            let bundle = vault::keygen_hybrid_bundle();
            let json = serde_json::to_string_pretty(&bundle).map_err(|e| e.to_string())?;
            println!("{json}");
            Ok(())
        }
        "seal" => {
            if args.len() < 4 {
                return Err(
                    "Usage: onion-pqc seal <mlkem_pubkey_hex> <x25519_pubkey_hex> <input_file>"
                        .into(),
                );
            }
            let ek = hex::decode(args[1].trim())
                .map_err(|e| format!("Invalid ML-KEM pubkey hex: {e}"))?;
            let x_vec = hex::decode(args[2].trim())
                .map_err(|e| format!("Invalid X25519 pubkey hex: {e}"))?;
            let x_pk: [u8; 32] = x_vec
                .try_into()
                .map_err(|_| "X25519 pubkey must decode to 32 bytes".to_owned())?;
            let plain = fs::read_to_string(&args[3])
                .map_err(|e| format!("Failed reading {}: {e}", args[3]))?;
            let sealed =
                vault::seal_pqc_envelope(&ek, &x_pk, None, &plain).map_err(|e| e.to_string())?;
            println!("{}", sealed.envelope);
            Ok(())
        }
        "open" => {
            if args.len() < 4 {
                return Err(
                    "Usage: onion-pqc open <mlkem_secret_hex> <x25519_secret_hex> <envelope_file>"
                        .into(),
                );
            }
            let dk = hex::decode(args[1].trim())
                .map_err(|e| format!("Invalid ML-KEM secret hex: {e}"))?;
            let x_vec = hex::decode(args[2].trim())
                .map_err(|e| format!("Invalid X25519 secret hex: {e}"))?;
            let x_sk: [u8; 32] = x_vec
                .try_into()
                .map_err(|_| "X25519 secret key must decode to 32 bytes".to_owned())?;
            let env_str = fs::read_to_string(&args[3])
                .map_err(|e| format!("Failed reading {}: {e}", args[3]))?;
            let opened =
                vault::open_pqc_envelope(&dk, &x_sk, &env_str).map_err(|e| e.to_string())?;
            print!("{}", opened.plaintext);
            Ok(())
        }
        _ => Err(
            "Usage: onion-pqc <keygen | seal <ek> <x_pk> <file> | open <dk> <x_sk> <file>>".into(),
        ),
    }
}

fn dispatch_clean_cli(args: &[String]) -> Result<(), String> {
    let sub = args.first().map(String::as_str).unwrap_or("help");
    match sub {
        "scrub" => {
            if args.len() < 3 {
                return Err("Usage: onion-clean scrub <input_path> <output_path>".into());
            }
            let in_path = Path::new(&args[1]);
            let out_path = Path::new(&args[2]);
            let raw =
                fs::read(in_path).map_err(|e| format!("Failed reading {}: {e}", args[1]))?;
            let fname = in_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("input.bin");
            let outcome = forensics::scrub_bytes(fname, &raw).map_err(|e| e.to_string())?;
            fs::write(out_path, &outcome.clean_bytes_vec)
                .map_err(|e| format!("Failed writing {}: {e}", args[2]))?;

            let summary = serde_json::json!({
                "format": outcome.format,
                "originalBytes": outcome.original_bytes,
                "cleanBytes": outcome.clean_bytes_vec.len(),
                "removedSegments": outcome.removed_segments,
                "sha256Before": outcome.sha256_before,
                "sha256After": outcome.sha256_after,
                "outputPath": out_path.display().to_string(),
            });
            let pretty =
                serde_json::to_string_pretty(&summary).map_err(|e| e.to_string())?;
            println!("{pretty}");
            Ok(())
        }
        _ => Err("Usage: onion-clean scrub <input_path> <output_path>".into()),
    }
}

async fn dispatch_osint_cli(args: &[String]) -> Result<(), String> {
    let sub = args.first().map(String::as_str).unwrap_or("help");
    match sub {
        "validate" => {
            let Some(addr) = args.get(1) else {
                return Err("Usage: onion-osint validate <address.onion>".into());
            };
            let res = osint::validate_onion_v3(addr);
            let pretty = serde_json::to_string_pretty(&res).map_err(|e| e.to_string())?;
            println!("{pretty}");
            if res.valid {
                Ok(())
            } else {
                Err(format!("Invalid Tor v3 onion address: {}", res.reason))
            }
        }
        "probe" => {
            let Some(url) = args.get(1) else {
                return Err("Usage: onion-osint probe <http(s)://target>".into());
            };
            let cfg = AppConfig::from_env();
            let res = osint::probe_via_tor(url, &cfg.tor_socks_addr)
                .await
                .map_err(|e| e.to_string())?;
            let pretty = serde_json::to_string_pretty(&res).map_err(|e| e.to_string())?;
            println!("{pretty}");
            if res.ok {
                Ok(())
            } else {
                Err(res.error.unwrap_or_else(|| "Tor probe failed".into()))
            }
        }
        _ => Err("Usage: onion-osint <validate <addr.onion> | probe <url>>".into()),
    }
}

async fn run_cli_healthcheck() -> Result<(), String> {
    let port = env::var("ONIONOS_BIND_PORT")
        .ok()
        .and_then(|v| v.parse::<u16>().ok())
        .unwrap_or(8430);
    let url = format!("http://127.0.0.1:{port}/api/health");

    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(3))
        .build()
        .map_err(|e| format!("Healthcheck client init failed: {e}"))?;

    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("Healthcheck request failed ({url}): {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("Healthcheck returned HTTP {}", resp.status()));
    }
    let body = resp.text().await.map_err(|e| e.to_string())?;
    println!("{body}");
    Ok(())
}

async fn run_http_compositor() -> Result<(), String> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("onion_os=info,tower_http=info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();

    let config = AppConfig::from_env();
    let bind_str = format!("{}:{}", config.bind_addr, config.bind_port);
    let state = AppState::new(config)?;

    // Optionally supervise local `/usr/local/bin/oniontalk-node` on 127.0.0.1:8420
    state
        .supervisor
        .ensure_oniontalk_node(&state.config.oniontalk_internal_url)
        .await;

    let shutdown_state = Arc::clone(&state);
    let router = build_router(state);

    let listener = TcpListener::bind(&bind_str)
        .await
        .map_err(|e| format!("Failed to bind OnionOS compositor on {bind_str}: {e}"))?;

    tracing::info!(
        version = ONIONOS_VERSION,
        bind = %bind_str,
        "OnionOS GNOME 47 Amnesic Tor PQC Compositor listening"
    );

    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal(shutdown_state))
        .await
        .map_err(|e| format!("OnionOS server runtime error: {e}"))?;

    Ok(())
}

async fn shutdown_signal(state: Arc<AppState>) {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        } else {
            std::future::pending::<()>().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("Shutdown signal received — tearing down OnionShare, Relay, Browser & zeroizing RAM");
    let _ = state.pty_registry.kill_all().await;
    let _ = tokio::join!(
        state
            .onionshare
            .stop_with_timeout(Duration::from_millis(500)),
        state.relay.stop_with_timeout(Duration::from_millis(400)),
        state.supervisor.stop_browser(),
    );
    state.vault.lock().await;
}

fn print_usage() {
    println!(
        "OnionOS v{ONIONOS_VERSION} — Consolidated Sovereign GNOME 47 Tor & PQC Linux Core\n\
         Usage:\n\
           onion-os [serve]                        Start GNOME 47 Web Desktop Compositor (:8430)\n\
           onion-os browser-agent                  Start isolated UID 10015 Browser Agent (:6902)\n\
           onion-os --self-test                    Run deterministic PQC + TOTP + QR + Files + MAT2 + OSINT self-test\n\
           onion-os --healthcheck                  Probe local /api/health readiness\n\
           onion-pqc keygen                        Generate ML-KEM-768 + X25519 + Ed25519 key bundle\n\
           onion-clean scrub <in> <out>            Strip binary EXIF/XMP/ID3/PDF metadata\n\
           onion-osint validate <addr.onion>       Validate Tor v3 SHA3-256 + Ed25519 onion address"
    );
}
