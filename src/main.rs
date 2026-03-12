mod auth;
mod config;
mod crypto;
mod fingerprint;
mod mux;
mod proxy;
mod server;
mod socks5;
mod transport;

use std::time::Duration;

use anyhow::{Result, anyhow};
use tokio::signal;
use tokio::signal::unix::SignalKind;
use tracing::{error, info, warn};

fn main() {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <client|server|fingerprint> <arg>", args[0]);
        std::process::exit(1);
    }

    match args[1].as_str() {
        "fingerprint" => {
            if args.len() < 3 {
                eprintln!("Usage: {} fingerprint <input.bin>", args[0]);
                std::process::exit(1);
            }
            run_fingerprint(&args[2]);
        }
        "client" => {
            if args.len() < 3 {
                eprintln!("Usage: {} client <config.json>", args[0]);
                std::process::exit(1);
            }
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("failed to build tokio runtime");
            rt.block_on(run_client(&args[2]));
        }
        "server" => {
            if args.len() < 3 {
                eprintln!("Usage: {} server <config.json>", args[0]);
                std::process::exit(1);
            }
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("failed to build tokio runtime");
            rt.block_on(run_server(&args[2]));
        }
        _ => {
            eprintln!("Usage: {} <client|server|fingerprint> <arg>", args[0]);
            std::process::exit(1);
        }
    }
}

fn run_fingerprint(input_path: &str) {
    let raw = match std::fs::read(input_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("read {}: {}", input_path, e);
            std::process::exit(1);
        }
    };

    let template = match fingerprint::parse_client_hello(&raw) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("parse ClientHello: {}", e);
            std::process::exit(1);
        }
    };

    let output_path = format!(
        "{}.json",
        input_path.strip_suffix(".bin").unwrap_or(input_path)
    );

    if let Err(e) = template.save(&output_path) {
        eprintln!("write template: {}", e);
        std::process::exit(1);
    }

    if let Err(e) = template.verify(&raw) {
        eprintln!("verification FAILED: {}", e);
        std::process::exit(1);
    }

    eprintln!("domain: {}", template.domain);
    eprintln!("grease fields: {}", template.grease.len());
    eprintln!("verified: static bytes match original 1:1");
    eprintln!("written to {}", output_path);
}

async fn run_server(config_path: &str) {
    let cfg = match config::ServerConfig::load(config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config: {}", e);
            std::process::exit(1);
        }
    };

    let master_key = match crypto::parse_key(&cfg.key) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("invalid key: {}", e);
            std::process::exit(1);
        }
    };

    let (secret, psk) = match crypto::derive_keys(&master_key) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("key derivation: {}", e);
            std::process::exit(1);
        }
    };

    let domain = if let Some(fp_path) = &cfg.fingerprint {
        let template = fingerprint::FingerprintTemplate::load(fp_path).unwrap_or_else(|e| {
            eprintln!("load fingerprint: {}", e);
            std::process::exit(1);
        });
        template.domain.clone()
    } else {
        cfg.disguise.clone()
    };

    let srv = server::Server::new();

    info!("server starting on {}", cfg.bind);

    #[cfg(unix)]
    let mut sigterm =
        signal::unix::signal(SignalKind::terminate()).expect("failed to register SIGTERM handler");

    tokio::select! {
        result = srv.listen(&cfg.bind, &secret, &domain, &psk) => {
            if let Err(e) = result {
                error!("listener error: {}", e);
            }
        }
        _ = signal::ctrl_c() => {
            info!("shutting down");
        }
        _ = sigterm.recv() => {
            info!("sigterm received");
        }
    }
}

async fn run_client(config_path: &str) {
    let cfg = match config::ClientConfig::load(config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config: {}", e);
            std::process::exit(1);
        }
    };

    let master_key = match crypto::parse_key(&cfg.key) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("invalid key: {}", e);
            std::process::exit(1);
        }
    };

    let (secret, psk) = match crypto::derive_keys(&master_key) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("key derivation: {}", e);
            std::process::exit(1);
        }
    };

    let mut backoff = Duration::from_secs(1);
    let mut attempt = 0u32;

    loop {
        attempt += 1;
        if attempt > 1 {
            warn!("reconnecting attempt={} backoff={:?}", attempt, backoff);
        }

        let start = std::time::Instant::now();
        let result = connect(&cfg, &secret, &psk).await;
        if start.elapsed() > Duration::from_secs(60) {
            backoff = Duration::from_secs(1);
            attempt = 0;
        }

        match result {
            Ok(()) => {
                info!("disconnected");
                return;
            }
            Err(e) => {
                error!("connection failed: {}", e);
            }
        }

        let mut sigterm = signal::unix::signal(SignalKind::terminate())
            .expect("failed to register SIGTERM handler");

        tokio::select! {
            _ = tokio::time::sleep(backoff) => {}
            _ = signal::ctrl_c() => {
                info!("shutting down");
                return;
            }
            _ = sigterm.recv() => {
                info!("sigterm received");
                return;
            }
        }

        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
}

async fn connect(cfg: &config::ClientConfig, secret: &[u8], psk: &[u8]) -> Result<()> {
    info!("connecting to {}", cfg.server);

    let template = fingerprint::FingerprintTemplate::load(&cfg.fingerprint)?;
    let mut tls = transport::dial(&cfg.server, secret, &template).await?;
    info!("connected to {}", cfg.server);

    auth::write_msg(
        &mut tls,
        &auth::AuthRequest {
            version: 2,
            proof: crypto::auth_proof(psk, "stw-auth"),
        },
    )
    .await?;

    let resp: auth::AuthResponse = auth::read_msg(&mut tls).await?;

    if !crypto::verify_auth_proof(psk, "stw-auth-ok", &resp.proof) {
        return Err(anyhow!("server auth proof invalid"));
    }

    info!("authenticated");

    let transport = transport::bridge(tls);
    let session = mux::client(transport, auth::smux_config())?;

    info!("tunnel established, socks5 on {}", cfg.listen);

    let socks_addr = cfg.listen.clone();
    let socks_session = session.clone();
    let socks_handle = tokio::spawn(async move {
        if let Err(e) = socks5::listen(&socks_addr, socks_session).await {
            error!("socks5 error: {}", e);
        }
    });

    let mut sigterm =
        signal::unix::signal(SignalKind::terminate()).map_err(|e| anyhow!("sigterm: {}", e))?;

    tokio::select! {
        _ = session.closed() => {
            warn!("session closed, reconnecting");
            socks_handle.abort();
            Err(anyhow!("session closed"))
        }
        _ = signal::ctrl_c() => {
            info!("shutting down");
            socks_handle.abort();
            Ok(())
        }
        _ = sigterm.recv() => {
            info!("sigterm received");
            socks_handle.abort();
            Ok(())
        }
    }
}
