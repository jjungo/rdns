mod cache;
mod config;
mod dns;
mod reload;
mod server;
mod stats;

use config::Config;
use server::DnsServer;
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Get config file path from command line args or use default
    let args: Vec<String> = env::args().collect();
    let config_path = if args.len() > 1 {
        &args[1]
    } else {
        "config.toml"
    };

    // Try to load config file, fall back to defaults if not found
    let (config, config_loaded) = match Config::from_file(config_path) {
        Ok(cfg) => (cfg, true),
        Err(e) => {
            eprintln!("Could not load {} ({}), using defaults", config_path, e);
            (Config::default_config(), false)
        }
    };

    // Initialize logger with log level from config
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(&config.server.log_level),
    )
    .init();

    if config_loaded {
        log::info!("Loaded configuration from {}", config_path);
    } else {
        log::info!("Using default configuration");
    }

    // Print applied configuration
    config.display();

    let addr = config.listen_addr();
    log::info!("Starting DNS server on {}", addr);

    let server = DnsServer::new(&addr, config).await?;

    // Start config file watcher only if a config file was successfully loaded
    let reload_rx = if config_loaded {
        match reload::watch_config_file(config_path.to_string()) {
            Ok(rx) => {
                log::info!("Config hot-reload enabled for: {}", config_path);
                Some(rx)
            }
            Err(e) => {
                log::warn!("Failed to setup config watcher: {}", e);
                log::warn!("Continuing without hot-reload support");
                None
            }
        }
    } else {
        log::info!("Config hot-reload disabled (no config file loaded)");
        None
    };

    // Spawn reload handler
    if let Some(mut rx) = reload_rx {
        let records = server.get_records();
        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                match msg {
                    reload::ReloadMessage::ConfigChanged(new_config) => {
                        if let Err(e) = reload::apply_config_update(&new_config, &records).await {
                            log::error!("Failed to apply config update: {}", e);
                        }
                    }
                }
            }
        });
    }

    server.run().await?;
    Ok(())
}
