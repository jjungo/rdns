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
        Ok(cfg) => {
            println!("Loaded configuration from {}", config_path);
            (cfg, true)
        }
        Err(e) => {
            println!("Could not load {} ({}), using defaults", config_path, e);
            (Config::default_config(), false)
        }
    };

    // Print applied configuration
    println!("\n═══════════════════════════════════════════════════");
    println!("           DNS Server Configuration");
    println!("═══════════════════════════════════════════════════");
    println!("Server:");
    println!("  Listen Address:      {}", config.server.listen_address);
    println!("  Listen Port:         {}", config.server.listen_port);
    println!();
    println!("Cache:");
    println!("  Max Entries:         {}", config.cache.max_entries);
    println!("  Cleanup Interval:    {}s", config.cache.cleanup_interval);
    println!();
    println!("Statistics:");
    println!("  File Path:           {}", config.stats.file_path);
    println!("  Update Interval:     {}s", config.stats.update_interval);
    println!();
    println!("DNS:");
    println!("  Default TTL:         {}s", config.dns.default_ttl);
    println!();
    println!("Static Records:        {}", config.records.len());
    for (domain, ip) in &config.records {
        println!("  {} -> {}", domain, ip);
    }
    println!("═══════════════════════════════════════════════════\n");

    let addr = config.listen_addr();
    println!("Starting DNS server on {}", addr);

    let server = DnsServer::new(&addr, config).await?;

    // Start config file watcher only if a config file was successfully loaded
    let reload_rx = if config_loaded {
        match reload::watch_config_file(config_path.to_string()) {
            Ok(rx) => {
                println!("Config hot-reload enabled for: {}\n", config_path);
                Some(rx)
            }
            Err(e) => {
                eprintln!("Warning: Failed to setup config watcher: {}", e);
                eprintln!("Continuing without hot-reload support\n");
                None
            }
        }
    } else {
        println!("Config hot-reload disabled (no config file loaded)\n");
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
                            eprintln!("Failed to apply config update: {}", e);
                        }
                    }
                }
            }
        });
    }

    server.run().await?;
    Ok(())
}
