mod dns;
mod server;
mod cache;
mod stats;
mod config;

use server::DnsServer;
use config::Config;
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
    let config = match Config::from_file(config_path) {
        Ok(cfg) => {
            println!("Loaded configuration from {}", config_path);
            cfg
        }
        Err(e) => {
            println!("Could not load {} ({}), using defaults", config_path, e);
            Config::default_config()
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
    server.run().await?;
    Ok(())
}
