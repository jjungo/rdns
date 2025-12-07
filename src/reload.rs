use crate::config::Config;
use notify::{Config as NotifyConfig, Event, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::mpsc;

pub enum ReloadMessage {
    ConfigChanged(Config),
}

/// Starts watching a configuration file for changes
/// Returns a channel receiver that will receive reload messages
pub fn watch_config_file(
    config_path: String,
) -> Result<mpsc::Receiver<ReloadMessage>, Box<dyn std::error::Error>> {
    let (tx, rx) = mpsc::channel(10);

    let config_path_clone = config_path.clone();

    std::thread::spawn(move || {
        if let Err(e) = run_file_watcher(&config_path_clone, tx) {
            log::error!("Config file watcher error: {}", e);
        }
    });

    Ok(rx)
}

fn run_file_watcher(
    config_path: &str,
    tx: mpsc::Sender<ReloadMessage>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (notify_tx, notify_rx) = std::sync::mpsc::channel();

    let mut watcher = RecommendedWatcher::new(notify_tx, NotifyConfig::default())?;

    // Convert to absolute path so it matches the event paths
    let path = std::fs::canonicalize(Path::new(config_path))?;

    // Watch the config file
    watcher.watch(&path, RecursiveMode::NonRecursive)?;

    log::info!("Watching config file for changes: {}", config_path);
    log::info!("File watcher initialized successfully");

    // Keep watcher alive by moving it into the loop
    let _watcher = watcher;

    loop {
        match notify_rx.recv() {
            Ok(Ok(Event { kind, paths, .. })) => {
                // Check if the event is a data modification event and affects our config file
                if matches!(
                    kind,
                    notify::EventKind::Modify(notify::event::ModifyKind::Data(_))
                ) && paths.iter().any(|p| p == &path)
                {
                    println!(
                        "\n[CONFIG RELOAD] File modification detected: {}",
                        config_path
                    );
                    log::debug!("[CONFIG RELOAD] Event type: {:?}", kind);

                    match load_and_validate_config(config_path) {
                        Ok(new_config) => {
                            println!(
                                "[CONFIG RELOAD] Validation successful, applying new configuration..."
                            );
                            if let Err(e) =
                                tx.blocking_send(ReloadMessage::ConfigChanged(new_config))
                            {
                                eprintln!(
                                    "[CONFIG RELOAD ERROR] Failed to send reload message: {}",
                                    e
                                );
                                break;
                            }
                        }
                        Err(e) => {
                            eprintln!(
                                "[CONFIG RELOAD ERROR] Failed to reload config (keeping old config): {}",
                                e
                            );
                        }
                    }
                }
            }
            Ok(Err(e)) => {
                log::error!("Watch error: {}", e);
            }
            Err(e) => {
                log::error!("Channel receive error: {}", e);
                break;
            }
        }
    }

    Ok(())
}

/// Loads and validates a configuration file
fn load_and_validate_config(path: &str) -> Result<Config, Box<dyn std::error::Error>> {
    let config = Config::from_file(path)?;

    // Validate the configuration
    validate_config(&config)?;

    Ok(config)
}

/// Validates a configuration to ensure it's valid before applying
fn validate_config(config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    log::debug!("[CONFIG RELOAD] Validating configuration...");

    // Validate listen port
    if config.server.listen_port == 0 {
        return Err("Listen port cannot be 0".into());
    }

    // Validate cache settings
    if config.cache.max_entries == 0 {
        return Err("Cache max_entries must be greater than 0".into());
    }

    if config.cache.cleanup_interval == 0 {
        return Err("Cache cleanup_interval must be greater than 0".into());
    }

    // Validate stats settings
    if config.stats.update_interval == 0 {
        return Err("Stats update_interval must be greater than 0".into());
    }

    // Validate DNS records
    let records = config.parse_records()?;
    println!(
        "[CONFIG RELOAD] Found {} valid DNS record(s)",
        records.len()
    );

    Ok(())
}

/// Applies a new configuration to running server components
pub async fn apply_config_update(
    new_config: &Config,
    records: &Arc<tokio::sync::RwLock<std::collections::HashMap<String, std::net::Ipv4Addr>>>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Parse and update DNS records
    let new_records = new_config.parse_records()?;

    let mut records_guard = records.write().await;
    records_guard.clear();
    records_guard.extend(new_records.clone());
    drop(records_guard);

    println!("\n[CONFIG RELOAD] Configuration Reloaded Successfully!");
    new_config.display();

    Ok(())
}
