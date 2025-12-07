use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::net::Ipv4Addr;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub server: ServerConfig,
    pub cache: CacheConfig,
    pub stats: StatsConfig,
    pub dns: DnsConfig,
    #[serde(default)]
    pub records: HashMap<String, String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub listen_address: String,
    pub listen_port: u16,
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

fn default_log_level() -> String {
    "warn".to_string()
}

#[derive(Debug, Deserialize, Clone)]
pub struct CacheConfig {
    pub max_entries: usize,
    pub cleanup_interval: u64,
    pub default_ttl: u32,
}

#[derive(Debug, Deserialize, Clone)]
pub struct StatsConfig {
    pub file_path: String,
    pub update_interval: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DnsConfig {
    pub default_ttl: u32,
}

impl Config {
    pub fn from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = fs::read_to_string(path)?;
        let config: Config = toml::from_str(&contents)?;
        Ok(config)
    }

    pub fn default_config() -> Self {
        Config {
            server: ServerConfig {
                listen_address: "127.0.0.1".to_string(),
                listen_port: 9053,
                log_level: "warn".to_string(),
            },
            cache: CacheConfig {
                max_entries: 1000,
                cleanup_interval: 60,
                default_ttl: 300,
            },
            stats: StatsConfig {
                file_path: "dns_stats.txt".to_string(),
                update_interval: 60,
            },
            dns: DnsConfig { default_ttl: 300 },
            records: HashMap::new(),
        }
    }

    pub fn parse_records(&self) -> Result<HashMap<String, Ipv4Addr>, Box<dyn std::error::Error>> {
        let mut parsed_records = HashMap::new();
        for (domain, ip_str) in &self.records {
            let ip: Ipv4Addr = ip_str.parse()?;
            parsed_records.insert(domain.clone(), ip);
        }
        Ok(parsed_records)
    }

    pub fn listen_addr(&self) -> String {
        format!("{}:{}", self.server.listen_address, self.server.listen_port)
    }

    /// Display configuration in a formatted table
    pub fn display(&self) {
        let records_count = self.records.len();

        log::info!("\n═══════════════════════════════════════════════════");
        log::info!("           DNS Server Configuration");
        log::info!("═══════════════════════════════════════════════════");
        log::info!("Server:");
        log::info!("  Listen Address:      {}", self.server.listen_address);
        log::info!("  Listen Port:         {}", self.server.listen_port);
        log::info!("");
        log::info!("Cache:");
        log::info!("  Max Entries:         {}", self.cache.max_entries);
        log::info!("  Cleanup Interval:    {}s", self.cache.cleanup_interval);
        log::info!("  Default TTL:         {}s", self.cache.default_ttl);
        log::info!("");
        log::info!("Statistics:");
        log::info!("  File Path:           {}", self.stats.file_path);
        log::info!("  Update Interval:     {}s", self.stats.update_interval);
        log::info!("");
        log::info!("DNS:");
        log::info!("  Default TTL:         {}s", self.dns.default_ttl);
        log::info!("");
        log::info!("Static Records:        {}", records_count);
        for (domain, ip) in &self.records {
            log::info!("  {} -> {}", domain, ip);
        }
        log::info!("═══════════════════════════════════════════════════\n");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default_config();
        assert_eq!(config.server.listen_address, "127.0.0.1");
        assert_eq!(config.server.listen_port, 9053);
        assert_eq!(config.cache.max_entries, 1000);
        assert_eq!(config.cache.cleanup_interval, 60);
        assert_eq!(config.cache.default_ttl, 300);
        assert_eq!(config.dns.default_ttl, 300);
        assert_eq!(config.records.len(), 0);
    }

    #[test]
    fn test_listen_addr() {
        let config = Config::default_config();
        assert_eq!(config.listen_addr(), "127.0.0.1:9053");
    }

    #[test]
    fn test_parse_records_valid() {
        let mut config = Config::default_config();
        config
            .records
            .insert("example.com".to_string(), "1.2.3.4".to_string());
        config
            .records
            .insert("test.com".to_string(), "5.6.7.8".to_string());

        let parsed = config.parse_records().unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed.get("example.com"), Some(&Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(parsed.get("test.com"), Some(&Ipv4Addr::new(5, 6, 7, 8)));
    }

    #[test]
    fn test_parse_records_invalid_ip() {
        let mut config = Config::default_config();
        config
            .records
            .insert("example.com".to_string(), "invalid".to_string());

        assert!(config.parse_records().is_err());
    }

    #[test]
    fn test_parse_records_empty() {
        let config = Config::default_config();
        let parsed = config.parse_records().unwrap();
        assert_eq!(parsed.len(), 0);
    }

    #[test]
    fn test_cache_default_ttl() {
        let mut config = Config::default_config();

        // Test default value
        assert_eq!(config.cache.default_ttl, 300);

        // Test setting custom value
        config.cache.default_ttl = 600;
        assert_eq!(config.cache.default_ttl, 600);

        // Test another value
        config.cache.default_ttl = 60;
        assert_eq!(config.cache.default_ttl, 60);
    }
}
