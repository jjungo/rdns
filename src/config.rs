use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::net::Ipv4Addr;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub server: ServerConfig,
    pub cache: CacheConfig,
    pub stats: StatsConfig,
    #[allow(dead_code)]
    pub dns: DnsConfig,
    #[serde(default)]
    pub records: HashMap<String, String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub listen_address: String,
    pub listen_port: u16,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CacheConfig {
    pub max_entries: usize,
    pub cleanup_interval: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct StatsConfig {
    pub file_path: String,
    pub update_interval: u64,
}

#[allow(dead_code)]
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

    pub fn default() -> Self {
        Config {
            server: ServerConfig {
                listen_address: "127.0.0.1".to_string(),
                listen_port: 9053,
            },
            cache: CacheConfig {
                max_entries: 1000,
                cleanup_interval: 60,
            },
            stats: StatsConfig {
                file_path: "dns_stats.txt".to_string(),
                update_interval: 60,
            },
            dns: DnsConfig {
                default_ttl: 300,
            },
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
}
