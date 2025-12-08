use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use trust_dns_resolver::error::ResolveError;

/// A pool of DNS resolvers with fallback support
pub struct ResolverPool {
    resolvers: Vec<Arc<TokioAsyncResolver>>,
}

impl ResolverPool {
    /// Create a new resolver pool from a list of upstream server addresses
    ///
    /// # Arguments
    /// * `upstream_servers` - List of DNS server addresses in format "ip:port" or "ip" (defaults to port 53)
    ///
    /// # Returns
    /// * `Ok(ResolverPool)` - Successfully created pool
    /// * `Err(String)` - If no valid resolvers could be created
    pub fn new(upstream_servers: Vec<String>) -> Result<Self, String> {
        if upstream_servers.is_empty() {
            // Use system DNS configuration
            log::info!("No upstream servers configured, using system DNS");
            let resolver =
                TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
            return Ok(ResolverPool {
                resolvers: vec![Arc::new(resolver)],
            });
        }

        let mut resolvers = Vec::new();

        for server_str in &upstream_servers {
            match Self::parse_nameserver(server_str) {
                Ok(nameserver_config) => {
                    let mut resolver_config = ResolverConfig::new();
                    resolver_config.add_name_server(nameserver_config.clone());

                    let resolver =
                        TokioAsyncResolver::tokio(resolver_config, ResolverOpts::default());

                    resolvers.push(Arc::new(resolver));
                    log::info!("Added upstream DNS server: {}", server_str);
                }
                Err(e) => {
                    log::warn!("Failed to parse upstream server '{}': {}", server_str, e);
                }
            }
        }

        if resolvers.is_empty() {
            return Err(format!(
                "No valid upstream servers could be configured from: {:?}",
                upstream_servers
            ));
        }

        log::info!(
            "Resolver pool initialized with {} upstream server(s)",
            resolvers.len()
        );
        Ok(ResolverPool { resolvers })
    }

    /// Parse a nameserver string in format "ip:port" or "ip" (defaults to port 53)
    fn parse_nameserver(server_str: &str) -> Result<NameServerConfig, String> {
        // Try parsing as "ip:port"
        if let Ok(socket_addr) = SocketAddr::from_str(server_str) {
            return Ok(NameServerConfig {
                socket_addr,
                protocol: Protocol::Udp,
                tls_dns_name: None,
                trust_negative_responses: false,
                bind_addr: None,
            });
        }

        // Try parsing as just "ip" (default to port 53)
        if let Ok(ip_addr) = IpAddr::from_str(server_str) {
            let socket_addr = SocketAddr::new(ip_addr, 53);
            return Ok(NameServerConfig {
                socket_addr,
                protocol: Protocol::Udp,
                tls_dns_name: None,
                trust_negative_responses: false,
                bind_addr: None,
            });
        }

        Err(format!("Invalid DNS server address: {}", server_str))
    }

    /// Lookup a domain with automatic fallback to next resolver on failure
    ///
    /// Tries each resolver in order until one succeeds or all fail
    pub async fn lookup<R>(
        &self,
        domain: &str,
        record_type: trust_dns_resolver::proto::rr::RecordType,
    ) -> Result<R, ResolveError>
    where
        R: From<trust_dns_resolver::lookup::Lookup>,
    {
        let mut last_error = None;

        for (i, resolver) in self.resolvers.iter().enumerate() {
            log::debug!(
                "Trying upstream server #{} for {} ({:?})",
                i + 1,
                domain,
                record_type
            );

            match resolver.lookup(domain, record_type).await {
                Ok(lookup) => {
                    if i > 0 {
                        log::debug!(
                            "Upstream server #{} succeeded for {} after {} failure(s)",
                            i + 1,
                            domain,
                            i
                        );
                    }
                    return Ok(R::from(lookup));
                }
                Err(e) => {
                    log::debug!("Upstream server #{} failed for {}: {}", i + 1, domain, e);
                    last_error = Some(e);
                }
            }
        }

        // All resolvers failed, return the last error
        Err(last_error.unwrap_or_else(|| {
            ResolveError::from(
                trust_dns_resolver::error::ResolveErrorKind::NoRecordsFound {
                    query: Box::new(trust_dns_resolver::proto::op::Query::default()),
                    soa: None,
                    negative_ttl: None,
                    response_code: trust_dns_resolver::proto::op::ResponseCode::ServFail,
                    trusted: false,
                },
            )
        }))
    }

    /// Lookup IP addresses (supports both A and AAAA records)
    #[allow(dead_code)]
    pub async fn lookup_ip(
        &self,
        domain: &str,
    ) -> Result<trust_dns_resolver::lookup_ip::LookupIp, ResolveError> {
        let mut last_error = None;

        for (i, resolver) in self.resolvers.iter().enumerate() {
            log::debug!(
                "Trying upstream server #{} for {} (IP lookup)",
                i + 1,
                domain
            );

            match resolver.lookup_ip(domain).await {
                Ok(lookup) => {
                    if i > 0 {
                        log::debug!(
                            "Upstream server #{} succeeded for {} after {} failure(s)",
                            i + 1,
                            domain,
                            i
                        );
                    }
                    return Ok(lookup);
                }
                Err(e) => {
                    log::debug!("Upstream server #{} failed for {}: {}", i + 1, domain, e);
                    last_error = Some(e);
                }
            }
        }

        // All resolvers failed
        Err(last_error.unwrap_or_else(|| {
            ResolveError::from(
                trust_dns_resolver::error::ResolveErrorKind::NoRecordsFound {
                    query: Box::new(trust_dns_resolver::proto::op::Query::default()),
                    soa: None,
                    negative_ttl: None,
                    response_code: trust_dns_resolver::proto::op::ResponseCode::ServFail,
                    trusted: false,
                },
            )
        }))
    }

    /// Get the number of configured resolvers
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.resolvers.len()
    }

    /// Check if the pool is empty
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.resolvers.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_nameserver_with_port() {
        let config = ResolverPool::parse_nameserver("8.8.8.8:53").unwrap();
        assert_eq!(config.socket_addr.ip().to_string(), "8.8.8.8");
        assert_eq!(config.socket_addr.port(), 53);
        assert_eq!(config.protocol, Protocol::Udp);
    }

    #[test]
    fn test_parse_nameserver_without_port() {
        let config = ResolverPool::parse_nameserver("1.1.1.1").unwrap();
        assert_eq!(config.socket_addr.ip().to_string(), "1.1.1.1");
        assert_eq!(config.socket_addr.port(), 53); // Default port
        assert_eq!(config.protocol, Protocol::Udp);
    }

    #[test]
    fn test_parse_nameserver_ipv6_with_port() {
        let config = ResolverPool::parse_nameserver("[2001:4860:4860::8888]:53").unwrap();
        assert_eq!(config.socket_addr.ip().to_string(), "2001:4860:4860::8888");
        assert_eq!(config.socket_addr.port(), 53);
    }

    #[test]
    fn test_parse_nameserver_ipv6_without_port() {
        let config = ResolverPool::parse_nameserver("2001:4860:4860::8888").unwrap();
        assert_eq!(config.socket_addr.ip().to_string(), "2001:4860:4860::8888");
        assert_eq!(config.socket_addr.port(), 53);
    }

    #[test]
    fn test_parse_nameserver_invalid() {
        assert!(ResolverPool::parse_nameserver("invalid").is_err());
        assert!(ResolverPool::parse_nameserver("").is_err());
        assert!(ResolverPool::parse_nameserver("999.999.999.999").is_err());
    }

    #[test]
    fn test_empty_upstream_servers() {
        // Should use system DNS
        let pool = ResolverPool::new(vec![]).unwrap();
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn test_multiple_upstream_servers() {
        let pool =
            ResolverPool::new(vec!["8.8.8.8".to_string(), "1.1.1.1:53".to_string()]).unwrap();
        assert_eq!(pool.len(), 2);
    }

    #[test]
    fn test_all_invalid_servers_fails() {
        let result = ResolverPool::new(vec!["invalid1".to_string(), "invalid2".to_string()]);
        assert!(result.is_err());
    }

    #[test]
    fn test_mixed_valid_invalid_servers() {
        let pool = ResolverPool::new(vec![
            "8.8.8.8".to_string(),
            "invalid".to_string(),
            "1.1.1.1".to_string(),
        ])
        .unwrap();
        // Should have 2 valid resolvers
        assert_eq!(pool.len(), 2);
    }
}
