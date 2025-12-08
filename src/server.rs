use crate::cache::DnsCache;
use crate::config::Config;
use crate::dns::{DnsAnswer, DnsPacket, QTYPE_HTTPS, QueryType, RCODE_SERVER_FAILURE};
use crate::handler::*;
use crate::resolver_pool::ResolverPool;
use crate::stats::DnsStats;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

pub struct DnsServer {
    records: Arc<RwLock<HashMap<String, Ipv4Addr>>>,
    cache: Arc<RwLock<DnsCache>>,
    socket: Arc<UdpSocket>,
    resolver_pool: Arc<ResolverPool>,
    stats: Arc<DnsStats>,
    config: Config,
}

impl DnsServer {
    pub async fn new(addr: &str, config: Config) -> Result<Self, Box<dyn std::error::Error>> {
        let socket = UdpSocket::bind(addr).await?;
        log::info!("DNS Server listening on {}", addr);

        // Parse records from config
        let records = config.parse_records()?;

        // Create cache with configured limit and TTL
        let cache = DnsCache::new(config.cache.max_entries, config.cache.default_ttl);

        // Create resolver pool with configured upstream servers
        let resolver_pool = ResolverPool::new(config.server.upstream_servers.clone())
            .map_err(|e| format!("Failed to create resolver pool: {}", e))?;

        Ok(DnsServer {
            records: Arc::new(RwLock::new(records)),
            cache: Arc::new(RwLock::new(cache)),
            socket: Arc::new(socket),
            resolver_pool: Arc::new(resolver_pool),
            stats: Arc::new(DnsStats::new()),
            config,
        })
    }

    #[allow(dead_code)]
    pub async fn add_record(&self, domain: String, ip: Ipv4Addr) {
        let mut records = self.records.write().await;
        records.insert(domain, ip);
    }

    /// Get a reference to the records map for hot-reloading
    pub fn get_records(&self) -> Arc<RwLock<HashMap<String, Ipv4Addr>>> {
        self.records.clone()
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Spawn background task for cache cleanup
        let cache_for_cleanup = self.cache.clone();
        let cleanup_interval = self.config.cache.cleanup_interval;
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(tokio::time::Duration::from_secs(cleanup_interval));
            loop {
                interval.tick().await;
                let mut cache = cache_for_cleanup.write().await;
                let before = cache.len();
                cache.cleanup_expired();
                let after = cache.len();
                if before != after {
                    log::debug!(
                        "Cache cleanup: removed {} expired entries ({} -> {})",
                        before - after,
                        before,
                        after
                    );
                }
            }
        });

        // Spawn background task for periodic stats
        let stats_for_display = self.stats.clone();
        let cache_for_stats = self.cache.clone();
        let stats_interval = self.config.stats.update_interval;
        let stats_file = self.config.stats.file_path.clone();
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(tokio::time::Duration::from_secs(stats_interval));
            loop {
                interval.tick().await;
                let cache_size = cache_for_stats.read().await.len();
                if let Err(e) = stats_for_display.write_stats_to_file(&stats_file, cache_size) {
                    log::error!("Failed to write stats to file: {}", e);
                }
            }
        });

        let mut buf = vec![0u8; 512];

        loop {
            let (len, src) = self.socket.recv_from(&mut buf).await?;
            let request_data = buf[..len].to_vec();

            let records = self.records.clone();
            let cache = self.cache.clone();
            let socket = self.socket.clone();
            let resolver_pool = self.resolver_pool.clone();
            let stats = self.stats.clone();

            tokio::spawn(async move {
                let start = Instant::now();
                if let Err(e) = handle_query(
                    request_data,
                    src,
                    socket,
                    records,
                    cache,
                    resolver_pool,
                    stats.clone(),
                )
                .await
                {
                    log::error!("Error handling query from {}: {}", src, e);
                }
                stats.record_response_time(start.elapsed());
            });
        }
    }
}

async fn handle_query(
    data: Vec<u8>,
    src: SocketAddr,
    socket: Arc<UdpSocket>,
    records: Arc<RwLock<HashMap<String, Ipv4Addr>>>,
    cache: Arc<RwLock<DnsCache>>,
    resolver_pool: Arc<ResolverPool>,
    stats: Arc<DnsStats>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut packet = DnsPacket::from_bytes(&data)?;

    log::debug!("Received query from {}", src);

    if packet.questions.is_empty() {
        return Ok(());
    }

    // Set response flags
    packet.header.set_response();
    packet.header.set_recursion_available();

    // Create query handler
    let handler = QueryHandler::new(&cache, &resolver_pool, &stats);

    let questions = packet.questions.clone();
    for question in &questions {
        // Record query by type
        stats.record_query(u16::from(question.qtype));

        log::debug!("  Question: {} (type: {:?})", question.name, question.qtype);

        match question.qtype {
            QueryType::A => {
                handle_a_query_with_local(&question.name, &records, &handler, &mut packet).await;
            }
            QueryType::AAAA => {
                handler
                    .handle::<AAAARecord>(&question.name, &mut packet)
                    .await;
            }
            QueryType::NS => {
                handler
                    .handle::<NSRecord>(&question.name, &mut packet)
                    .await;
            }
            QueryType::SOA => {
                handler
                    .handle::<SOARecord>(&question.name, &mut packet)
                    .await;
            }
            QueryType::MX => {
                handler
                    .handle::<MXRecord>(&question.name, &mut packet)
                    .await;
            }
            QueryType::CNAME => {
                handler
                    .handle::<CNAMERecord>(&question.name, &mut packet)
                    .await;
            }
            QueryType::PTR => {
                handler
                    .handle::<PTRRecord>(&question.name, &mut packet)
                    .await;
            }
            QueryType::TXT => {
                handler
                    .handle::<TXTRecord>(&question.name, &mut packet)
                    .await;
            }
            QueryType::HTTPS => {
                handle_generic_query(
                    &question.name,
                    QTYPE_HTTPS,
                    "HTTPS",
                    &resolver_pool,
                    &stats,
                    &mut packet,
                )
                .await;
            }
            QueryType::Unknown(qtype) => {
                handle_generic_query(
                    &question.name,
                    qtype,
                    &format!("TYPE{}", qtype),
                    &resolver_pool,
                    &stats,
                    &mut packet,
                )
                .await;
            }
        }
    }

    let response = packet.to_bytes();
    socket.send_to(&response, src).await?;

    Ok(())
}

/// Special handler for A records that checks local records first
async fn handle_a_query_with_local(
    domain: &str,
    records: &Arc<RwLock<HashMap<String, Ipv4Addr>>>,
    handler: &QueryHandler<'_>,
    packet: &mut DnsPacket,
) {
    // First check local static records
    let records_guard = records.read().await;
    if let Some(&ip) = records_guard.get(domain) {
        handler.stats.record_cache_hit(); // Treat local records as cache hit
        log::debug!("  Answer (local): {} -> {}", domain, ip);
        let answer = DnsAnswer::new_a_record(domain.to_string(), 300, ip);
        packet.answers.push(answer);
        packet.header.answers += 1;
        return;
    }
    drop(records_guard);

    // Otherwise use generic handler
    handler.handle::<ARecord>(domain, packet).await;
}

/// Generic handler for any query type - forwards raw DNS records from upstream
async fn handle_generic_query(
    domain: &str,
    qtype: u16,
    qtype_name: &str,
    resolver_pool: &Arc<ResolverPool>,
    stats: &Arc<DnsStats>,
    packet: &mut DnsPacket,
) {
    use trust_dns_resolver::proto::rr::RecordType;
    use trust_dns_resolver::proto::serialize::binary::{BinEncodable, BinEncoder};

    // Record cache miss and upstream query
    stats.record_cache_miss();
    stats.record_upstream_query();

    // Convert qtype to RecordType
    let record_type = RecordType::from(qtype);

    // Forward to upstream
    log::debug!(
        "  Forwarding to upstream DNS for {} ({})",
        domain,
        qtype_name
    );
    match with_timeout(
        resolver_pool.lookup::<trust_dns_resolver::lookup::Lookup>(domain, record_type),
        domain,
        qtype_name,
    )
    .await
    {
        Ok(lookup) => {
            for record in lookup.record_iter() {
                if let Some(rdata) = record.data() {
                    // Serialize the raw record data
                    let mut data = Vec::new();
                    let mut encoder = BinEncoder::new(&mut data);
                    if let Ok(()) = rdata.emit(&mut encoder) {
                        let ttl = record.ttl();
                        log::debug!(
                            "  Answer (upstream): {} {} -> <{} bytes> (TTL: {}s)",
                            domain,
                            qtype_name,
                            data.len(),
                            ttl
                        );

                        // Create answer with raw data
                        let answer = crate::dns::DnsAnswer {
                            name: domain.to_string(),
                            qtype: QueryType::from(qtype),
                            qclass: 1,
                            ttl,
                            data,
                        };
                        packet.answers.push(answer);
                        packet.header.answers += 1;
                    }
                }
            }
        }
        Err(e) => {
            log::warn!("  Upstream resolution failed for {}: {}", domain, e);
            packet.header.set_rcode(RCODE_SERVER_FAILURE);
            stats.record_unresolved();
        }
    }
}
