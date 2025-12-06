use crate::cache::{CacheEntry, DnsCache, RecordData};
use crate::config::Config;
use crate::dns::{
    DnsAnswer, DnsPacket, QTYPE_A, QTYPE_AAAA, QTYPE_CNAME, QTYPE_MX, QTYPE_NS, QTYPE_PTR,
    QTYPE_SOA, QTYPE_TXT, QueryType, RCODE_SERVER_FAILURE,
};
use crate::stats::DnsStats;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::config::*;

// Timeout for upstream DNS queries
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(5);

pub struct DnsServer {
    records: Arc<RwLock<HashMap<String, Ipv4Addr>>>,
    cache: Arc<RwLock<DnsCache>>,
    socket: Arc<UdpSocket>,
    resolver: Arc<TokioAsyncResolver>,
    stats: Arc<DnsStats>,
    config: Config,
}

impl DnsServer {
    pub async fn new(addr: &str, config: Config) -> Result<Self, Box<dyn std::error::Error>> {
        let socket = UdpSocket::bind(addr).await?;
        println!("DNS Server listening on {}", addr);

        // Parse records from config
        let records = config.parse_records()?;

        // Create cache with configured limit
        let cache = DnsCache::new(config.cache.max_entries);

        // Create resolver with system configuration
        let resolver =
            TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

        Ok(DnsServer {
            records: Arc::new(RwLock::new(records)),
            cache: Arc::new(RwLock::new(cache)),
            socket: Arc::new(socket),
            resolver: Arc::new(resolver),
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
                    println!(
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
                    eprintln!("Failed to write stats to file: {}", e);
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
            let resolver = self.resolver.clone();
            let stats = self.stats.clone();

            tokio::spawn(async move {
                let start = Instant::now();
                if let Err(e) = handle_query(
                    request_data,
                    src,
                    socket,
                    records,
                    cache,
                    resolver,
                    stats.clone(),
                )
                .await
                {
                    eprintln!("Error handling query from {}: {}", src, e);
                }
                stats.record_response_time(start.elapsed());
            });
        }
    }
}

/// Helper function to check cache for a given domain and query type
async fn check_cache(
    domain: &str,
    qtype: u16,
    cache: &Arc<RwLock<DnsCache>>,
    stats: &Arc<DnsStats>,
) -> Option<Vec<CacheEntry>> {
    let mut cache_guard = cache.write().await;
    if let Some(cached_entries) = cache_guard.get(domain, qtype) {
        stats.record_cache_hit();
        return Some(cached_entries);
    }
    drop(cache_guard);
    stats.record_cache_miss();
    stats.record_upstream_query();
    None
}

/// Helper function to insert entries into cache
async fn insert_cache(
    domain: String,
    qtype: u16,
    entries: Vec<CacheEntry>,
    cache: &Arc<RwLock<DnsCache>>,
) {
    if !entries.is_empty() {
        let mut cache_guard = cache.write().await;
        cache_guard.insert(domain, qtype, entries);
    }
}

/// Wraps an upstream DNS query with a timeout to prevent hanging
async fn with_timeout<F, T>(
    future: F,
    domain: &str,
    qtype: &str,
) -> Result<T, trust_dns_resolver::error::ResolveError>
where
    F: std::future::Future<Output = Result<T, trust_dns_resolver::error::ResolveError>>,
{
    match tokio::time::timeout(UPSTREAM_TIMEOUT, future).await {
        Ok(result) => result,
        Err(_) => {
            eprintln!("Upstream DNS timeout for {} ({})", domain, qtype);
            Err(trust_dns_resolver::error::ResolveError::from(
                trust_dns_resolver::error::ResolveErrorKind::Timeout,
            ))
        }
    }
}

async fn handle_query(
    data: Vec<u8>,
    src: SocketAddr,
    socket: Arc<UdpSocket>,
    records: Arc<RwLock<HashMap<String, Ipv4Addr>>>,
    cache: Arc<RwLock<DnsCache>>,
    resolver: Arc<TokioAsyncResolver>,
    stats: Arc<DnsStats>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut packet = DnsPacket::from_bytes(&data)?;

    println!("Received query from {}", src);

    if packet.questions.is_empty() {
        return Ok(());
    }

    // Set response flags
    packet.header.set_response();
    packet.header.set_recursion_available();

    let questions = packet.questions.clone();
    for question in &questions {
        // Record query by type
        stats.record_query(u16::from(question.qtype));

        println!("  Question: {} (type: {:?})", question.name, question.qtype);

        match question.qtype {
            QueryType::A => {
                handle_a_query(
                    &question.name,
                    &records,
                    &cache,
                    &resolver,
                    &stats,
                    &mut packet,
                )
                .await;
            }
            QueryType::AAAA => {
                handle_aaaa_query(&question.name, &cache, &resolver, &stats, &mut packet).await;
            }
            QueryType::NS => {
                handle_ns_query(&question.name, &cache, &resolver, &stats, &mut packet).await;
            }
            QueryType::SOA => {
                handle_soa_query(&question.name, &cache, &resolver, &stats, &mut packet).await;
            }
            QueryType::MX => {
                handle_mx_query(&question.name, &cache, &resolver, &stats, &mut packet).await;
            }
            QueryType::CNAME => {
                handle_cname_query(&question.name, &cache, &resolver, &stats, &mut packet).await;
            }
            QueryType::PTR => {
                handle_ptr_query(&question.name, &cache, &resolver, &stats, &mut packet).await;
            }
            QueryType::TXT => {
                handle_txt_query(&question.name, &cache, &resolver, &stats, &mut packet).await;
            }
            _ => {
                println!("  Query type {:?} not supported", question.qtype);
            }
        }
    }

    let response = packet.to_bytes();
    socket.send_to(&response, src).await?;

    Ok(())
}

async fn handle_a_query(
    domain: &str,
    records: &Arc<RwLock<HashMap<String, Ipv4Addr>>>,
    cache: &Arc<RwLock<DnsCache>>,
    resolver: &Arc<TokioAsyncResolver>,
    stats: &Arc<DnsStats>,
    packet: &mut DnsPacket,
) {
    // First check local static records
    let records_guard = records.read().await;
    if let Some(&ip) = records_guard.get(domain) {
        stats.record_cache_hit(); // Treat local records as cache hit
        println!("  Answer (local): {} -> {}", domain, ip);
        let answer = DnsAnswer::new_a_record(domain.to_string(), 300, ip);
        packet.answers.push(answer);
        packet.header.answers += 1;
        return;
    }
    drop(records_guard);

    // Check cache
    if let Some(cached_entries) = check_cache(domain, QTYPE_A, cache, stats).await {
        for entry in cached_entries {
            if let RecordData::A(ip) = entry.data {
                let ttl = entry.remaining_ttl();
                println!("  Answer (cache): {} -> {} (TTL: {}s)", domain, ip, ttl);
                let answer = DnsAnswer::new_a_record(domain.to_string(), ttl, ip);
                packet.answers.push(answer);
                packet.header.answers += 1;
            }
        }
        return;
    }

    // Forward to upstream DNS server
    println!("  Forwarding to upstream DNS for {} (A)", domain);
    match with_timeout(resolver.lookup_ip(domain), domain, "A").await {
        Ok(lookup) => {
            let ttl = 300u32;
            let mut cache_entries = Vec::new();

            for ip in lookup.iter() {
                if let std::net::IpAddr::V4(ipv4) = ip {
                    println!(
                        "  Answer (upstream): {} -> {} (TTL: {}s)",
                        domain, ipv4, ttl
                    );

                    cache_entries.push(CacheEntry::new(RecordData::A(ipv4), ttl));

                    let answer = DnsAnswer::new_a_record(domain.to_string(), ttl, ipv4);
                    packet.answers.push(answer);
                    packet.header.answers += 1;
                }
            }

            // Cache the results
            insert_cache(domain.to_string(), QTYPE_A, cache_entries, cache).await;
        }
        Err(e) => {
            println!("  Upstream resolution failed for {}: {}", domain, e);
            packet.header.set_rcode(RCODE_SERVER_FAILURE);
        }
    }
}

async fn handle_aaaa_query(
    domain: &str,
    cache: &Arc<RwLock<DnsCache>>,
    resolver: &Arc<TokioAsyncResolver>,
    stats: &Arc<DnsStats>,
    packet: &mut DnsPacket,
) {
    // Check cache
    if let Some(cached_entries) = check_cache(domain, QTYPE_AAAA, cache, stats).await {
        for entry in cached_entries {
            if let RecordData::AAAA(ip) = entry.data {
                let ttl = entry.remaining_ttl();
                println!("  Answer (cache): {} -> {} (TTL: {}s)", domain, ip, ttl);
                let answer = DnsAnswer::new_aaaa_record(domain.to_string(), ttl, ip);
                packet.answers.push(answer);
                packet.header.answers += 1;
            }
        }
        return;
    }

    // Forward to upstream
    println!("  Forwarding to upstream DNS for {} (AAAA)", domain);
    match with_timeout(resolver.lookup_ip(domain), domain, "AAAA").await {
        Ok(lookup) => {
            let ttl = 300u32;
            let mut cache_entries = Vec::new();

            for ip in lookup.iter() {
                if let std::net::IpAddr::V6(ipv6) = ip {
                    println!(
                        "  Answer (upstream): {} -> {} (TTL: {}s)",
                        domain, ipv6, ttl
                    );

                    cache_entries.push(CacheEntry::new(RecordData::AAAA(ipv6), ttl));

                    let answer = DnsAnswer::new_aaaa_record(domain.to_string(), ttl, ipv6);
                    packet.answers.push(answer);
                    packet.header.answers += 1;
                }
            }

            insert_cache(domain.to_string(), QTYPE_AAAA, cache_entries, cache).await;
        }
        Err(e) => {
            println!("  Upstream resolution failed for {}: {}", domain, e);
            packet.header.set_rcode(RCODE_SERVER_FAILURE);
        }
    }
}

async fn handle_ns_query(
    domain: &str,
    cache: &Arc<RwLock<DnsCache>>,
    resolver: &Arc<TokioAsyncResolver>,
    stats: &Arc<DnsStats>,
    packet: &mut DnsPacket,
) {
    use trust_dns_resolver::proto::rr::RecordType;

    // Check cache
    if let Some(cached_entries) = check_cache(domain, QTYPE_NS, cache, stats).await {
        for entry in cached_entries {
            if let RecordData::NS(ref ns) = entry.data {
                let ttl = entry.remaining_ttl();
                println!("  Answer (cache): {} NS -> {} (TTL: {}s)", domain, ns, ttl);
                let answer = DnsAnswer::new_ns_record(domain.to_string(), ttl, ns.clone());
                packet.answers.push(answer);
                packet.header.answers += 1;
            }
        }
        return;
    }

    // Forward to upstream
    println!("  Forwarding to upstream DNS for {} (NS)", domain);
    match with_timeout(resolver.lookup(domain, RecordType::NS), domain, "NS").await {
        Ok(lookup) => {
            let ttl = 300u32;
            let mut cache_entries = Vec::new();

            for record in lookup.record_iter() {
                if let Some(ns_data) = record.data()
                    && let trust_dns_resolver::proto::rr::RData::NS(ns) = ns_data
                {
                    let ns_name = ns.to_string();
                    println!(
                        "  Answer (upstream): {} NS -> {} (TTL: {}s)",
                        domain, ns_name, ttl
                    );

                    cache_entries.push(CacheEntry::new(RecordData::NS(ns_name.clone()), ttl));

                    let answer = DnsAnswer::new_ns_record(domain.to_string(), ttl, ns_name);
                    packet.answers.push(answer);
                    packet.header.answers += 1;
                }
            }

            insert_cache(domain.to_string(), QTYPE_NS, cache_entries, cache).await;
        }
        Err(e) => {
            println!("  Upstream resolution failed for {}: {}", domain, e);
            packet.header.set_rcode(RCODE_SERVER_FAILURE);
        }
    }
}

async fn handle_mx_query(
    domain: &str,
    cache: &Arc<RwLock<DnsCache>>,
    resolver: &Arc<TokioAsyncResolver>,
    stats: &Arc<DnsStats>,
    packet: &mut DnsPacket,
) {
    use trust_dns_resolver::proto::rr::RecordType;

    // Check cache
    if let Some(cached_entries) = check_cache(domain, QTYPE_MX, cache, stats).await {
        for entry in cached_entries {
            if let RecordData::MX {
                priority,
                ref exchange,
            } = entry.data
            {
                let ttl = entry.remaining_ttl();
                println!(
                    "  Answer (cache): {} MX -> {} {} (TTL: {}s)",
                    domain, priority, exchange, ttl
                );
                let answer =
                    DnsAnswer::new_mx_record(domain.to_string(), ttl, priority, exchange.clone());
                packet.answers.push(answer);
                packet.header.answers += 1;
            }
        }
        return;
    }

    // Forward to upstream
    println!("  Forwarding to upstream DNS for {} (MX)", domain);
    match with_timeout(resolver.lookup(domain, RecordType::MX), domain, "MX").await {
        Ok(lookup) => {
            let ttl = 300u32;
            let mut cache_entries = Vec::new();

            for record in lookup.record_iter() {
                if let Some(mx_data) = record.data()
                    && let trust_dns_resolver::proto::rr::RData::MX(mx) = mx_data
                {
                    let priority = mx.preference();
                    let exchange = mx.exchange().to_string();
                    println!(
                        "  Answer (upstream): {} MX -> {} {} (TTL: {}s)",
                        domain, priority, exchange, ttl
                    );

                    cache_entries.push(CacheEntry::new(
                        RecordData::MX {
                            priority,
                            exchange: exchange.clone(),
                        },
                        ttl,
                    ));

                    let answer =
                        DnsAnswer::new_mx_record(domain.to_string(), ttl, priority, exchange);
                    packet.answers.push(answer);
                    packet.header.answers += 1;
                }
            }

            insert_cache(domain.to_string(), QTYPE_MX, cache_entries, cache).await;
        }
        Err(e) => {
            println!("  Upstream resolution failed for {}: {}", domain, e);
            packet.header.set_rcode(RCODE_SERVER_FAILURE);
        }
    }
}

async fn handle_cname_query(
    domain: &str,
    cache: &Arc<RwLock<DnsCache>>,
    resolver: &Arc<TokioAsyncResolver>,
    stats: &Arc<DnsStats>,
    packet: &mut DnsPacket,
) {
    use trust_dns_resolver::proto::rr::RecordType;

    // Check cache
    if let Some(cached_entries) = check_cache(domain, QTYPE_CNAME, cache, stats).await {
        for entry in cached_entries {
            if let RecordData::CNAME(ref cname) = entry.data {
                let ttl = entry.remaining_ttl();
                println!(
                    "  Answer (cache): {} CNAME -> {} (TTL: {}s)",
                    domain, cname, ttl
                );
                let answer = DnsAnswer::new_cname_record(domain.to_string(), ttl, cname.clone());
                packet.answers.push(answer);
                packet.header.answers += 1;
            }
        }
        return;
    }

    // Forward to upstream
    println!("  Forwarding to upstream DNS for {} (CNAME)", domain);
    match with_timeout(resolver.lookup(domain, RecordType::CNAME), domain, "CNAME").await {
        Ok(lookup) => {
            let ttl = 300u32;
            let mut cache_entries = Vec::new();

            for record in lookup.record_iter() {
                if let Some(cname_data) = record.data()
                    && let trust_dns_resolver::proto::rr::RData::CNAME(cname) = cname_data
                {
                    let cname_name = cname.to_string();
                    println!(
                        "  Answer (upstream): {} CNAME -> {} (TTL: {}s)",
                        domain, cname_name, ttl
                    );

                    cache_entries.push(CacheEntry::new(RecordData::CNAME(cname_name.clone()), ttl));

                    let answer = DnsAnswer::new_cname_record(domain.to_string(), ttl, cname_name);
                    packet.answers.push(answer);
                    packet.header.answers += 1;
                }
            }

            insert_cache(domain.to_string(), QTYPE_CNAME, cache_entries, cache).await;
        }
        Err(e) => {
            println!("  Upstream resolution failed for {}: {}", domain, e);
            packet.header.set_rcode(RCODE_SERVER_FAILURE);
        }
    }
}

async fn handle_ptr_query(
    domain: &str,
    cache: &Arc<RwLock<DnsCache>>,
    resolver: &Arc<TokioAsyncResolver>,
    stats: &Arc<DnsStats>,
    packet: &mut DnsPacket,
) {
    use trust_dns_resolver::proto::rr::RecordType;

    // Check cache
    if let Some(cached_entries) = check_cache(domain, QTYPE_PTR, cache, stats).await {
        for entry in cached_entries {
            if let RecordData::PTR(ref ptr) = entry.data {
                let ttl = entry.remaining_ttl();
                println!(
                    "  Answer (cache): {} PTR -> {} (TTL: {}s)",
                    domain, ptr, ttl
                );
                let answer = DnsAnswer::new_ptr_record(domain.to_string(), ttl, ptr.clone());
                packet.answers.push(answer);
                packet.header.answers += 1;
            }
        }
        return;
    }

    // Forward to upstream
    println!("  Forwarding to upstream DNS for {} (PTR)", domain);
    match with_timeout(resolver.lookup(domain, RecordType::PTR), domain, "PTR").await {
        Ok(lookup) => {
            let ttl = 300u32;
            let mut cache_entries = Vec::new();

            for record in lookup.record_iter() {
                if let Some(ptr_data) = record.data()
                    && let trust_dns_resolver::proto::rr::RData::PTR(ptr) = ptr_data
                {
                    let ptr_name = ptr.to_string();
                    println!(
                        "  Answer (upstream): {} PTR -> {} (TTL: {}s)",
                        domain, ptr_name, ttl
                    );

                    cache_entries.push(CacheEntry::new(RecordData::PTR(ptr_name.clone()), ttl));

                    let answer = DnsAnswer::new_ptr_record(domain.to_string(), ttl, ptr_name);
                    packet.answers.push(answer);
                    packet.header.answers += 1;
                }
            }

            insert_cache(domain.to_string(), QTYPE_PTR, cache_entries, cache).await;
        }
        Err(e) => {
            println!("  Upstream resolution failed for {}: {}", domain, e);
            packet.header.set_rcode(RCODE_SERVER_FAILURE);
        }
    }
}

async fn handle_txt_query(
    domain: &str,
    cache: &Arc<RwLock<DnsCache>>,
    resolver: &Arc<TokioAsyncResolver>,
    stats: &Arc<DnsStats>,
    packet: &mut DnsPacket,
) {
    use trust_dns_resolver::proto::rr::RecordType;

    // Check cache
    if let Some(cached_entries) = check_cache(domain, QTYPE_TXT, cache, stats).await {
        for entry in cached_entries {
            if let RecordData::TXT(ref txt) = entry.data {
                let ttl = entry.remaining_ttl();
                println!(
                    "  Answer (cache): {} TXT -> \"{}\" (TTL: {}s)",
                    domain, txt, ttl
                );
                let answer = DnsAnswer::new_txt_record(domain.to_string(), ttl, txt.clone());
                packet.answers.push(answer);
                packet.header.answers += 1;
            }
        }
        return;
    }

    // Forward to upstream
    println!("  Forwarding to upstream DNS for {} (TXT)", domain);
    match with_timeout(resolver.lookup(domain, RecordType::TXT), domain, "TXT").await {
        Ok(lookup) => {
            let ttl = 300u32;
            let mut cache_entries = Vec::new();

            for record in lookup.record_iter() {
                if let Some(txt_data) = record.data()
                    && let trust_dns_resolver::proto::rr::RData::TXT(txt) = txt_data
                {
                    // Concatenate all text strings with explicit UTF-8 handling
                    let txt_string = txt
                        .iter()
                        .map(|bytes| {
                            String::from_utf8(bytes.to_vec()).unwrap_or_else(|_| {
                                eprintln!(
                                    "Warning: Invalid UTF-8 in TXT record for {}, using replacement characters",
                                    domain
                                );
                                String::from_utf8_lossy(bytes).to_string()
                            })
                        })
                        .collect::<Vec<String>>()
                        .join("");

                    println!(
                        "  Answer (upstream): {} TXT -> \"{}\" (TTL: {}s)",
                        domain, txt_string, ttl
                    );

                    cache_entries.push(CacheEntry::new(RecordData::TXT(txt_string.clone()), ttl));

                    let answer = DnsAnswer::new_txt_record(domain.to_string(), ttl, txt_string);
                    packet.answers.push(answer);
                    packet.header.answers += 1;
                }
            }

            insert_cache(domain.to_string(), QTYPE_TXT, cache_entries, cache).await;
        }
        Err(e) => {
            println!("  Upstream resolution failed for {}: {}", domain, e);
            packet.header.set_rcode(RCODE_SERVER_FAILURE);
        }
    }
}

async fn handle_soa_query(
    domain: &str,
    cache: &Arc<RwLock<DnsCache>>,
    resolver: &Arc<TokioAsyncResolver>,
    stats: &Arc<DnsStats>,
    packet: &mut DnsPacket,
) {
    use trust_dns_resolver::proto::rr::RecordType;

    // Check cache
    if let Some(cached_entries) = check_cache(domain, QTYPE_SOA, cache, stats).await {
        for entry in cached_entries {
            if let RecordData::SOA {
                ref mname,
                ref rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } = entry.data
            {
                let ttl = entry.remaining_ttl();
                println!(
                    "  Answer (cache): {} SOA -> {} {} (TTL: {}s)",
                    domain, mname, rname, ttl
                );
                let answer = DnsAnswer::new_soa_record(
                    domain.to_string(),
                    ttl,
                    mname.clone(),
                    rname.clone(),
                    serial,
                    refresh,
                    retry,
                    expire,
                    minimum,
                );
                packet.answers.push(answer);
                packet.header.answers += 1;
            }
        }
        return;
    }

    // Forward to upstream
    println!("  Forwarding to upstream DNS for {} (SOA)", domain);
    match with_timeout(resolver.lookup(domain, RecordType::SOA), domain, "SOA").await {
        Ok(lookup) => {
            let ttl = 300u32;
            let mut cache_entries = Vec::new();

            for record in lookup.record_iter() {
                if let Some(soa_data) = record.data()
                    && let trust_dns_resolver::proto::rr::RData::SOA(soa) = soa_data
                {
                    let mname = soa.mname().to_string();
                    let rname = soa.rname().to_string();
                    let serial = soa.serial();
                    let refresh = soa.refresh() as u32;
                    let retry = soa.retry() as u32;
                    let expire = soa.expire() as u32;
                    let minimum = soa.minimum();

                    println!(
                        "  Answer (upstream): {} SOA -> {} {} (TTL: {}s)",
                        domain, mname, rname, ttl
                    );

                    cache_entries.push(CacheEntry::new(
                        RecordData::SOA {
                            mname: mname.clone(),
                            rname: rname.clone(),
                            serial,
                            refresh,
                            retry,
                            expire,
                            minimum,
                        },
                        ttl,
                    ));

                    let answer = DnsAnswer::new_soa_record(
                        domain.to_string(),
                        ttl,
                        mname,
                        rname,
                        serial,
                        refresh,
                        retry,
                        expire,
                        minimum,
                    );
                    packet.answers.push(answer);
                    packet.header.answers += 1;
                }
            }

            insert_cache(domain.to_string(), QTYPE_SOA, cache_entries, cache).await;
        }
        Err(e) => {
            println!("  Upstream resolution failed for {}: {}", domain, e);
            packet.header.set_rcode(RCODE_SERVER_FAILURE);
        }
    }
}
