use crate::cache::{CacheEntry, DnsCache, RecordData};
use crate::dns::{
    DnsAnswer, DnsPacket, QTYPE_A, QTYPE_AAAA, QTYPE_CNAME, QTYPE_MX, QTYPE_NS, QTYPE_PTR,
    QTYPE_SOA, QTYPE_TXT, RCODE_SERVER_FAILURE,
};
use crate::stats::DnsStats;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use tokio::sync::RwLock;
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::proto::rr::{RData, RecordType as DnsRecordType};

/// Abstraction over DNS record type operations
///
/// This trait inverts the dependency from concrete implementations to an
/// abstraction, allowing the QueryHandler to work with any record type
/// without knowing the specifics.
pub trait RecordType: Sized + Clone {
    /// The DNS query type constant (e.g., QTYPE_A = 1)
    fn qtype() -> u16;

    /// The human-readable name for logging (e.g., "A", "AAAA")
    fn qtype_name() -> &'static str;

    /// Extract this record type from cached data
    /// Returns None if the RecordData variant doesn't match
    fn extract_from_cache(data: &RecordData) -> Option<Self>;

    /// Extract this record type from upstream DNS response
    /// Returns None if the RData variant doesn't match
    fn extract_from_upstream(rdata: &RData) -> Option<Self>;

    /// Convert this record to a cache entry
    fn to_cache_entry(self, ttl: u32) -> CacheEntry;

    /// Convert this record to a DNS answer for the response packet
    fn to_answer(self, domain: String, ttl: u32) -> DnsAnswer;
}

/// A Record (IPv4 address)
#[derive(Clone, Debug)]
pub struct ARecord {
    pub ip: Ipv4Addr,
}

impl RecordType for ARecord {
    fn qtype() -> u16 {
        QTYPE_A
    }

    fn qtype_name() -> &'static str {
        "A"
    }

    fn extract_from_cache(data: &RecordData) -> Option<Self> {
        match data {
            RecordData::A(ip) => Some(ARecord { ip: *ip }),
            _ => None,
        }
    }

    fn extract_from_upstream(rdata: &RData) -> Option<Self> {
        match rdata {
            RData::A(a) => Some(ARecord { ip: a.0 }),
            _ => None,
        }
    }

    fn to_cache_entry(self, ttl: u32) -> CacheEntry {
        CacheEntry::new(RecordData::A(self.ip), ttl)
    }

    fn to_answer(self, domain: String, ttl: u32) -> DnsAnswer {
        DnsAnswer::new_a_record(domain, ttl, self.ip)
    }
}

/// AAAA Record (IPv6 address)
#[derive(Clone, Debug)]
pub struct AAAARecord {
    pub ip: Ipv6Addr,
}

impl RecordType for AAAARecord {
    fn qtype() -> u16 {
        QTYPE_AAAA
    }

    fn qtype_name() -> &'static str {
        "AAAA"
    }

    fn extract_from_cache(data: &RecordData) -> Option<Self> {
        match data {
            RecordData::AAAA(ip) => Some(AAAARecord { ip: *ip }),
            _ => None,
        }
    }

    fn extract_from_upstream(rdata: &RData) -> Option<Self> {
        match rdata {
            RData::AAAA(aaaa) => Some(AAAARecord { ip: aaaa.0 }),
            _ => None,
        }
    }

    fn to_cache_entry(self, ttl: u32) -> CacheEntry {
        CacheEntry::new(RecordData::AAAA(self.ip), ttl)
    }

    fn to_answer(self, domain: String, ttl: u32) -> DnsAnswer {
        DnsAnswer::new_aaaa_record(domain, ttl, self.ip)
    }
}

/// NS Record (Name Server)
#[derive(Clone, Debug)]
pub struct NSRecord {
    pub nameserver: String,
}

impl RecordType for NSRecord {
    fn qtype() -> u16 {
        QTYPE_NS
    }

    fn qtype_name() -> &'static str {
        "NS"
    }

    fn extract_from_cache(data: &RecordData) -> Option<Self> {
        match data {
            RecordData::NS(nameserver) => Some(NSRecord {
                nameserver: nameserver.clone(),
            }),
            _ => None,
        }
    }

    fn extract_from_upstream(rdata: &RData) -> Option<Self> {
        match rdata {
            RData::NS(ns) => Some(NSRecord {
                nameserver: ns.to_string(),
            }),
            _ => None,
        }
    }

    fn to_cache_entry(self, ttl: u32) -> CacheEntry {
        CacheEntry::new(RecordData::NS(self.nameserver.clone()), ttl)
    }

    fn to_answer(self, domain: String, ttl: u32) -> DnsAnswer {
        DnsAnswer::new_ns_record(domain, ttl, self.nameserver)
    }
}

/// MX Record (Mail Exchange)
#[derive(Clone, Debug)]
pub struct MXRecord {
    pub priority: u16,
    pub exchange: String,
}

impl RecordType for MXRecord {
    fn qtype() -> u16 {
        QTYPE_MX
    }

    fn qtype_name() -> &'static str {
        "MX"
    }

    fn extract_from_cache(data: &RecordData) -> Option<Self> {
        match data {
            RecordData::MX { priority, exchange } => Some(MXRecord {
                priority: *priority,
                exchange: exchange.clone(),
            }),
            _ => None,
        }
    }

    fn extract_from_upstream(rdata: &RData) -> Option<Self> {
        match rdata {
            RData::MX(mx) => Some(MXRecord {
                priority: mx.preference(),
                exchange: mx.exchange().to_string(),
            }),
            _ => None,
        }
    }

    fn to_cache_entry(self, ttl: u32) -> CacheEntry {
        CacheEntry::new(
            RecordData::MX {
                priority: self.priority,
                exchange: self.exchange.clone(),
            },
            ttl,
        )
    }

    fn to_answer(self, domain: String, ttl: u32) -> DnsAnswer {
        DnsAnswer::new_mx_record(domain, ttl, self.priority, self.exchange)
    }
}

/// CNAME Record (Canonical Name)
#[derive(Clone, Debug)]
pub struct CNAMERecord {
    pub cname: String,
}

impl RecordType for CNAMERecord {
    fn qtype() -> u16 {
        QTYPE_CNAME
    }

    fn qtype_name() -> &'static str {
        "CNAME"
    }

    fn extract_from_cache(data: &RecordData) -> Option<Self> {
        match data {
            RecordData::CNAME(cname) => Some(CNAMERecord {
                cname: cname.clone(),
            }),
            _ => None,
        }
    }

    fn extract_from_upstream(rdata: &RData) -> Option<Self> {
        match rdata {
            RData::CNAME(cname) => Some(CNAMERecord {
                cname: cname.to_string(),
            }),
            _ => None,
        }
    }

    fn to_cache_entry(self, ttl: u32) -> CacheEntry {
        CacheEntry::new(RecordData::CNAME(self.cname.clone()), ttl)
    }

    fn to_answer(self, domain: String, ttl: u32) -> DnsAnswer {
        DnsAnswer::new_cname_record(domain, ttl, self.cname)
    }
}

/// PTR Record (Pointer for reverse DNS)
#[derive(Clone, Debug)]
pub struct PTRRecord {
    pub ptrdname: String,
}

impl RecordType for PTRRecord {
    fn qtype() -> u16 {
        QTYPE_PTR
    }

    fn qtype_name() -> &'static str {
        "PTR"
    }

    fn extract_from_cache(data: &RecordData) -> Option<Self> {
        match data {
            RecordData::PTR(ptrdname) => Some(PTRRecord {
                ptrdname: ptrdname.clone(),
            }),
            _ => None,
        }
    }

    fn extract_from_upstream(rdata: &RData) -> Option<Self> {
        match rdata {
            RData::PTR(ptr) => Some(PTRRecord {
                ptrdname: ptr.to_string(),
            }),
            _ => None,
        }
    }

    fn to_cache_entry(self, ttl: u32) -> CacheEntry {
        CacheEntry::new(RecordData::PTR(self.ptrdname.clone()), ttl)
    }

    fn to_answer(self, domain: String, ttl: u32) -> DnsAnswer {
        DnsAnswer::new_ptr_record(domain, ttl, self.ptrdname)
    }
}

/// TXT Record (Text data with UTF-8 validation)
#[derive(Clone, Debug)]
pub struct TXTRecord {
    pub text: String,
}

impl RecordType for TXTRecord {
    fn qtype() -> u16 {
        QTYPE_TXT
    }

    fn qtype_name() -> &'static str {
        "TXT"
    }

    fn extract_from_cache(data: &RecordData) -> Option<Self> {
        match data {
            RecordData::TXT(text) => Some(TXTRecord { text: text.clone() }),
            _ => None,
        }
    }

    fn extract_from_upstream(rdata: &RData) -> Option<Self> {
        match rdata {
            RData::TXT(txt) => {
                // TXT records need UTF-8 validation
                let txt_string = txt
                    .iter()
                    .map(|bytes| {
                        String::from_utf8(bytes.to_vec()).unwrap_or_else(|_| {
                            log::warn!(
                                "Warning: Invalid UTF-8 in TXT record, using replacement characters"
                            );
                            String::from_utf8_lossy(bytes).to_string()
                        })
                    })
                    .collect::<Vec<String>>()
                    .join("");

                Some(TXTRecord { text: txt_string })
            }
            _ => None,
        }
    }

    fn to_cache_entry(self, ttl: u32) -> CacheEntry {
        CacheEntry::new(RecordData::TXT(self.text.clone()), ttl)
    }

    fn to_answer(self, domain: String, ttl: u32) -> DnsAnswer {
        DnsAnswer::new_txt_record(domain, ttl, self.text)
    }
}

/// SOA Record (Start of Authority)
#[derive(Clone, Debug)]
pub struct SOARecord {
    pub mname: String,
    pub rname: String,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32,
}

impl RecordType for SOARecord {
    fn qtype() -> u16 {
        QTYPE_SOA
    }

    fn qtype_name() -> &'static str {
        "SOA"
    }

    fn extract_from_cache(data: &RecordData) -> Option<Self> {
        match data {
            RecordData::SOA {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => Some(SOARecord {
                mname: mname.clone(),
                rname: rname.clone(),
                serial: *serial,
                refresh: *refresh,
                retry: *retry,
                expire: *expire,
                minimum: *minimum,
            }),
            _ => None,
        }
    }

    fn extract_from_upstream(rdata: &RData) -> Option<Self> {
        match rdata {
            RData::SOA(soa) => Some(SOARecord {
                mname: soa.mname().to_string(),
                rname: soa.rname().to_string(),
                serial: soa.serial(),
                refresh: soa.refresh() as u32,
                retry: soa.retry() as u32,
                expire: soa.expire() as u32,
                minimum: soa.minimum(),
            }),
            _ => None,
        }
    }

    fn to_cache_entry(self, ttl: u32) -> CacheEntry {
        CacheEntry::new(
            RecordData::SOA {
                mname: self.mname.clone(),
                rname: self.rname.clone(),
                serial: self.serial,
                refresh: self.refresh,
                retry: self.retry,
                expire: self.expire,
                minimum: self.minimum,
            },
            ttl,
        )
    }

    fn to_answer(self, domain: String, ttl: u32) -> DnsAnswer {
        DnsAnswer::new_soa_record(
            domain,
            ttl,
            self.mname,
            self.rname,
            self.serial,
            self.refresh,
            self.retry,
            self.expire,
            self.minimum,
        )
    }
}

/// Generic query handler that works with any RecordType
///
/// Responsible for the single concern of: cache check → upstream → cache insert
/// Delegates record-specific operations to the RecordType trait
pub struct QueryHandler<'a> {
    pub cache: &'a Arc<RwLock<DnsCache>>,
    pub resolver: &'a Arc<TokioAsyncResolver>,
    pub stats: &'a Arc<DnsStats>,
}

impl<'a> QueryHandler<'a> {
    pub fn new(
        cache: &'a Arc<RwLock<DnsCache>>,
        resolver: &'a Arc<TokioAsyncResolver>,
        stats: &'a Arc<DnsStats>,
    ) -> Self {
        Self {
            cache,
            resolver,
            stats,
        }
    }

    /// Handle a DNS query for any record type
    ///
    /// This is the single, generic implementation that replaces all 8 handlers
    pub async fn handle<R: RecordType>(&self, domain: &str, packet: &mut DnsPacket) {
        // Step 1: Check cache
        if self.try_from_cache::<R>(domain, packet).await {
            return;
        }

        // Step 2: Forward to upstream
        self.forward_to_upstream::<R>(domain, packet).await;
    }

    /// Try to answer from cache
    /// Returns true if cache hit, false if cache miss
    async fn try_from_cache<R: RecordType>(&self, domain: &str, packet: &mut DnsPacket) -> bool {
        if let Some(cached_entries) = check_cache(domain, R::qtype(), self.cache, self.stats).await
        {
            for entry in cached_entries {
                if let Some(record) = R::extract_from_cache(&entry.data) {
                    let ttl = entry.remaining_ttl();
                    log::debug!(
                        "  Answer (cache): {} {} -> ... (TTL: {}s)",
                        domain,
                        R::qtype_name(),
                        ttl
                    );

                    let answer = record.to_answer(domain.to_string(), ttl);
                    packet.answers.push(answer);
                    packet.header.answers += 1;
                }
            }
            return true;
        }
        false
    }

    /// Forward query to upstream DNS server
    async fn forward_to_upstream<R: RecordType>(&self, domain: &str, packet: &mut DnsPacket) {
        let record_type = DnsRecordType::from(R::qtype());

        log::debug!(
            "  Forwarding to upstream DNS for {} ({})",
            domain,
            R::qtype_name()
        );

        match with_timeout(
            self.resolver.lookup(domain, record_type),
            domain,
            R::qtype_name(),
        )
        .await
        {
            Ok(lookup) => {
                let ttl = get_default_ttl(self.cache).await;
                let mut cache_entries = Vec::new();

                for record in lookup.record_iter() {
                    if let Some(rdata) = record.data()
                        && let Some(parsed_record) = R::extract_from_upstream(rdata)
                    {
                        log::debug!(
                            "  Answer (upstream): {} {} -> ... (TTL: {}s)",
                            domain,
                            R::qtype_name(),
                            ttl
                        );

                        // Add to cache entries
                        cache_entries.push(parsed_record.clone().to_cache_entry(ttl));

                        // Add to response packet
                        let answer = parsed_record.to_answer(domain.to_string(), ttl);
                        packet.answers.push(answer);
                        packet.header.answers += 1;
                    }
                }

                // Cache the results
                insert_cache(domain.to_string(), R::qtype(), cache_entries, self.cache).await;
            }
            Err(e) => {
                log::warn!("  Upstream resolution failed for {}: {}", domain, e);
                packet.header.set_rcode(RCODE_SERVER_FAILURE);
                self.stats.record_unresolved();
            }
        }
    }
}

// Helper functions from server.rs that we need to use

/// Check cache for a domain and query type
async fn check_cache(
    domain: &str,
    qtype: u16,
    cache: &Arc<RwLock<DnsCache>>,
    stats: &Arc<DnsStats>,
) -> Option<Vec<CacheEntry>> {
    let mut cache_guard = cache.write().await;
    if let Some(entries) = cache_guard.get(domain, qtype) {
        stats.record_cache_hit();
        return Some(entries);
    }
    stats.record_cache_miss();
    None
}

/// Get default TTL from cache
async fn get_default_ttl(cache: &Arc<RwLock<DnsCache>>) -> u32 {
    let cache_guard = cache.read().await;
    cache_guard.default_ttl()
}

/// Insert entries into cache
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

/// Wrap upstream DNS query with timeout protection
pub(crate) async fn with_timeout<T>(
    future: impl std::future::Future<Output = Result<T, trust_dns_resolver::error::ResolveError>>,
    domain: &str,
    qtype_name: &str,
) -> Result<T, String> {
    use std::time::Duration;
    const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(5);

    match tokio::time::timeout(UPSTREAM_TIMEOUT, future).await {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(e)) => Err(format!("DNS resolution error: {}", e)),
        Err(_) => Err(format!(
            "Timeout after {}s querying {} for {}",
            UPSTREAM_TIMEOUT.as_secs(),
            qtype_name,
            domain
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::QueryType;

    #[test]
    fn test_a_record_trait_implementation() {
        // Test cache extraction
        let cache_data = RecordData::A(Ipv4Addr::new(192, 168, 1, 1));
        let record = ARecord::extract_from_cache(&cache_data).unwrap();
        assert_eq!(record.ip, Ipv4Addr::new(192, 168, 1, 1));

        // Test wrong variant returns None
        let wrong_data = RecordData::AAAA(Ipv6Addr::LOCALHOST);
        assert!(ARecord::extract_from_cache(&wrong_data).is_none());
    }

    #[test]
    fn test_a_record_to_cache_entry() {
        let record = ARecord {
            ip: Ipv4Addr::new(1, 2, 3, 4),
        };
        let entry = record.to_cache_entry(300);

        match entry.data {
            RecordData::A(ip) => assert_eq!(ip, Ipv4Addr::new(1, 2, 3, 4)),
            _ => panic!("Expected A record in cache entry"),
        }
    }

    #[test]
    fn test_a_record_to_answer() {
        let record = ARecord {
            ip: Ipv4Addr::new(93, 184, 216, 34),
        };
        let answer = record.to_answer("example.com".to_string(), 300);

        assert_eq!(answer.name, "example.com");
        assert_eq!(answer.ttl, 300);
        assert!(matches!(answer.qtype, QueryType::A));
        assert_eq!(answer.data, vec![93, 184, 216, 34]);
    }

    #[test]
    fn test_aaaa_record_trait_implementation() {
        let ipv6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let cache_data = RecordData::AAAA(ipv6);
        let record = AAAARecord::extract_from_cache(&cache_data).unwrap();
        assert_eq!(record.ip, ipv6);

        // Test wrong variant returns None
        let wrong_data = RecordData::A(Ipv4Addr::LOCALHOST);
        assert!(AAAARecord::extract_from_cache(&wrong_data).is_none());
    }

    #[test]
    fn test_mx_record_multi_field() {
        let record = MXRecord {
            priority: 10,
            exchange: "mail.example.com".to_string(),
        };

        let entry = record.clone().to_cache_entry(300);
        match entry.data {
            RecordData::MX { priority, exchange } => {
                assert_eq!(priority, 10);
                assert_eq!(exchange, "mail.example.com");
            }
            _ => panic!("Expected MX record"),
        }

        let answer = record.to_answer("example.com".to_string(), 300);
        assert_eq!(answer.name, "example.com");
        assert!(matches!(answer.qtype, QueryType::MX));
    }

    #[test]
    fn test_ns_record() {
        let record = NSRecord {
            nameserver: "ns1.example.com".to_string(),
        };

        let entry = record.clone().to_cache_entry(300);
        match entry.data {
            RecordData::NS(ns) => assert_eq!(ns, "ns1.example.com"),
            _ => panic!("Expected NS record"),
        }
    }

    #[test]
    fn test_cname_record() {
        let record = CNAMERecord {
            cname: "www.example.com".to_string(),
        };

        let entry = record.clone().to_cache_entry(300);
        match entry.data {
            RecordData::CNAME(cname) => assert_eq!(cname, "www.example.com"),
            _ => panic!("Expected CNAME record"),
        }
    }

    #[test]
    fn test_ptr_record() {
        let record = PTRRecord {
            ptrdname: "example.com".to_string(),
        };

        let entry = record.clone().to_cache_entry(300);
        match entry.data {
            RecordData::PTR(ptr) => assert_eq!(ptr, "example.com"),
            _ => panic!("Expected PTR record"),
        }
    }

    #[test]
    fn test_txt_record() {
        let record = TXTRecord {
            text: "v=spf1 include:_spf.example.com ~all".to_string(),
        };

        let entry = record.clone().to_cache_entry(300);
        match entry.data {
            RecordData::TXT(txt) => assert_eq!(txt, "v=spf1 include:_spf.example.com ~all"),
            _ => panic!("Expected TXT record"),
        }
    }

    #[test]
    fn test_soa_record_all_fields() {
        let record = SOARecord {
            mname: "ns1.example.com".to_string(),
            rname: "admin.example.com".to_string(),
            serial: 2024010101,
            refresh: 3600,
            retry: 600,
            expire: 86400,
            minimum: 300,
        };

        let entry = record.clone().to_cache_entry(300);
        match entry.data {
            RecordData::SOA {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => {
                assert_eq!(mname, "ns1.example.com");
                assert_eq!(rname, "admin.example.com");
                assert_eq!(serial, 2024010101);
                assert_eq!(refresh, 3600);
                assert_eq!(retry, 600);
                assert_eq!(expire, 86400);
                assert_eq!(minimum, 300);
            }
            _ => panic!("Expected SOA record"),
        }
    }

    #[test]
    fn test_record_type_constants() {
        assert_eq!(ARecord::qtype(), QTYPE_A);
        assert_eq!(AAAARecord::qtype(), QTYPE_AAAA);
        assert_eq!(MXRecord::qtype(), QTYPE_MX);
        assert_eq!(NSRecord::qtype(), QTYPE_NS);
        assert_eq!(CNAMERecord::qtype(), QTYPE_CNAME);
        assert_eq!(PTRRecord::qtype(), QTYPE_PTR);
        assert_eq!(TXTRecord::qtype(), QTYPE_TXT);
        assert_eq!(SOARecord::qtype(), QTYPE_SOA);
    }

    #[test]
    fn test_record_type_names() {
        assert_eq!(ARecord::qtype_name(), "A");
        assert_eq!(AAAARecord::qtype_name(), "AAAA");
        assert_eq!(MXRecord::qtype_name(), "MX");
        assert_eq!(NSRecord::qtype_name(), "NS");
        assert_eq!(CNAMERecord::qtype_name(), "CNAME");
        assert_eq!(PTRRecord::qtype_name(), "PTR");
        assert_eq!(TXTRecord::qtype_name(), "TXT");
        assert_eq!(SOARecord::qtype_name(), "SOA");
    }
}
