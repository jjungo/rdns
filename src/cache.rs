use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

#[allow(clippy::upper_case_acronyms)]
#[derive(Clone, Debug)]
pub enum RecordData {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    NS(String),
    CNAME(String),
    SOA {
        mname: String,
        rname: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    PTR(String),
    MX { priority: u16, exchange: String },
    TXT(String),
}

#[derive(Clone, Debug)]
pub struct CacheEntry {
    pub data: RecordData,
    pub expires_at: Instant,
}

impl CacheEntry {
    pub fn new(data: RecordData, ttl: u32) -> Self {
        CacheEntry {
            data,
            expires_at: Instant::now() + Duration::from_secs(ttl as u64),
        }
    }

    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }

    pub fn remaining_ttl(&self) -> u32 {
        let now = Instant::now();
        if now >= self.expires_at {
            return 0;
        }
        (self.expires_at - now).as_secs() as u32
    }
}

pub struct DnsCache {
    cache: HashMap<(String, u16), Vec<CacheEntry>>, // Key is (domain, query_type)
    max_entries: usize,
}

impl DnsCache {
    pub fn new(max_entries: usize) -> Self {
        DnsCache {
            cache: HashMap::new(),
            max_entries,
        }
    }

    pub fn get(&mut self, domain: &str, qtype: u16) -> Option<Vec<CacheEntry>> {
        let key = (domain.to_string(), qtype);
        if let Some(entries) = self.cache.get(&key) {
            // Filter out expired entries
            let valid_entries: Vec<CacheEntry> = entries
                .iter()
                .filter(|e| !e.is_expired())
                .cloned()
                .collect();

            if valid_entries.is_empty() {
                self.cache.remove(&key);
                return None;
            }

            return Some(valid_entries);
        }
        None
    }

    pub fn insert(&mut self, domain: String, qtype: u16, entries: Vec<CacheEntry>) {
        if entries.is_empty() {
            return;
        }

        // Simple eviction: if we're at max capacity, remove expired entries
        let total_entries: usize = self.cache.values().map(|v| v.len()).sum();
        if total_entries >= self.max_entries {
            self.cleanup_expired();

            // If still at capacity, remove the key with shortest average TTL
            let total_entries: usize = self.cache.values().map(|v| v.len()).sum();
            if total_entries >= self.max_entries
                && let Some(key_to_remove) = self.cache
                    .iter()
                    .min_by_key(|(_, entries)| {
                        let avg_ttl: u32 = entries.iter().map(|e| e.remaining_ttl()).sum::<u32>()
                            / entries.len().max(1) as u32;
                        avg_ttl
                    })
                    .map(|(k, _)| k.clone())
                {
                    self.cache.remove(&key_to_remove);
                }
        }

        let key = (domain, qtype);
        self.cache.insert(key, entries);
    }

    pub fn cleanup_expired(&mut self) {
        self.cache.retain(|_, entries| {
            entries.retain(|e| !e.is_expired());
            !entries.is_empty()
        });
    }

    pub fn len(&self) -> usize {
        self.cache.values().map(|v| v.len()).sum()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    #[allow(dead_code)]
    pub fn clear(&mut self) {
        self.cache.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    #[test]
    fn test_cache_entry_expiration() {
        let entry = CacheEntry::new(RecordData::A(Ipv4Addr::new(1, 1, 1, 1)), 1);
        assert!(!entry.is_expired());
        sleep(Duration::from_secs(2));
        assert!(entry.is_expired());
    }

    #[test]
    fn test_cache_insert_and_get() {
        let mut cache = DnsCache::new(10);
        let entry = vec![CacheEntry::new(RecordData::A(Ipv4Addr::new(1, 1, 1, 1)), 300)];
        cache.insert("test.com".to_string(), 1, entry);

        let result = cache.get("test.com", 1);
        assert!(result.is_some());
        let entries = result.unwrap();
        assert_eq!(entries.len(), 1);
        if let RecordData::A(ip) = entries[0].data {
            assert_eq!(ip, Ipv4Addr::new(1, 1, 1, 1));
        } else {
            panic!("Expected A record");
        }
    }

    #[test]
    fn test_cache_expiration() {
        let mut cache = DnsCache::new(10);
        let entry = vec![CacheEntry::new(RecordData::A(Ipv4Addr::new(1, 1, 1, 1)), 1)];
        cache.insert("test.com".to_string(), 1, entry);

        sleep(Duration::from_secs(2));

        let result = cache.get("test.com", 1);
        assert!(result.is_none());
    }

    #[test]
    fn test_cache_eviction() {
        let mut cache = DnsCache::new(2);
        let entry1 = vec![CacheEntry::new(RecordData::A(Ipv4Addr::new(1, 1, 1, 1)), 300)];
        let entry2 = vec![CacheEntry::new(RecordData::A(Ipv4Addr::new(2, 2, 2, 2)), 300)];
        cache.insert("test1.com".to_string(), 1, entry1);
        cache.insert("test2.com".to_string(), 1, entry2);

        assert_eq!(cache.len(), 2);

        // Adding third entry should evict one
        let entry3 = vec![CacheEntry::new(RecordData::A(Ipv4Addr::new(3, 3, 3, 3)), 300)];
        cache.insert("test3.com".to_string(), 1, entry3);

        assert_eq!(cache.len(), 2);
    }
}
