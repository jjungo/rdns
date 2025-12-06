use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use std::fs::File;
use std::io::Write;

pub struct DnsStats {
    start_time: Instant,
    total_queries: AtomicU64,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    upstream_queries: AtomicU64,
    queries_by_type: HashMap<u16, AtomicU64>,
    total_response_time_ms: AtomicU64,
}

impl Default for DnsStats {
    fn default() -> Self {
        let mut queries_by_type = HashMap::new();
        // Pre-populate common record types
        for &qtype in &[1, 2, 5, 6, 12, 15, 16, 28] {
            queries_by_type.insert(qtype, AtomicU64::new(0));
        }

        DnsStats {
            start_time: Instant::now(),
            total_queries: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            upstream_queries: AtomicU64::new(0),
            queries_by_type,
            total_response_time_ms: AtomicU64::new(0),
        }
    }
}

impl DnsStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_query(&self, qtype: u16) {
        self.total_queries.fetch_add(1, Ordering::Relaxed);
        if let Some(counter) = self.queries_by_type.get(&qtype) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn record_cache_hit(&self) {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_cache_miss(&self) {
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_upstream_query(&self) {
        self.upstream_queries.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_response_time(&self, duration: Duration) {
        self.total_response_time_ms
            .fetch_add(duration.as_millis() as u64, Ordering::Relaxed);
    }

    pub fn get_uptime(&self) -> Duration {
        self.start_time.elapsed()
    }

    pub fn get_total_queries(&self) -> u64 {
        self.total_queries.load(Ordering::Relaxed)
    }

    pub fn get_cache_hits(&self) -> u64 {
        self.cache_hits.load(Ordering::Relaxed)
    }

    pub fn get_cache_misses(&self) -> u64 {
        self.cache_misses.load(Ordering::Relaxed)
    }

    pub fn get_upstream_queries(&self) -> u64 {
        self.upstream_queries.load(Ordering::Relaxed)
    }

    pub fn get_cache_hit_ratio(&self) -> f64 {
        let hits = self.get_cache_hits() as f64;
        let total = hits + self.get_cache_misses() as f64;
        if total == 0.0 {
            0.0
        } else {
            (hits / total) * 100.0
        }
    }

    pub fn get_average_response_time_ms(&self) -> f64 {
        let total_time = self.total_response_time_ms.load(Ordering::Relaxed) as f64;
        let total_queries = self.get_total_queries() as f64;
        if total_queries == 0.0 {
            0.0
        } else {
            total_time / total_queries
        }
    }

    pub fn get_queries_per_second(&self) -> f64 {
        let total = self.get_total_queries() as f64;
        let uptime_secs = self.get_uptime().as_secs_f64();
        if uptime_secs == 0.0 {
            0.0
        } else {
            total / uptime_secs
        }
    }

    pub fn get_query_count_by_type(&self, qtype: u16) -> u64 {
        self.queries_by_type
            .get(&qtype)
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    pub fn write_stats_to_file(&self, filename: &str, cache_size: usize) -> std::io::Result<()> {
        let uptime = self.get_uptime();
        let hours = uptime.as_secs() / 3600;
        let minutes = (uptime.as_secs() % 3600) / 60;
        let seconds = uptime.as_secs() % 60;

        let mut file = File::create(filename)?;

        writeln!(file, "\n═══════════════════════════════════════════════════")?;
        writeln!(file, "           DNS Server Statistics")?;
        writeln!(file, "═══════════════════════════════════════════════════")?;
        writeln!(file, "Uptime:              {}h {}m {}s", hours, minutes, seconds)?;
        writeln!(file, "Total Queries:       {}", self.get_total_queries())?;
        writeln!(file, "Queries/sec:         {:.2}", self.get_queries_per_second())?;
        writeln!(file, "Avg Response Time:   {:.2} ms", self.get_average_response_time_ms())?;
        writeln!(file)?;
        writeln!(file, "Cache Performance:")?;
        writeln!(file, "  Cache Hits:        {} ({:.1}%)",
            self.get_cache_hits(),
            self.get_cache_hit_ratio()
        )?;
        writeln!(file, "  Cache Misses:      {}", self.get_cache_misses())?;
        writeln!(file, "  Upstream Queries:  {}", self.get_upstream_queries())?;
        writeln!(file, "  Cache Entries:     {}", cache_size)?;
        writeln!(file)?;
        writeln!(file, "Queries by Type:")?;

        let types = [
            (1, "A"),
            (28, "AAAA"),
            (2, "NS"),
            (6, "SOA"),
            (12, "PTR"),
            (15, "MX"),
            (16, "TXT"),
            (5, "CNAME"),
        ];

        for (qtype, name) in types {
            let count = self.get_query_count_by_type(qtype);
            if count > 0 {
                let percentage = (count as f64 / self.get_total_queries() as f64) * 100.0;
                writeln!(file, "  {:<10} {:>6} ({:>5.1}%)", name, count, percentage)?;
            }
        }
        writeln!(file, "═══════════════════════════════════════════════════\n")?;

        Ok(())
    }
}
