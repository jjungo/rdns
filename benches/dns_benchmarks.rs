use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use rdns::dns::{DnsPacket, DnsHeader, DnsQuestion, QueryType, DnsAnswer};
use rdns::cache::{DnsCache, RecordData};
use std::net::Ipv4Addr;

// Benchmark DNS packet parsing
fn bench_dns_packet_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("dns_parsing");
    group.measurement_time(std::time::Duration::from_secs(2));
    group.sample_size(30);

    // Create a sample DNS query packet
    let mut query = vec![
        0x12, 0x34, // Transaction ID
        0x01, 0x00, // Flags: standard query
        0x00, 0x01, // Questions: 1
        0x00, 0x00, // Answer RRs: 0
        0x00, 0x00, // Authority RRs: 0
        0x00, 0x00, // Additional RRs: 0
    ];

    // Add question: "example.com" A record
    query.extend_from_slice(&[
        0x07, // Length of "example"
    ]);
    query.extend_from_slice(b"example");
    query.extend_from_slice(&[
        0x03, // Length of "com"
    ]);
    query.extend_from_slice(b"com");
    query.extend_from_slice(&[
        0x00, // End of name
        0x00, 0x01, // Type: A
        0x00, 0x01, // Class: IN
    ]);

    group.bench_function("parse_dns_query", |b| {
        b.iter(|| {
            DnsPacket::from_bytes(black_box(&query)).unwrap()
        })
    });

    group.finish();
}

// Benchmark DNS response creation
fn bench_dns_response_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("dns_response");
    group.measurement_time(std::time::Duration::from_secs(2));
    group.sample_size(30);

    group.bench_function("create_dns_response", |b| {
        b.iter(|| {
            let packet = DnsPacket {
                header: DnsHeader {
                    id: black_box(0x1234),
                    flags: 0x8180,
                    questions: 1,
                    answers: 1,
                    authority: 0,
                    additional: 0,
                },
                questions: vec![DnsQuestion {
                    name: "example.com".to_string(),
                    qtype: QueryType::A,
                    qclass: 1,
                }],
                answers: vec![DnsAnswer::new_a_record(
                    "example.com".to_string(),
                    300,
                    Ipv4Addr::new(93, 184, 216, 34),
                )],
            };
            black_box(packet.to_bytes())
        })
    });

    group.finish();
}

// Benchmark cache operations
fn bench_cache_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache");
    group.measurement_time(std::time::Duration::from_secs(2));
    group.sample_size(30);

    // Benchmark cache insertion
    group.bench_function("insert", |b| {
        let mut cache = DnsCache::new(1000);
        let mut counter = 0u32;
        b.iter(|| {
            let domain = format!("domain{}.com", counter);
            let entry = vec![rdns::cache::CacheEntry::new(
                RecordData::A(Ipv4Addr::new(192, 168, 1, counter as u8)),
                300,
            )];
            cache.insert(black_box(domain), 1, entry);
            counter = (counter + 1) % 1000;
        })
    });

    // Benchmark cache lookup - hit
    group.bench_function("lookup_hit", |b| {
        let mut cache = DnsCache::new(1000);
        // Pre-populate cache
        for i in 0..100 {
            let domain = format!("domain{}.com", i);
            let entry = vec![rdns::cache::CacheEntry::new(
                RecordData::A(Ipv4Addr::new(192, 168, 1, i as u8)),
                300,
            )];
            cache.insert(domain, 1, entry);
        }

        let mut counter = 0;
        b.iter(|| {
            let domain = format!("domain{}.com", counter % 100);
            black_box(cache.get(black_box(&domain), 1));
            counter += 1;
        })
    });

    // Benchmark cache lookup - miss
    group.bench_function("lookup_miss", |b| {
        let mut cache = DnsCache::new(1000);
        let mut counter = 0;

        b.iter(|| {
            let domain = format!("missing{}.com", counter);
            black_box(cache.get(black_box(&domain), 1));
            counter += 1;
        })
    });

    group.finish();
}

// Benchmark cache cleanup
fn bench_cache_cleanup(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_cleanup");

    // Configure shorter measurement time for cleanup benchmarks
    group.measurement_time(std::time::Duration::from_secs(2));
    group.sample_size(10);

    for size in [100, 500].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.iter_batched(
                || {
                    let mut cache = DnsCache::new(1500);
                    // Pre-populate with expired entries (TTL=0 means instant expiration)
                    for i in 0..size {
                        let domain = format!("domain{}.com", i);
                        let entry = vec![rdns::cache::CacheEntry::new(
                            RecordData::A(Ipv4Addr::new(192, 168, 1, (i % 256) as u8)),
                            0, // Already expired (TTL=0)
                        )];
                        cache.insert(domain, 1, entry);
                    }
                    cache
                },
                |mut cache| {
                    cache.cleanup_expired();
                    black_box(cache)
                },
                criterion::BatchSize::LargeInput,
            )
        });
    }

    group.finish();
}

// Benchmark different DNS record types
fn bench_record_types(c: &mut Criterion) {
    let mut group = c.benchmark_group("record_types");
    group.measurement_time(std::time::Duration::from_secs(2));
    group.sample_size(30);

    group.bench_function("A_record", |b| {
        b.iter(|| {
            DnsAnswer::new_a_record(
                black_box("example.com".to_string()),
                300,
                Ipv4Addr::new(93, 184, 216, 34),
            )
        })
    });

    group.bench_function("AAAA_record", |b| {
        b.iter(|| {
            DnsAnswer::new_aaaa_record(
                black_box("example.com".to_string()),
                300,
                "2606:2800:220:1:248:1893:25c8:1946".parse().unwrap(),
            )
        })
    });

    group.bench_function("MX_record", |b| {
        b.iter(|| {
            DnsAnswer::new_mx_record(
                black_box("example.com".to_string()),
                300,
                10,
                "mail.example.com".to_string(),
            )
        })
    });

    group.bench_function("TXT_record", |b| {
        b.iter(|| {
            DnsAnswer::new_txt_record(
                black_box("example.com".to_string()),
                300,
                "v=spf1 include:_spf.example.com ~all".to_string(),
            )
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_dns_packet_parsing,
    bench_dns_response_creation,
    bench_cache_operations,
    bench_cache_cleanup,
    bench_record_types,
);
criterion_main!(benches);
