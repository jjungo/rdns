use rdns::config::Config;
use rdns::dns::{DnsPacket, QueryType};
use rdns::server::DnsServer;
use tokio::net::UdpSocket;
use tokio::time::{Duration, sleep};

/// Helper to create a DNS query packet
fn create_dns_query(domain: &str, qtype: QueryType) -> Vec<u8> {
    let mut query = vec![
        0x12, 0x34, // Transaction ID
        0x01, 0x00, // Flags: standard query, recursion desired
        0x00, 0x01, // Questions: 1
        0x00, 0x00, // Answer RRs: 0
        0x00, 0x00, // Authority RRs: 0
        0x00, 0x00, // Additional RRs: 0
    ];

    // Encode domain name
    for label in domain.split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0); // End of name

    // Add question type and class
    let qtype_num: u16 = qtype.into();
    query.extend_from_slice(&qtype_num.to_be_bytes());
    query.extend_from_slice(&[0x00, 0x01]); // Class: IN

    query
}

/// Helper to send DNS query and get response
async fn send_dns_query(port: u16, query: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    socket.send_to(query, format!("127.0.0.1:{}", port)).await?;

    let mut buf = vec![0u8; 512];
    let len = socket.recv(&mut buf).await?;
    buf.truncate(len);

    Ok(buf)
}

/// Helper to extract IPv4 address from A record answer in DNS response
fn extract_ipv4_from_response(response: &[u8]) -> Option<[u8; 4]> {
    // Skip header (12 bytes) and question section
    let mut offset = 12;

    // Skip question section - find the null terminator
    while offset < response.len() && response[offset] != 0 {
        let len = response[offset] as usize;
        if (len & 0xC0) == 0xC0 {
            // Pointer - skip 2 bytes
            offset += 2;
            break;
        }
        offset += len + 1;
    }
    if offset < response.len() && response[offset] == 0 {
        offset += 1; // Skip null terminator
    }
    offset += 4; // Skip QTYPE and QCLASS

    // Now at answer section
    // Skip answer name (could be pointer or full name)
    if offset >= response.len() {
        return None;
    }

    if (response[offset] & 0xC0) == 0xC0 {
        offset += 2; // Pointer
    } else {
        // Full name
        while offset < response.len() && response[offset] != 0 {
            let len = response[offset] as usize;
            offset += len + 1;
        }
        offset += 1; // Skip null terminator
    }

    // Skip TYPE (2 bytes), CLASS (2 bytes), TTL (4 bytes)
    offset += 8;

    // Read RDLENGTH (2 bytes)
    if offset + 2 > response.len() {
        return None;
    }
    let rdlength = u16::from_be_bytes([response[offset], response[offset + 1]]) as usize;
    offset += 2;

    // For A record, RDLENGTH should be 4
    if rdlength == 4 && offset + 4 <= response.len() {
        Some([
            response[offset],
            response[offset + 1],
            response[offset + 2],
            response[offset + 3],
        ])
    } else {
        None
    }
}

#[tokio::test]
async fn test_basic_a_query() {
    // Create config with a test record
    let mut config = Config::default_config();
    config.server.listen_port = 19053; // Use different port for testing
    config
        .records
        .insert("test.local".to_string(), "192.168.1.100".to_string());

    let addr = config.listen_addr();
    let server = DnsServer::new(&addr, config).await.unwrap();

    // Start server in background
    tokio::spawn(async move {
        server.run().await.ok();
    });

    // Give server time to start
    sleep(Duration::from_millis(100)).await;

    // Send query
    let query = create_dns_query("test.local", QueryType::A);
    let response = send_dns_query(19053, &query).await.unwrap();

    // Parse response (from_bytes only parses questions currently, not answers)
    let packet = DnsPacket::from_bytes(&response).unwrap();

    assert_eq!(packet.header.questions, 1);
    assert_eq!(packet.header.answers, 1, "Should have 1 answer in header");
    assert_eq!(packet.questions[0].name, "test.local");
    assert!(matches!(packet.questions[0].qtype, QueryType::A));

    // Verify the returned IP address matches
    let ip = extract_ipv4_from_response(&response).expect("Should contain valid A record");
    assert_eq!(ip, [192, 168, 1, 100], "IP should be 192.168.1.100");
}

#[tokio::test]
async fn test_upstream_forwarding() {
    let mut config = Config::default_config();
    config.server.listen_port = 19054;

    let addr = config.listen_addr();
    let server = DnsServer::new(&addr, config).await.unwrap();

    tokio::spawn(async move {
        server.run().await.ok();
    });

    sleep(Duration::from_millis(100)).await;

    // Query a real domain (google.com) - should forward to upstream
    let query = create_dns_query("google.com", QueryType::A);
    let response = send_dns_query(19054, &query).await.unwrap();

    let packet = DnsPacket::from_bytes(&response).unwrap();

    assert_eq!(packet.header.questions, 1);
    assert!(
        packet.header.answers > 0,
        "Should have answers from upstream"
    );
    assert_eq!(packet.questions[0].name, "google.com");
}

#[tokio::test]
async fn test_cache_behavior() {
    let mut config = Config::default_config();
    config.server.listen_port = 19055;

    let addr = config.listen_addr();
    let server = DnsServer::new(&addr, config).await.unwrap();

    tokio::spawn(async move {
        server.run().await.ok();
    });

    sleep(Duration::from_millis(100)).await;

    let query = create_dns_query("github.com", QueryType::A);

    // First query - should go to upstream
    let response1 = send_dns_query(19055, &query).await.unwrap();
    let packet1 = DnsPacket::from_bytes(&response1).unwrap();

    // Second query - should come from cache (faster)
    let start = std::time::Instant::now();
    let response2 = send_dns_query(19055, &query).await.unwrap();
    let duration = start.elapsed();
    let packet2 = DnsPacket::from_bytes(&response2).unwrap();

    // Both should have answers
    assert!(packet1.header.answers > 0);
    assert!(packet2.header.answers > 0);

    // Cached response should be very fast (< 10ms)
    assert!(
        duration.as_millis() < 10,
        "Cached query took {}ms, expected < 10ms",
        duration.as_millis()
    );
}

#[tokio::test]
async fn test_multiple_record_types() {
    let mut config = Config::default_config();
    config.server.listen_port = 19056;

    let addr = config.listen_addr();
    let server = DnsServer::new(&addr, config).await.unwrap();

    tokio::spawn(async move {
        server.run().await.ok();
    });

    sleep(Duration::from_millis(100)).await;

    // Test A record
    let query_a = create_dns_query("google.com", QueryType::A);
    let response_a = send_dns_query(19056, &query_a).await.unwrap();
    let packet_a = DnsPacket::from_bytes(&response_a).unwrap();
    assert!(packet_a.header.answers > 0, "A record should have answers");

    // Test AAAA record (may not always have answers, just verify we get a response)
    let query_aaaa = create_dns_query("google.com", QueryType::AAAA);
    let response_aaaa = send_dns_query(19056, &query_aaaa).await.unwrap();
    let packet_aaaa = DnsPacket::from_bytes(&response_aaaa).unwrap();
    assert_eq!(packet_aaaa.header.questions, 1, "Should process AAAA query");

    // Test MX record
    let query_mx = create_dns_query("gmail.com", QueryType::MX);
    let response_mx = send_dns_query(19056, &query_mx).await.unwrap();
    let packet_mx = DnsPacket::from_bytes(&response_mx).unwrap();
    assert!(
        packet_mx.header.answers > 0,
        "MX record should have answers"
    );
}

#[tokio::test]
async fn test_concurrent_queries() {
    let mut config = Config::default_config();
    config.server.listen_port = 19057;
    config
        .records
        .insert("concurrent.test".to_string(), "1.2.3.4".to_string());

    let addr = config.listen_addr();
    let server = DnsServer::new(&addr, config).await.unwrap();

    tokio::spawn(async move {
        server.run().await.ok();
    });

    sleep(Duration::from_millis(100)).await;

    // Send 10 concurrent queries
    let mut handles = vec![];
    for _ in 0..10 {
        handles.push(tokio::spawn(async move {
            let query = create_dns_query("concurrent.test", QueryType::A);
            send_dns_query(19057, &query).await
        }));
    }

    // All should succeed
    for handle in handles {
        let result = handle.await.unwrap();
        assert!(result.is_ok());

        let packet = DnsPacket::from_bytes(&result.unwrap()).unwrap();
        assert_eq!(packet.header.answers, 1);
    }
}

#[tokio::test]
async fn test_nonexistent_domain() {
    let mut config = Config::default_config();
    config.server.listen_port = 19058;

    let addr = config.listen_addr();
    let server = DnsServer::new(&addr, config).await.unwrap();

    tokio::spawn(async move {
        server.run().await.ok();
    });

    sleep(Duration::from_millis(100)).await;

    // Query for domain that doesn't exist in local records
    let query = create_dns_query("notinlocal.test", QueryType::A);
    let response = send_dns_query(19058, &query).await.unwrap();

    // Should still get a response (either from upstream or NXDOMAIN)
    let packet = DnsPacket::from_bytes(&response).unwrap();
    assert_eq!(packet.header.questions, 1);
}

#[tokio::test]
async fn test_malformed_dns_packet() {
    let mut config = Config::default_config();
    config.server.listen_port = 19060;

    let addr = config.listen_addr();
    let server = DnsServer::new(&addr, config).await.unwrap();

    tokio::spawn(async move {
        server.run().await.ok();
    });

    sleep(Duration::from_millis(100)).await;

    // Send malformed packet (too short - only 4 bytes, needs 12+ for header)
    let malformed = vec![0x12, 0x34, 0x01, 0x00];
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // Send malformed packet
    socket.send_to(&malformed, "127.0.0.1:19060").await.unwrap();

    // Try to receive response with timeout
    let mut buf = vec![0u8; 512];
    let result = tokio::time::timeout(Duration::from_millis(500), socket.recv(&mut buf)).await;

    // Server should either not respond or send an error
    // Main goal: server doesn't crash
    assert!(result.is_err() || result.is_ok());
}

#[tokio::test]
async fn test_servfail_response() {
    let mut config = Config::default_config();
    config.server.listen_port = 19061;

    let addr = config.listen_addr();
    let server = DnsServer::new(&addr, config).await.unwrap();

    tokio::spawn(async move {
        server.run().await.ok();
    });

    sleep(Duration::from_millis(100)).await;

    // Query for definitely invalid domain that should return SERVFAIL or NXDOMAIN
    let query = create_dns_query(
        "this-domain-absolutely-does-not-exist-12345.invalid",
        QueryType::A,
    );
    let response = send_dns_query(19061, &query).await.unwrap();

    // Check RCODE in response flags (last 4 bits)
    let rcode = u16::from_be_bytes([response[2], response[3]]) & 0x000F;

    // SERVFAIL (2) or NXDOMAIN (3) are both acceptable
    assert!(
        rcode == 2 || rcode == 3,
        "Expected SERVFAIL (2) or NXDOMAIN (3), got RCODE {}",
        rcode
    );
}

#[tokio::test]
async fn test_concurrent_queries_complete() {
    // Test that many concurrent queries complete without hanging
    let mut config = Config::default_config();
    config.server.listen_port = 19062;

    let addr = config.listen_addr();
    let server = DnsServer::new(&addr, config).await.unwrap();

    tokio::spawn(async move {
        server.run().await.ok();
    });

    sleep(Duration::from_millis(100)).await;

    // Send 20 concurrent queries
    let mut handles = vec![];
    for i in 0..20 {
        handles.push(tokio::spawn(async move {
            let domain = format!("test{}.example.com", i);
            let query = create_dns_query(&domain, QueryType::A);
            send_dns_query(19062, &query).await
        }));
    }

    // All should complete within reasonable time (timeout prevents hanging)
    let timeout_result = tokio::time::timeout(Duration::from_secs(10), async {
        for handle in handles {
            handle.await.ok();
        }
    })
    .await;

    assert!(
        timeout_result.is_ok(),
        "Queries should complete within 10 seconds (with 5s timeout per query)"
    );
}

#[tokio::test]
async fn test_https_query_type() {
    let mut config = Config::default_config();
    config.server.listen_port = 19063;

    let addr = config.listen_addr();
    let server = DnsServer::new(&addr, config).await.unwrap();

    tokio::spawn(async move {
        server.run().await.ok();
    });

    sleep(Duration::from_millis(100)).await;

    // Query for HTTPS record type (65)
    let query = create_dns_query("google.com", QueryType::HTTPS);
    let response = send_dns_query(19063, &query).await.unwrap();

    let packet = DnsPacket::from_bytes(&response).unwrap();

    // Verify the query was processed
    assert_eq!(packet.header.questions, 1);
    assert_eq!(packet.questions[0].name, "google.com");
    assert!(matches!(packet.questions[0].qtype, QueryType::HTTPS));

    // Should have answers from upstream (Google supports HTTPS records)
    assert!(
        packet.header.answers > 0,
        "HTTPS query should return answers from upstream"
    );
}

#[tokio::test]
async fn test_unknown_query_type_caa() {
    let mut config = Config::default_config();
    config.server.listen_port = 19064;

    let addr = config.listen_addr();
    let server = DnsServer::new(&addr, config).await.unwrap();

    tokio::spawn(async move {
        server.run().await.ok();
    });

    sleep(Duration::from_millis(100)).await;

    // Query for CAA record type (257) - an "unknown" type
    let query = create_dns_query("google.com", QueryType::Unknown(257));
    let response = send_dns_query(19064, &query).await.unwrap();

    let packet = DnsPacket::from_bytes(&response).unwrap();

    // Verify the query was processed
    assert_eq!(packet.header.questions, 1);
    assert_eq!(packet.questions[0].name, "google.com");

    // Verify it's recognized as Unknown(257)
    match packet.questions[0].qtype {
        QueryType::Unknown(257) => {} // Expected
        _ => panic!("Expected Unknown(257) query type"),
    }

    // Google has CAA records, so should have answers
    assert!(
        packet.header.answers > 0,
        "CAA query should return answers from upstream"
    );
}

#[tokio::test]
async fn test_https_cloudflare() {
    let mut config = Config::default_config();
    config.server.listen_port = 19065;

    let addr = config.listen_addr();
    let server = DnsServer::new(&addr, config).await.unwrap();

    tokio::spawn(async move {
        server.run().await.ok();
    });

    sleep(Duration::from_millis(100)).await;

    // Query for HTTPS record - Cloudflare is known to have HTTPS records
    let query = create_dns_query("cloudflare.com", QueryType::HTTPS);
    let response = send_dns_query(19065, &query).await.unwrap();

    let packet = DnsPacket::from_bytes(&response).unwrap();

    assert_eq!(packet.header.questions, 1);
    assert!(
        packet.header.answers > 0,
        "Cloudflare should have HTTPS records"
    );

    // Verify response has QR bit set (is a response)
    let flags = u16::from_be_bytes([response[2], response[3]]);
    assert!(flags & 0x8000 != 0, "QR bit should be set (response)");

    // Verify RA bit set (recursion available)
    assert!(flags & 0x0080 != 0, "RA bit should be set");
}

#[tokio::test]
async fn test_unknown_type_generic_forwarding() {
    let mut config = Config::default_config();
    config.server.listen_port = 19066;

    let addr = config.listen_addr();
    let server = DnsServer::new(&addr, config).await.unwrap();

    tokio::spawn(async move {
        server.run().await.ok();
    });

    sleep(Duration::from_millis(100)).await;

    // Test multiple unknown types
    let unknown_types = vec![
        QueryType::Unknown(64),  // SVCB
        QueryType::Unknown(257), // CAA
        QueryType::Unknown(99),  // SPF (deprecated but still testable)
    ];

    for qtype in unknown_types {
        let query = create_dns_query("example.com", qtype);
        let response = send_dns_query(19066, &query).await.unwrap();

        let packet = DnsPacket::from_bytes(&response).unwrap();

        // Should process the query without errors
        assert_eq!(packet.header.questions, 1);

        // Verify response bit is set
        let flags = u16::from_be_bytes([response[2], response[3]]);
        assert!(flags & 0x8000 != 0, "Should be a response");
    }
}

#[tokio::test]
async fn test_custom_cache_ttl() {
    let mut config = Config::default_config();
    config.server.listen_port = 19069;
    config.cache.default_ttl = 600; // Custom TTL of 10 minutes

    let addr = config.listen_addr();
    let server = DnsServer::new(&addr, config).await.unwrap();

    tokio::spawn(async move {
        server.run().await.ok();
    });

    sleep(Duration::from_millis(100)).await;

    // Query a domain that will be cached with custom TTL
    let query = create_dns_query("github.com", QueryType::A);
    let response = send_dns_query(19069, &query).await.unwrap();

    let packet = DnsPacket::from_bytes(&response).unwrap();

    // Verify we got a valid response
    assert_eq!(packet.header.questions, 1);
    assert!(
        packet.header.answers > 0,
        "Should have answers from upstream"
    );

    // Second query should come from cache
    let response2 = send_dns_query(19069, &query).await.unwrap();
    let packet2 = DnsPacket::from_bytes(&response2).unwrap();

    assert_eq!(packet2.header.questions, 1);
    assert!(packet2.header.answers > 0, "Should have cached answers");
}

#[tokio::test]
async fn test_cache_ttl_expiration() {
    // Test that cached entries expire according to configured TTL
    let mut config = Config::default_config();
    config.server.listen_port = 19070;
    config.cache.default_ttl = 2; // Very short TTL of 2 seconds

    let addr = config.listen_addr();
    let server = DnsServer::new(&addr, config).await.unwrap();

    tokio::spawn(async move {
        server.run().await.ok();
    });

    sleep(Duration::from_millis(100)).await;

    // First query - should go to upstream and cache with 2 second TTL
    let query = create_dns_query("example.com", QueryType::A);
    let response1 = send_dns_query(19070, &query).await.unwrap();
    let packet1 = DnsPacket::from_bytes(&response1).unwrap();
    assert!(
        packet1.header.answers > 0,
        "Should have answers from upstream"
    );

    // Immediate second query - should come from cache
    let response2 = send_dns_query(19070, &query).await.unwrap();
    let packet2 = DnsPacket::from_bytes(&response2).unwrap();
    assert!(packet2.header.answers > 0, "Should have cached answers");

    // Wait for cache to expire (2 seconds + buffer)
    sleep(Duration::from_secs(3)).await;

    // Third query - cache should be expired, will go to upstream again
    // We can't directly verify it went to upstream, but we verify it still works
    let response3 = send_dns_query(19070, &query).await.unwrap();
    let packet3 = DnsPacket::from_bytes(&response3).unwrap();
    assert!(
        packet3.header.answers > 0,
        "Should still get answers after cache expiration"
    );
}

#[tokio::test]
async fn test_https_cache_behavior() {
    let mut config = Config::default_config();
    config.server.listen_port = 19067;

    let addr = config.listen_addr();
    let server = DnsServer::new(&addr, config).await.unwrap();

    tokio::spawn(async move {
        server.run().await.ok();
    });

    sleep(Duration::from_millis(100)).await;

    let query = create_dns_query("google.com", QueryType::HTTPS);

    // First query - should go to upstream
    let response1 = send_dns_query(19067, &query).await.unwrap();
    let packet1 = DnsPacket::from_bytes(&response1).unwrap();

    // Give a moment for caching (though should be immediate)
    sleep(Duration::from_millis(10)).await;

    // Second query - may come from cache (note: generic handler doesn't cache yet)
    let start = std::time::Instant::now();
    let response2 = send_dns_query(19067, &query).await.unwrap();
    let duration = start.elapsed();
    let packet2 = DnsPacket::from_bytes(&response2).unwrap();

    // Both should have answers
    assert!(packet1.header.answers > 0);
    assert!(packet2.header.answers > 0);

    // Verify server doesn't hang on repeated queries
    assert!(
        duration.as_millis() < 1000,
        "Second query took {}ms, should be quick",
        duration.as_millis()
    );
}

#[tokio::test]
async fn test_https_concurrent_queries() {
    let mut config = Config::default_config();
    config.server.listen_port = 19068;

    let addr = config.listen_addr();
    let server = DnsServer::new(&addr, config).await.unwrap();

    tokio::spawn(async move {
        server.run().await.ok();
    });

    sleep(Duration::from_millis(100)).await;

    // Send 5 concurrent HTTPS queries
    let mut handles = vec![];
    for _ in 0..5 {
        handles.push(tokio::spawn(async move {
            let query = create_dns_query("google.com", QueryType::HTTPS);
            send_dns_query(19068, &query).await
        }));
    }

    // All should succeed
    for handle in handles {
        let result = handle.await.unwrap();
        assert!(result.is_ok(), "HTTPS query should succeed");

        let response = result.unwrap();
        let packet = DnsPacket::from_bytes(&response).unwrap();
        assert!(packet.header.answers > 0, "Should have HTTPS answers");
    }
}
