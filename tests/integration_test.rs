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
