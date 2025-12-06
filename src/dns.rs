use std::net::{Ipv4Addr, Ipv6Addr};

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone, Copy)]
pub enum QueryType {
    A,
    NS,
    CNAME,
    SOA,
    PTR,
    MX,
    TXT,
    AAAA,
    Unknown(u16),
}

impl From<u16> for QueryType {
    fn from(num: u16) -> Self {
        match num {
            1 => QueryType::A,
            2 => QueryType::NS,
            5 => QueryType::CNAME,
            6 => QueryType::SOA,
            12 => QueryType::PTR,
            15 => QueryType::MX,
            16 => QueryType::TXT,
            28 => QueryType::AAAA,
            _ => QueryType::Unknown(num),
        }
    }
}

impl From<QueryType> for u16 {
    fn from(qtype: QueryType) -> Self {
        match qtype {
            QueryType::A => 1,
            QueryType::NS => 2,
            QueryType::CNAME => 5,
            QueryType::SOA => 6,
            QueryType::PTR => 12,
            QueryType::MX => 15,
            QueryType::TXT => 16,
            QueryType::AAAA => 28,
            QueryType::Unknown(x) => x,
        }
    }
}

#[derive(Debug, Default)]
pub struct DnsHeader {
    pub id: u16,
    pub flags: u16,
    pub questions: u16,
    pub answers: u16,
    pub authority: u16,
    pub additional: u16,
}

impl DnsHeader {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self, String> {
        if buf.len() < 12 {
            return Err("Buffer too short for DNS header".to_string());
        }

        Ok(DnsHeader {
            id: u16::from_be_bytes([buf[0], buf[1]]),
            flags: u16::from_be_bytes([buf[2], buf[3]]),
            questions: u16::from_be_bytes([buf[4], buf[5]]),
            answers: u16::from_be_bytes([buf[6], buf[7]]),
            authority: u16::from_be_bytes([buf[8], buf[9]]),
            additional: u16::from_be_bytes([buf[10], buf[11]]),
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.id.to_be_bytes());
        bytes.extend_from_slice(&self.flags.to_be_bytes());
        bytes.extend_from_slice(&self.questions.to_be_bytes());
        bytes.extend_from_slice(&self.answers.to_be_bytes());
        bytes.extend_from_slice(&self.authority.to_be_bytes());
        bytes.extend_from_slice(&self.additional.to_be_bytes());
        bytes
    }

    pub fn set_response(&mut self) {
        self.flags |= 0x8000; // Set QR bit to 1 (response)
    }

    pub fn set_recursion_available(&mut self) {
        self.flags |= 0x0080; // Set RA bit
    }
}

#[derive(Debug, Clone)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: QueryType,
    pub qclass: u16,
}

impl DnsQuestion {
    pub fn from_bytes(buf: &[u8], offset: usize) -> Result<(Self, usize), String> {
        let (name, new_offset) = parse_domain_name(buf, offset)?;

        if new_offset + 4 > buf.len() {
            return Err("Buffer too short for question type and class".to_string());
        }

        let qtype = QueryType::from(u16::from_be_bytes([buf[new_offset], buf[new_offset + 1]]));
        let qclass = u16::from_be_bytes([buf[new_offset + 2], buf[new_offset + 3]]);

        Ok((
            DnsQuestion {
                name,
                qtype,
                qclass,
            },
            new_offset + 4,
        ))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = encode_domain_name(&self.name);
        bytes.extend_from_slice(&u16::from(self.qtype).to_be_bytes());
        bytes.extend_from_slice(&self.qclass.to_be_bytes());
        bytes
    }
}

#[derive(Debug)]
pub struct DnsAnswer {
    pub name: String,
    pub qtype: QueryType,
    pub qclass: u16,
    pub ttl: u32,
    pub data: Vec<u8>,
}

impl DnsAnswer {
    pub fn new_a_record(name: String, ttl: u32, ip: Ipv4Addr) -> Self {
        DnsAnswer {
            name,
            qtype: QueryType::A,
            qclass: 1,
            ttl,
            data: ip.octets().to_vec(),
        }
    }

    pub fn new_aaaa_record(name: String, ttl: u32, ip: Ipv6Addr) -> Self {
        DnsAnswer {
            name,
            qtype: QueryType::AAAA,
            qclass: 1,
            ttl,
            data: ip.octets().to_vec(),
        }
    }

    pub fn new_ns_record(name: String, ttl: u32, nameserver: String) -> Self {
        DnsAnswer {
            name,
            qtype: QueryType::NS,
            qclass: 1,
            ttl,
            data: encode_domain_name(&nameserver),
        }
    }

    pub fn new_cname_record(name: String, ttl: u32, cname: String) -> Self {
        DnsAnswer {
            name,
            qtype: QueryType::CNAME,
            qclass: 1,
            ttl,
            data: encode_domain_name(&cname),
        }
    }

    pub fn new_ptr_record(name: String, ttl: u32, ptrdname: String) -> Self {
        DnsAnswer {
            name,
            qtype: QueryType::PTR,
            qclass: 1,
            ttl,
            data: encode_domain_name(&ptrdname),
        }
    }

    pub fn new_mx_record(name: String, ttl: u32, priority: u16, exchange: String) -> Self {
        let mut data = Vec::new();
        data.extend_from_slice(&priority.to_be_bytes());
        data.extend_from_slice(&encode_domain_name(&exchange));

        DnsAnswer {
            name,
            qtype: QueryType::MX,
            qclass: 1,
            ttl,
            data,
        }
    }

    pub fn new_txt_record(name: String, ttl: u32, text: String) -> Self {
        let mut data = Vec::new();
        // TXT records are length-prefixed strings
        // Split into chunks of max 255 bytes if needed
        let text_bytes = text.as_bytes();
        let mut offset = 0;

        while offset < text_bytes.len() {
            let chunk_len = std::cmp::min(255, text_bytes.len() - offset);
            data.push(chunk_len as u8);
            data.extend_from_slice(&text_bytes[offset..offset + chunk_len]);
            offset += chunk_len;
        }

        DnsAnswer {
            name,
            qtype: QueryType::TXT,
            qclass: 1,
            ttl,
            data,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_soa_record(
        name: String,
        ttl: u32,
        mname: String,
        rname: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    ) -> Self {
        let mut data = Vec::new();

        // Encode MNAME (primary name server)
        data.extend_from_slice(&encode_domain_name(&mname));

        // Encode RNAME (responsible party email)
        data.extend_from_slice(&encode_domain_name(&rname));

        // Add SOA fields
        data.extend_from_slice(&serial.to_be_bytes());
        data.extend_from_slice(&refresh.to_be_bytes());
        data.extend_from_slice(&retry.to_be_bytes());
        data.extend_from_slice(&expire.to_be_bytes());
        data.extend_from_slice(&minimum.to_be_bytes());

        DnsAnswer {
            name,
            qtype: QueryType::SOA,
            qclass: 1,
            ttl,
            data,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = encode_domain_name(&self.name);
        bytes.extend_from_slice(&u16::from(self.qtype).to_be_bytes());
        bytes.extend_from_slice(&self.qclass.to_be_bytes());
        bytes.extend_from_slice(&self.ttl.to_be_bytes());
        bytes.extend_from_slice(&(self.data.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&self.data);
        bytes
    }
}

pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsAnswer>,
}

impl DnsPacket {
    pub fn from_bytes(buf: &[u8]) -> Result<Self, String> {
        let header = DnsHeader::from_bytes(buf)?;

        let mut offset = 12;
        let mut questions = Vec::new();

        for _ in 0..header.questions {
            let (question, new_offset) = DnsQuestion::from_bytes(buf, offset)?;
            questions.push(question);
            offset = new_offset;
        }

        Ok(DnsPacket {
            header,
            questions,
            answers: Vec::new(),
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.header.to_bytes();

        for question in &self.questions {
            bytes.extend_from_slice(&question.to_bytes());
        }

        for answer in &self.answers {
            bytes.extend_from_slice(&answer.to_bytes());
        }

        bytes
    }
}

/// Encode a domain name into DNS wire format (length-prefixed labels)
fn encode_domain_name(domain: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    let domain_clean = domain.trim_end_matches('.');
    for label in domain_clean.split('.') {
        if !label.is_empty() {
            bytes.push(label.len() as u8);
            bytes.extend_from_slice(label.as_bytes());
        }
    }
    bytes.push(0); // Null terminator
    bytes
}

fn parse_domain_name(buf: &[u8], mut offset: usize) -> Result<(String, usize), String> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut jump_offset = 0;

    loop {
        if offset >= buf.len() {
            return Err("Offset out of bounds".to_string());
        }

        let len = buf[offset] as usize;

        // Check for pointer (compression)
        if (len & 0xC0) == 0xC0 {
            if offset + 1 >= buf.len() {
                return Err("Buffer too short for pointer".to_string());
            }

            if !jumped {
                jump_offset = offset + 2;
            }

            let pointer = (len & 0x3F) << 8 | (buf[offset + 1] as usize);
            offset = pointer;
            jumped = true;
            continue;
        }

        offset += 1;

        if len == 0 {
            break;
        }

        if offset + len > buf.len() {
            return Err("Label length exceeds buffer".to_string());
        }

        let label = String::from_utf8_lossy(&buf[offset..offset + len]).to_string();
        labels.push(label);
        offset += len;
    }

    let name = labels.join(".");
    let final_offset = if jumped { jump_offset } else { offset };

    Ok((name, final_offset))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_domain_name() {
        let domain = "example.com";
        let mut expected = Vec::new();
        expected.push(7); // "example"
        expected.extend_from_slice(b"example");
        expected.push(3); // "com"
        expected.extend_from_slice(b"com");
        expected.push(0); // null terminator

        let question = DnsQuestion {
            name: domain.to_string(),
            qtype: QueryType::A,
            qclass: 1,
        };

        let bytes = question.to_bytes();
        assert_eq!(&bytes[..expected.len()], &expected[..]);
    }

    #[test]
    fn test_parse_domain_name() {
        let mut buf = Vec::new();
        buf.push(7); // "example"
        buf.extend_from_slice(b"example");
        buf.push(3); // "com"
        buf.extend_from_slice(b"com");
        buf.push(0); // null terminator

        let (name, offset) = parse_domain_name(&buf, 0).unwrap();
        assert_eq!(name, "example.com");
        assert_eq!(offset, buf.len());
    }

    #[test]
    fn test_dns_answer_a_record() {
        let answer =
            DnsAnswer::new_a_record("test.com".to_string(), 300, Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(answer.name, "test.com");
        assert_eq!(answer.ttl, 300);
        assert_eq!(answer.data, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_dns_answer_aaaa_record() {
        let answer = DnsAnswer::new_aaaa_record(
            "test.com".to_string(),
            300,
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
        );
        assert_eq!(answer.name, "test.com");
        assert_eq!(answer.ttl, 300);
        assert_eq!(answer.data.len(), 16);
    }

    #[test]
    fn test_dns_answer_ns_record() {
        let answer = DnsAnswer::new_ns_record(
            "example.com".to_string(),
            300,
            "ns1.example.com".to_string(),
        );
        let bytes = answer.to_bytes();
        // Should contain encoded domain names
        assert!(bytes.len() > 20);
    }

    #[test]
    fn test_dns_answer_mx_record() {
        let answer = DnsAnswer::new_mx_record(
            "example.com".to_string(),
            300,
            10,
            "mail.example.com".to_string(),
        );
        // First 2 bytes of data should be priority
        assert_eq!(answer.data[0..2], [0, 10]);
    }

    #[test]
    fn test_dns_answer_txt_record() {
        let text = "v=spf1 include:_spf.example.com ~all";
        let answer = DnsAnswer::new_txt_record("example.com".to_string(), 300, text.to_string());
        // First byte should be length
        assert_eq!(answer.data[0], text.len() as u8);
        assert_eq!(answer.data.len(), text.len() + 1); // +1 for length prefix
    }
}
