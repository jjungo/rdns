use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone)]
pub enum DnsParseError {
    BufferTooShort {
        needed: usize,
        available: usize,
    },
    #[allow(dead_code)]
    InvalidPointer {
        offset: usize,
    },
    LabelTooLong {
        length: usize,
    },
    OffsetOutOfBounds {
        offset: usize,
        buffer_len: usize,
    },
    #[allow(dead_code)]
    InvalidUtf8 {
        context: String,
    },
}

impl fmt::Display for DnsParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::BufferTooShort { needed, available } => {
                write!(
                    f,
                    "Buffer too short: needed {} bytes, available {}",
                    needed, available
                )
            }
            Self::InvalidPointer { offset } => {
                write!(f, "Invalid DNS pointer at offset {}", offset)
            }
            Self::LabelTooLong { length } => {
                write!(f, "DNS label too long: {} bytes (max 63)", length)
            }
            Self::OffsetOutOfBounds { offset, buffer_len } => {
                write!(
                    f,
                    "Offset {} out of bounds (buffer size: {})",
                    offset, buffer_len
                )
            }
            Self::InvalidUtf8 { context } => {
                write!(f, "Invalid UTF-8 in {}", context)
            }
        }
    }
}

impl std::error::Error for DnsParseError {}

// DNS Query Type Constants (RFC 1035)
pub const QTYPE_A: u16 = 1;
pub const QTYPE_NS: u16 = 2;
pub const QTYPE_CNAME: u16 = 5;
pub const QTYPE_SOA: u16 = 6;
pub const QTYPE_PTR: u16 = 12;
pub const QTYPE_MX: u16 = 15;
pub const QTYPE_TXT: u16 = 16;
pub const QTYPE_AAAA: u16 = 28;

// DNS Response Codes (RFC 1035 Section 4.1.1)
#[allow(dead_code)]
pub const RCODE_NO_ERROR: u16 = 0;
#[allow(dead_code)]
pub const RCODE_FORMAT_ERROR: u16 = 1;
pub const RCODE_SERVER_FAILURE: u16 = 2;
#[allow(dead_code)]
pub const RCODE_NAME_ERROR: u16 = 3;
#[allow(dead_code)]
pub const RCODE_NOT_IMPLEMENTED: u16 = 4;
#[allow(dead_code)]
pub const RCODE_REFUSED: u16 = 5;

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
            QTYPE_A => QueryType::A,
            QTYPE_NS => QueryType::NS,
            QTYPE_CNAME => QueryType::CNAME,
            QTYPE_SOA => QueryType::SOA,
            QTYPE_PTR => QueryType::PTR,
            QTYPE_MX => QueryType::MX,
            QTYPE_TXT => QueryType::TXT,
            QTYPE_AAAA => QueryType::AAAA,
            _ => QueryType::Unknown(num),
        }
    }
}

impl From<QueryType> for u16 {
    fn from(qtype: QueryType) -> Self {
        match qtype {
            QueryType::A => QTYPE_A,
            QueryType::NS => QTYPE_NS,
            QueryType::CNAME => QTYPE_CNAME,
            QueryType::SOA => QTYPE_SOA,
            QueryType::PTR => QTYPE_PTR,
            QueryType::MX => QTYPE_MX,
            QueryType::TXT => QTYPE_TXT,
            QueryType::AAAA => QTYPE_AAAA,
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

    pub fn from_bytes(buf: &[u8]) -> Result<Self, DnsParseError> {
        if buf.len() < 12 {
            return Err(DnsParseError::BufferTooShort {
                needed: 12,
                available: buf.len(),
            });
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

    pub fn set_rcode(&mut self, rcode: u16) {
        // Clear existing RCODE (last 4 bits of flags)
        self.flags &= 0xFFF0;
        // Set new RCODE
        self.flags |= rcode & 0x000F;
    }

    #[allow(dead_code)]
    pub fn get_rcode(&self) -> u16 {
        self.flags & 0x000F
    }
}

#[derive(Debug, Clone)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: QueryType,
    pub qclass: u16,
}

impl DnsQuestion {
    pub fn from_bytes(buf: &[u8], offset: usize) -> Result<(Self, usize), DnsParseError> {
        let (name, new_offset) = parse_domain_name(buf, offset)?;

        if new_offset + 4 > buf.len() {
            return Err(DnsParseError::BufferTooShort {
                needed: new_offset + 4,
                available: buf.len(),
            });
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
    pub fn from_bytes(buf: &[u8]) -> Result<Self, DnsParseError> {
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

fn parse_domain_name(buf: &[u8], mut offset: usize) -> Result<(String, usize), DnsParseError> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut jump_offset = 0;

    loop {
        if offset >= buf.len() {
            return Err(DnsParseError::OffsetOutOfBounds {
                offset,
                buffer_len: buf.len(),
            });
        }

        let len = buf[offset] as usize;

        // Check for pointer (compression)
        if (len & 0xC0) == 0xC0 {
            if offset + 1 >= buf.len() {
                return Err(DnsParseError::BufferTooShort {
                    needed: offset + 2,
                    available: buf.len(),
                });
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

        if len > 63 {
            return Err(DnsParseError::LabelTooLong { length: len });
        }

        if offset + len > buf.len() {
            return Err(DnsParseError::BufferTooShort {
                needed: offset + len,
                available: buf.len(),
            });
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

    #[test]
    fn test_rcode_set_and_get() {
        let mut header = DnsHeader::default();

        // Initially should be RCODE_NO_ERROR (0)
        assert_eq!(header.get_rcode(), RCODE_NO_ERROR);

        // Set SERVFAIL
        header.set_rcode(RCODE_SERVER_FAILURE);
        assert_eq!(header.get_rcode(), RCODE_SERVER_FAILURE);

        // Set NAME_ERROR
        header.set_rcode(RCODE_NAME_ERROR);
        assert_eq!(header.get_rcode(), RCODE_NAME_ERROR);

        // Verify RCODE is properly masked (only 4 bits)
        header.set_rcode(0x1F); // Try to set more than 4 bits
        assert_eq!(header.get_rcode(), 0x0F); // Should be masked to 4 bits
    }

    #[test]
    fn test_rcode_doesnt_affect_other_flags() {
        let mut header = DnsHeader::default();

        // Set QR and RA bits
        header.set_response();
        header.set_recursion_available();

        let flags_before = header.flags;

        // Set RCODE
        header.set_rcode(RCODE_SERVER_FAILURE);

        // QR and RA bits should still be set
        assert_eq!(header.flags & 0x8000, 0x8000, "QR bit should still be set");
        assert_eq!(header.flags & 0x0080, 0x0080, "RA bit should still be set");
        assert_eq!(header.get_rcode(), RCODE_SERVER_FAILURE);

        // Upper bits should be unchanged
        assert_eq!(header.flags & 0xFFF0, flags_before & 0xFFF0);
    }

    #[test]
    fn test_parse_error_buffer_too_short() {
        let short_buf = vec![0, 1, 2, 3]; // Only 4 bytes
        let result = DnsHeader::from_bytes(&short_buf);
        assert!(result.is_err());
        match result.unwrap_err() {
            DnsParseError::BufferTooShort { needed, available } => {
                assert_eq!(needed, 12);
                assert_eq!(available, 4);
            }
            _ => panic!("Expected BufferTooShort error"),
        }
    }

    #[test]
    fn test_parse_error_label_too_long() {
        let mut buf = vec![0; 100];
        buf[0] = 65; // Label length > 63 (max is 63)
        let result = parse_domain_name(&buf, 0);
        assert!(result.is_err());
        match result.unwrap_err() {
            DnsParseError::LabelTooLong { length } => {
                assert_eq!(length, 65);
            }
            _ => panic!("Expected LabelTooLong error"),
        }
    }

    #[test]
    fn test_parse_error_display() {
        let err = DnsParseError::BufferTooShort {
            needed: 12,
            available: 4,
        };
        assert_eq!(
            err.to_string(),
            "Buffer too short: needed 12 bytes, available 4"
        );

        let err = DnsParseError::OffsetOutOfBounds {
            offset: 100,
            buffer_len: 50,
        };
        assert_eq!(
            err.to_string(),
            "Offset 100 out of bounds (buffer size: 50)"
        );
    }

    #[test]
    fn test_all_rcode_constants() {
        let mut header = DnsHeader::default();

        // Test all RCODE constants
        header.set_rcode(RCODE_NO_ERROR);
        assert_eq!(header.get_rcode(), 0);

        header.set_rcode(RCODE_FORMAT_ERROR);
        assert_eq!(header.get_rcode(), 1);

        header.set_rcode(RCODE_SERVER_FAILURE);
        assert_eq!(header.get_rcode(), 2);

        header.set_rcode(RCODE_NAME_ERROR);
        assert_eq!(header.get_rcode(), 3);

        header.set_rcode(RCODE_NOT_IMPLEMENTED);
        assert_eq!(header.get_rcode(), 4);

        header.set_rcode(RCODE_REFUSED);
        assert_eq!(header.get_rcode(), 5);
    }

    #[test]
    fn test_parse_error_invalid_pointer() {
        let err = DnsParseError::InvalidPointer { offset: 512 };
        assert_eq!(err.to_string(), "Invalid DNS pointer at offset 512");

        // Verify the error can be cloned and debugged
        let err_clone = err.clone();
        assert_eq!(format!("{:?}", err_clone), "InvalidPointer { offset: 512 }");
    }

    #[test]
    fn test_parse_error_invalid_utf8() {
        let err = DnsParseError::InvalidUtf8 {
            context: "TXT record".to_string(),
        };
        assert_eq!(err.to_string(), "Invalid UTF-8 in TXT record");

        // Verify std::error::Error trait is implemented
        let _err_trait: &dyn std::error::Error = &err;
    }

    #[test]
    fn test_parse_error_offset_out_of_bounds() {
        let err = DnsParseError::OffsetOutOfBounds {
            offset: 200,
            buffer_len: 100,
        };

        // Test that it can be used in Result context
        let result: Result<(), DnsParseError> = Err(err.clone());
        assert!(result.is_err());

        match result {
            Err(DnsParseError::OffsetOutOfBounds { offset, buffer_len }) => {
                assert_eq!(offset, 200);
                assert_eq!(buffer_len, 100);
            }
            _ => panic!("Expected OffsetOutOfBounds error"),
        }
    }
}
