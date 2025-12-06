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

#[derive(Debug)]
#[derive(Default)]
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
        let mut bytes = Vec::new();

        // Encode domain name
        for label in self.name.split('.') {
            bytes.push(label.len() as u8);
            bytes.extend_from_slice(label.as_bytes());
        }
        bytes.push(0); // Null terminator

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
        let mut data = Vec::new();
        let ns_clean = nameserver.trim_end_matches('.');
        for label in ns_clean.split('.') {
            if !label.is_empty() {
                data.push(label.len() as u8);
                data.extend_from_slice(label.as_bytes());
            }
        }
        data.push(0); // Null terminator

        DnsAnswer {
            name,
            qtype: QueryType::NS,
            qclass: 1,
            ttl,
            data,
        }
    }

    pub fn new_cname_record(name: String, ttl: u32, cname: String) -> Self {
        let mut data = Vec::new();
        let cname_clean = cname.trim_end_matches('.');
        for label in cname_clean.split('.') {
            if !label.is_empty() {
                data.push(label.len() as u8);
                data.extend_from_slice(label.as_bytes());
            }
        }
        data.push(0); // Null terminator

        DnsAnswer {
            name,
            qtype: QueryType::CNAME,
            qclass: 1,
            ttl,
            data,
        }
    }

    pub fn new_ptr_record(name: String, ttl: u32, ptrdname: String) -> Self {
        let mut data = Vec::new();
        let ptr_clean = ptrdname.trim_end_matches('.');
        for label in ptr_clean.split('.') {
            if !label.is_empty() {
                data.push(label.len() as u8);
                data.extend_from_slice(label.as_bytes());
            }
        }
        data.push(0); // Null terminator

        DnsAnswer {
            name,
            qtype: QueryType::PTR,
            qclass: 1,
            ttl,
            data,
        }
    }

    pub fn new_mx_record(name: String, ttl: u32, priority: u16, exchange: String) -> Self {
        let mut data = Vec::new();
        data.extend_from_slice(&priority.to_be_bytes());
        let exchange_clean = exchange.trim_end_matches('.');
        for label in exchange_clean.split('.') {
            if !label.is_empty() {
                data.push(label.len() as u8);
                data.extend_from_slice(label.as_bytes());
            }
        }
        data.push(0); // Null terminator

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
        let mname_clean = mname.trim_end_matches('.');
        for label in mname_clean.split('.') {
            if !label.is_empty() {
                data.push(label.len() as u8);
                data.extend_from_slice(label.as_bytes());
            }
        }
        data.push(0);

        // Encode RNAME (responsible party email)
        let rname_clean = rname.trim_end_matches('.');
        for label in rname_clean.split('.') {
            if !label.is_empty() {
                data.push(label.len() as u8);
                data.extend_from_slice(label.as_bytes());
            }
        }
        data.push(0);

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
        let mut bytes = Vec::new();

        // Encode domain name
        for label in self.name.split('.') {
            bytes.push(label.len() as u8);
            bytes.extend_from_slice(label.as_bytes());
        }
        bytes.push(0); // Null terminator

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
