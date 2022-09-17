use std::{
    convert::TryInto,
    fmt::UpperHex,
    time::{Duration},
};
use tokio::{self, task::JoinHandle, time::timeout};
use bitvec::{prelude::*, view::BitView};
use rand;

const DNS_HEAER_SIZE: usize = 12;

#[derive(Debug)]
pub struct DNSQuery {
    header: Header,
    question: Question,
}

impl DNSQuery {
    pub fn new(domain: String, qtype: QueryType) -> Self {
        // 生成DNS 随机ID
        return DNSQuery {
            header: DNSQuery::build_header(),
            question: Question::new(domain, qtype),
        };
    }

    pub fn serialize(&self) -> Vec<u8> {
        let header_b = self.header.serialize();
        let question_b = self.question.serialize();

        let mut buf: Vec<u8> = Vec::with_capacity(header_b.len() + question_b.len());
        buf.extend(header_b);
        buf.extend(question_b);
        return buf;
    }

    fn build_header() -> Header {
        let id = rand::random::<u16>();
        return Header {
            ID: id,
            QR: false,
            Opcode: 0,
            AA: false,
            TC: false,
            RD: true,
            RA: false,
            Z: 0,
            RCODE: 0,
            QDCOUNT: 1,
            ANCOUNT: 0,
            NSCOUNT: 0,
            ARCOUNT: 0,
        };
    }

    pub async fn query(&self, duration: Duration) -> Result<DnsResp, String> {
        let client = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
            Ok(c) => c,
            Err(e) => return Err(e.to_string()),
        };
        match client.connect("8.8.8.8:53").await {
            Err(e) => return Err(e.to_string()),
            _ => (),
        };

        match client.send(self.serialize().as_mut_slice()).await {
            Err(e) => return Err(e.to_string()),
            _ => (),
        };

        let mut buf: Vec<u8> = vec![0; 512];

        let n_res = match timeout(duration, client.recv(&mut buf)).await {
            Ok(o) => o,
            Err(e) => return Err(e.to_string()),
        };
        let n = match n_res {
            Ok(n) => n,
            Err(e) => return Err(e.to_string()),
        };

        let resp = match DnsResp::parse(&buf[..n]) {
            Ok(r) => r,
            Err(e) => return Err(e),
        };

        return Ok(resp);
    }
}

pub struct DnsResp {
    // 保存的DNS包,由于DNS中域名大量使用偏移指针,取出RDATA需要对整个包寻址获取完整域名
    buf: Vec<u8>,
    header: Header,
    questions: Question,
    answers: Vec<ResourceRecord>,
}

impl DnsResp {
    fn parse(data: &[u8]) -> Result<DnsResp, String> {
        let header = Header::deserialize(data).unwrap();
        let mut end: usize = DNS_HEAER_SIZE;
        let mut ans: Vec<ResourceRecord> = Vec::with_capacity(header.ancount() as usize);
        let question = Question::deserialization(data, end.clone(), &mut end);
        for _ in 0..header.ancount() {
            ans.push(ResourceRecord::deserialization(data, end.clone(), &mut end).unwrap());
        }

        let dp = DnsResp {
            header: header,
            questions: question,
            answers: ans,
            buf: data.to_vec(),
        };
        return Ok(dp);
    }

    fn answers(&self) -> &[ResourceRecord] {
        self.answers.as_ref()
    }
}

#[derive(Debug)]
struct Header {
    // 16 bit
    ID: u16,
    // flag
    // 1 bit —— 0:查询,1:响应
    QR: bool,
    // 4 bit 0：标准查询
    Opcode: u8,
    // 1 bit
    AA: bool,
    TC: bool,
    RD: bool,
    RA: bool,
    // 3 bit
    Z: u8,
    // 4 bit
    RCODE: u8,
    // 16 bit
    QDCOUNT: u16,
    ANCOUNT: u16,
    NSCOUNT: u16,
    ARCOUNT: u16,
}

impl Header {
    fn serialize(&self) -> Vec<u8> {
        let mut res: Vec<u8> = Vec::with_capacity(DNS_HEAER_SIZE);
        res.extend(self.ID.to_be_bytes().iter());
        // QR/Opcode/AA/TC/RD/RA/Z/RCODE
        let mut flag = 0u16;
        // 大端bit操作 0x0100
        let flag_view = flag.view_bits_mut::<Msb0>();
        // Set flag
        flag_view.set(0, self.QR);
        // Opcode
        flag_view.set(1, false);
        flag_view.set(2, false);
        flag_view.set(3, false);
        flag_view.set(4, false);

        flag_view.set(5, self.AA);
        flag_view.set(6, self.TC);
        flag_view.set(7, self.RD);
        flag_view.set(8, self.RA);
        // Z
        flag_view.set(9, false);
        flag_view.set(10, false);
        flag_view.set(11, false);
        // RCODE
        flag_view.set(12, false);
        flag_view.set(13, false);
        flag_view.set(14, false);
        flag_view.set(15, false);

        res.extend(flag.to_be_bytes().iter());
        res.extend(self.QDCOUNT.to_be_bytes().iter());
        res.extend(self.ANCOUNT.to_be_bytes().iter());
        res.extend(self.NSCOUNT.to_be_bytes().iter());
        res.extend(self.ARCOUNT.to_be_bytes().iter());

        return res;
    }

    fn deserialize(data: &[u8]) -> Result<Header, String> {
        if data.len() < DNS_HEAER_SIZE {
            return Err(String::from("Header::deserialize size < Header Size"));
        }

        // id
        let mut index = 0;
        let id = u16::from_be_bytes(data[index..index + 2].try_into().unwrap());
        index += 2;
        // flag
        let flag = u16::from_be_bytes(data[index..index + 2].try_into().unwrap());
        index += 2;

        // QDCOUNT\ANCOUNT\NSCOUNT\ARCOUNT
        let qdcount = u16::from_be_bytes(data[index..index + 2].try_into().unwrap());
        index += 2;
        // ANCOUNT
        let ancount = u16::from_be_bytes(data[index..index + 2].try_into().unwrap());
        index += 2;

        // NSCOUNT
        let nscount = u16::from_be_bytes(data[index..index + 2].try_into().unwrap());
        index += 2;
        // ARCOUNT
        let arcount = u16::from_be_bytes(data[index..index + 2].try_into().unwrap());
        index += 2;

        let mut header = Header {
            ID: id,
            QR: false,
            Opcode: 0,
            AA: false,
            TC: false,
            RD: false,
            RA: false,
            Z: 0,
            RCODE: 0,
            QDCOUNT: qdcount,
            ANCOUNT: ancount,
            NSCOUNT: nscount,
            ARCOUNT: arcount,
        };
        header.parse_flag(flag);
        return Ok(header);
    }

    fn parse_flag(&mut self, flag: u16) {
        let flag_view = flag.view_bits::<Msb0>();
        let qr = *flag_view.get(0).as_deref().unwrap();

        let mut opcode = 0u8;
        let opcode_view = opcode.view_bits_mut::<Lsb0>();
        opcode_view.set(0, *flag_view.get(1).as_deref().unwrap());
        opcode_view.set(1, *flag_view.get(2).as_deref().unwrap());
        opcode_view.set(2, *flag_view.get(3).as_deref().unwrap());
        opcode_view.set(3, *flag_view.get(4).as_deref().unwrap());

        let aa = *flag_view.get(5).as_deref().unwrap();
        let tc = *flag_view.get(6).as_deref().unwrap();
        let rd = *flag_view.get(7).as_deref().unwrap();
        let ra = *flag_view.get(8).as_deref().unwrap();

        // 3bit
        let mut z = 0u8;
        let z_view = z.view_bits_mut::<Lsb0>();
        z_view.set(0, *flag_view.get(9).as_deref().unwrap());
        z_view.set(1, *flag_view.get(10).as_deref().unwrap());
        z_view.set(2, *flag_view.get(11).as_deref().unwrap());
        // 4bit
        let mut rcode = 0u8;
        let rcode_view = rcode.view_bits_mut::<Lsb0>();
        rcode_view.set(0, *flag_view.get(12).as_deref().unwrap());
        rcode_view.set(1, *flag_view.get(13).as_deref().unwrap());
        rcode_view.set(2, *flag_view.get(14).as_deref().unwrap());
        rcode_view.set(3, *flag_view.get(15).as_deref().unwrap());

        self.QR = qr;
        self.Opcode = opcode;
        self.AA = aa;
        self.TC = tc;
        self.RD = rd;
        self.RA = ra;
        self.Z = z;
        self.RCODE = rcode;
    }

    pub fn qdcount(&self) -> u16 {
        self.QDCOUNT
    }

    pub fn ancount(&self) -> u16 {
        self.ANCOUNT
    }
}

#[derive(Debug)]
pub enum QueryType {
    A,
    NS,
    CNAME,
    SOA,
    WKS,
    PTR,
    HINFO,
    MX,
    AAAA,
    AXFR,
    ANY,
    UNKNOWN,
}

impl QueryType {
    fn qtype_as_u16(qtype: &QueryType) -> u16 {
        return match qtype {
            QueryType::A => 1,
            QueryType::NS => 2,
            QueryType::CNAME => 5,
            QueryType::SOA => 6,
            QueryType::WKS => 11,
            QueryType::PTR => 12,
            QueryType::HINFO => 13,
            QueryType::MX => 15,
            QueryType::AAAA => 28,
            QueryType::AXFR => 252,
            QueryType::ANY => 255,
            _ => 256,
        };
    }

    fn u16_as_qtype(qtype: u16) -> QueryType {
        return match qtype {
            1 => QueryType::A,
            2 => QueryType::NS,
            5 => QueryType::CNAME,
            6 => QueryType::SOA,
            11 => QueryType::WKS,
            12 => QueryType::PTR,
            13 => QueryType::HINFO,
            15 => QueryType::MX,
            28 => QueryType::AAAA,
            252 => QueryType::AXFR,
            255 => QueryType::ANY,
            _ => QueryType::UNKNOWN,
        };
    }
}

#[derive(Debug)]
struct Question {
    // 长度不定，格式：例www.google.com => 3www6google3com
    QNAME: String,
    QTYPE: QueryType,
    QCLASS: u16,
}

impl Question {
    fn new(domain: String, qtype: QueryType) -> Self {
        return Self {
            QNAME: domain,
            QTYPE: qtype,
            QCLASS: 1,
        };
    }

    fn fmt_domain(&self) -> Vec<u8> {
        // www.qq.com -> 3www2qq3com 其中的数字占一个字节而不是字符
        let mut s: Vec<u8> = Vec::new();
        let strs: Vec<&str> = self.QNAME.split(".").collect();
        for ss in strs {
            s.push(ss.len() as u8);
            s.extend(ss.as_bytes());
        }
        return s;
    }

    fn domain2str(b: &[u8]) -> String {
        let mut s = String::from("");
        let mut c = 0;
        let mut should_parse_num = true;
        for i in b.iter() {
            if *i == 0x00 {
                break;
            }
            if should_parse_num {
                c = *i;
                should_parse_num = false;
                continue;
            }
            s.push(*i as char);
            c -= 1;
            if c <= 0 && *i != 0x00 {
                s.push('.');
                should_parse_num = true;
            }
        }
        // 移除最后一个.
        s.remove(s.len() - 1);
        return s;
    }

    fn serialize(&self) -> Vec<u8> {
        let mut res: Vec<u8> = Vec::new();
        res.extend(self.fmt_domain());
        // 结束符
        res.push(0);

        res.extend(QueryType::qtype_as_u16(&self.QTYPE).to_be_bytes());
        res.extend(self.QCLASS.to_be_bytes());
        return res;
    }

    fn deserialization(data: &[u8], start: usize, end: &mut usize) -> Question {
        let mut index = start;
        while index < data.len() {
            if data[index] == 0x00 {
                break;
            }
            index += 1;
        }
        let name = Question::domain2str(&data[start..index]);
        index += 1;
        // qtype
        let qtype = u16::from_be_bytes(data[index..index + 2].try_into().unwrap());
        index += 2;

        // qclass
        let qclass = u16::from_be_bytes(data[index..index + 2].try_into().unwrap());
        index += 2;

        *end = index;

        return Question {
            QNAME: name,
            QTYPE: QueryType::u16_as_qtype(qtype),
            QCLASS: qclass,
        };
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum RRType {
    A,     //     1 a host address
    NS,    //     2 an authoritative name server
    MD,    //     3 a mail destination (Obsolete - use MX)
    MF,    //     4 a mail forwarder (Obsolete - use MX)
    CNAME, //     5 the canonical name for an alias
    SOA,   //     6 marks the start of a zone of authority
    MB,    //     7 a mailbox domain name (EXPERIMENTAL)
    MG,    //     8 a mail group member (EXPERIMENTAL)
    MR,    //     9 a mail rename domain name (EXPERIMENTAL)
    NULL,  //     10 a null RR (EXPERIMENTAL)
    WKS,   //     11 a well known service description
    PTR,   //     12 a domain name pointer
    HINFO, //     13 host information
    MINFO, //     14 mailbox or mail list information
    MX,    //     15 mail exchange
    TXT,   //     16 text strings
    UNKNOWN,
}

impl RRType {
    fn u16_to_rrtype(rrtype: u16) -> RRType {
        match rrtype {
            1 => RRType::A,
            2 => RRType::NS,
            3 => RRType::MD,
            4 => RRType::MF,
            5 => RRType::CNAME,
            6 => RRType::SOA,
            7 => RRType::MB,
            8 => RRType::MG,
            9 => RRType::MR,
            10 => RRType::NULL,
            11 => RRType::WKS,
            12 => RRType::PTR,
            13 => RRType::HINFO,
            14 => RRType::MINFO,
            15 => RRType::MX,
            16 => RRType::TXT,
            _ => RRType::UNKNOWN,
        }
    }

    fn rrtype_to_u16(rrtype: &RRType) -> u16 {
        return match rrtype {
            RRType::A => 1,
            RRType::NS => 2,
            RRType::MD => 3,
            RRType::MF => 4,
            RRType::CNAME => 5,
            RRType::SOA => 6,
            RRType::MB => 7,
            RRType::MG => 8,
            RRType::MR => 9,
            RRType::NULL => 10,
            RRType::WKS => 11,
            RRType::PTR => 12,
            RRType::HINFO => 13,
            RRType::MINFO => 14,
            RRType::MX => 15,
            RRType::TXT => 16,
            RRType::UNKNOWN => 256,
        };
    }
}

#[derive(Debug)]
struct ResourceRecord {
    NAME: String,
    // 16 bit
    TYPE: RRType,
    CLASS: u16,
    TTL: i32,
    RDLENGTH: u16,
    // offset of dns packet
    RDATA: usize,
}

impl ResourceRecord {
    // data: 完整DNS包数据
    // start: ResourceRecord开始解析的位置
    // end: 用于定位下一个ResourceRecord解析开始的位置(即是下一个ResourceRecord的start)
    fn deserialization(
        data: &[u8],
        start: usize,
        end: &mut usize,
    ) -> Result<ResourceRecord, String> {
        // DNS协议消息压缩技术
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // | 1  1|                OFFSET                   |
        // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        // 最开始的两个bit必须都为1，目的是为了避免混淆。后面的14bit表示字符串在整个DNS消息包中的偏移量
        if data[start] != 0xc0 {
            return Err(String::from("ResourceRecord::deserialization format error"));
        }

        let mut index = start;
        // Name
        let name_offset_u8: [u8; 2] = match data[index..index + 2].try_into() {
            Ok(s) => s,
            Err(e) => return Err(e.to_string()),
        };
        let name_offset = ResourceRecord::name_offset(&mut u16::from_be_bytes(name_offset_u8));
        // let name = Question::domain2str(&data[name_offset..]);
        let name = ResourceRecord::domain2str(data, name_offset);
        index += 2;
        // type
        let rrtype_u8: [u8; 2] = match data[index..index + 2].try_into() {
            Ok(s) => s,
            Err(e) => return Err(e.to_string()),
        };
        index += 2;
        let rrtype = RRType::u16_to_rrtype(u16::from_be_bytes(rrtype_u8));

        // class
        let class_u8: [u8; 2] = match data[index..index + 2].try_into() {
            Ok(s) => s,
            Err(e) => return Err(e.to_string()),
        };
        index += 2;
        let class = u16::from_be_bytes(class_u8);

        // ttl
        let ttl_u8: [u8; 4] = match data[index..index + 4].try_into() {
            Ok(s) => s,
            Err(e) => return Err(e.to_string()),
        };
        index += 4;
        let ttl = i32::from_be_bytes(ttl_u8);

        // rdlength
        let rdlength_u8: [u8; 2] = match data[index..index + 2].try_into() {
            Ok(s) => s,
            Err(e) => return Err(e.to_string()),
        };
        index += 2;
        let rdlength = u16::from_be_bytes(rdlength_u8);

        // rdata
        // let mut rdata: Vec<u8> = Vec::with_capacity(rdlength as usize);
        // rdata.extend(data[index..(index + rdlength as usize)].iter());
        // index += rdlength as usize;

        // end
        *end = index + (rdlength as usize);

        let r = ResourceRecord {
            NAME: name,
            // 16 bit
            TYPE: rrtype,
            CLASS: class,
            TTL: ttl,
            RDLENGTH: rdlength,
            RDATA: index,
        };
        return Ok(r);
    }

    fn name_offset(flag: &mut u16) -> usize {
        let v = flag.view_bits_mut::<Msb0>();
        v.set(0, false);
        v.set(1, false);
        return *flag as usize;
    }

    fn to_A(&self, data: &[u8]) -> Result<ARDATA, String> {
        return ARDATA::build(data, self.RDATA, self.RDLENGTH as usize);
    }

    fn to_CNAME(&self, data: &[u8]) -> Result<CNAME, String> {
        return CNAME::build(data, self.RDATA);
    }

    fn is_compression_prefix(n: u8) -> bool {
        let n_view = n.view_bits::<Msb0>();
        let n1 = *n_view.get(0).unwrap().as_ref();
        let n2 = *n_view.get(1).unwrap().as_ref();
        return n1 && n2;
    }

    // Question::domain2str未考虑到dns压缩后缀（例如a.w.bilicdn1.com 压缩成 a.w.bilicdn1 0xc019,0xc019为后缀在DNS包中的偏移），因此重新实现
    fn domain2str(b: &[u8], offset: usize) -> String {
        let mut i = offset;

        let mut s = String::from("");
        let mut c = 0;
        let mut should_parse_num = true;
        let mut meet_compression_prefix = false;
        while i < b.len() {
            meet_compression_prefix = ResourceRecord::is_compression_prefix(b[i]);
            if b[i] == 0x00 || meet_compression_prefix {
                break;
            }
            if should_parse_num {
                c = b[i];
                should_parse_num = false;

                i += 1;
                continue;
            }
            s.push(b[i] as char);
            c -= 1;
            if c <= 0 {
                s.push('.');
                should_parse_num = true;
            }
            i += 1;
        }

        if meet_compression_prefix {
            let mut offset_flag = u16::from_be_bytes(b[i..i + 2].try_into().unwrap());
            let offset_other = ResourceRecord::name_offset(&mut offset_flag);
            s.push_str(ResourceRecord::domain2str(b, offset_other).as_str());
        }

        // 移除最后一个.
        if s.as_bytes()[s.len() - 1] == ('.' as u8) {
            s.remove(s.len() - 1);
        }
        return s;
    }
}

#[derive(Debug)]
pub struct ARDATA {
    address: Vec<u8>,
}
impl ARDATA {
    fn build(data: &[u8], offset: usize, length: usize) -> Result<ARDATA, String> {
        if length != 4 {
            return Err(String::from("ARDATA::build => data.len != 4"));
        }
        let r = ARDATA {
            address: data[offset..offset + length].to_vec(),
        };
        return Ok(r);
    }

    fn ipv4_to_str(&self) -> String {
        let mut s = String::from("");
        for u in self.address.iter() {
            s.push_str(u.to_string().as_str());
            s.push('.');
        }
        s.remove(s.len() - 1);
        return s;
    }
}

pub struct CNAME {
    cname: String,
}

impl CNAME {
    fn build(data: &[u8], offset: usize) -> Result<CNAME, String> {
        return Ok(CNAME {
            cname: ResourceRecord::domain2str(data, offset),
        });
    }
}

fn print_x16<T: UpperHex>(num: &T) {
    println!("0x{:X} ", num);
}

fn print_8bit(n: u8) {
    let mut i = 0;
    while i < 8 {
        print!("0x{:X} ", (n >> i) & 1);
        i += 1;
    }
    print!("\n");
}

fn print_16bit(n: u16) {
    let mut i = 0;
    while i < 16 {
        print!("0x{:X} ", (n >> i) & 1);
        i += 1;
    }
    print!("\n");
}

#[test]
fn test_domain2str() {
    let mut v = vec![
        0x03, 0x77, 0x77, 0x77, 0x02, 0x71, 0x71, 0x03, 0x63, 0x6f, 0x6d, 0x00,
    ];
    print!("{}\n", Question::domain2str(v.as_slice()));
}
#[test]
fn test_name_offset() {
    let v = vec![0xc0, 0x0c];
    print!(
        "{}\n",
        ResourceRecord::name_offset(&mut u16::from_be_bytes(v.as_slice().try_into().unwrap()))
    );
}
#[test]
fn test_parse_flag() {
    let mut flag = 0x8180u16;
    let mut flag_view = flag.view_bits::<Msb0>();
    let qr = *flag_view.get(0).as_deref().unwrap();

    let mut opcode = 0u8;
    let mut opcode_view = opcode.view_bits_mut::<Lsb0>();
    opcode_view.set(0, *flag_view.get(1).as_deref().unwrap());
    opcode_view.set(1, *flag_view.get(2).as_deref().unwrap());
    opcode_view.set(2, *flag_view.get(3).as_deref().unwrap());
    opcode_view.set(3, *flag_view.get(4).as_deref().unwrap());

    let aa = *flag_view.get(5).as_deref().unwrap();
    let tc = *flag_view.get(6).as_deref().unwrap();
    let rd = *flag_view.get(7).as_deref().unwrap();
    let ra = *flag_view.get(8).as_deref().unwrap();

    // 3bit
    let mut z = 0u8;
    let z_view = z.view_bits_mut::<Lsb0>();
    z_view.set(0, *flag_view.get(9).as_deref().unwrap());
    z_view.set(1, *flag_view.get(10).as_deref().unwrap());
    z_view.set(2, *flag_view.get(11).as_deref().unwrap());
    // 4bit
    let mut rcode = 0u8;
    let rcode_view = rcode.view_bits_mut::<Lsb0>();
    rcode_view.set(0, *flag_view.get(12).as_deref().unwrap());
    rcode_view.set(1, *flag_view.get(13).as_deref().unwrap());
    rcode_view.set(2, *flag_view.get(14).as_deref().unwrap());
    rcode_view.set(3, *flag_view.get(15).as_deref().unwrap());

    print!("qr:{}\n", qr);
    print!("opcode:{}\n", opcode);
    print!("aa:{}\n", aa);
    print!("tc:{}\n", tc);
    print!("rd:{}\n", rd);
    print!("ra:{}\n", ra);
    print!("z:{}\n", z);
    print!("rcode:{}\n", rcode);
}
#[test]
fn test_u82str() {
    let v = vec![121u8, 14, 77, 221];
    let mut s = String::from("");
    for u in v {
        s.push_str(u.to_string().as_str());
        s.push('.');
    }
    s.remove(s.len() - 1);
    print!("{}\n", s);
}
#[test]
fn test_dnsclient() {
    let mut rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .thread_name("rt")
        .thread_stack_size(1024 * 512)
        .enable_all()
        .build()
        .unwrap();

    // let q = DNSQuery::new(String::from("www.csdn.com"), QueryType::A);
    let domains: Vec<&str> = vec![
        "www.baidu.com",
        "www.qq.com",
        "www.csdn.com",
        "www.bilibili.com",
        "www.bing.com",
    ];
    // let domains: Vec<&str> = vec!["www.bilibili.com"];
    let mut joins = Vec::new();

    for i in 0..domains.len() {
        let dm = domains[i].clone();
        let q = DNSQuery::new(String::from(dm), QueryType::A);
        let f = async move {
            print!("{} start\n", dm);
            let resp = match q.query(tokio::time::Duration::from_millis(1000)).await {
                Ok(r) => r,
                Err(e) => return print!("{}\n", e),
            };

            for rr in resp.answers {
                match rr.TYPE {
                    RRType::A => {
                        print!(
                            "Name: {} ipv4: {}\n",
                            rr.NAME,
                            rr.to_A(resp.buf.as_slice()).unwrap().ipv4_to_str()
                        );
                    }
                    RRType::CNAME => {
                        print!(
                            "Name: {} CNAME: {}\n",
                            rr.NAME,
                            rr.to_CNAME(resp.buf.as_slice()).unwrap().cname
                        );
                    }
                    _ => (),
                }
            }
            print!("{} end\n", dm);
        };
        joins.push(rt.spawn(f));
    }

    let r = async {
        for j in joins {
            j.await.unwrap();
        }
    };

    rt.block_on(r);
}


