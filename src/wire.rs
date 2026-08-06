// SPDX-License-Identifier: LGPL-2.1-or-later
use std::error::Error;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const DNS_HEADER_LEN: usize = 12;
pub const CLASS_IN: u16 = 1;
pub const CLASS_ANY: u16 = 255;
pub const TYPE_A: u16 = 1;
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_SOA: u16 = 6;
pub const TYPE_PTR: u16 = 12;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_OPT: u16 = 41;
pub const TYPE_TSIG: u16 = 250;

const FLAG_QR: u16 = 0x8000;
const FLAG_OPCODE: u16 = 0x7800;
const FLAG_AA: u16 = 0x0400;
const FLAG_TC: u16 = 0x0200;
const FLAG_RD: u16 = 0x0100;
const FLAG_RA: u16 = 0x0080;
const FLAG_CD: u16 = 0x0010;
const RCODE_MASK: u16 = 0x000f;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    pub id: u16,
    pub flags: u16,
    pub question_count: u16,
    pub answer_count: u16,
    pub authority_count: u16,
    pub additional_count: u16,
}

impl Header {
    pub fn parse(packet: &[u8]) -> Result<Self, WireError> {
        if packet.len() < DNS_HEADER_LEN {
            return Err(WireError::ShortPacket);
        }
        Ok(Self {
            id: read_u16(packet, 0)?,
            flags: read_u16(packet, 2)?,
            question_count: read_u16(packet, 4)?,
            answer_count: read_u16(packet, 6)?,
            authority_count: read_u16(packet, 8)?,
            additional_count: read_u16(packet, 10)?,
        })
    }

    pub const fn is_response(self) -> bool {
        self.flags & FLAG_QR != 0
    }

    pub const fn truncated(self) -> bool {
        self.flags & FLAG_TC != 0
    }

    pub const fn response_code(self) -> u16 {
        self.flags & RCODE_MASK
    }

    pub const fn checking_disabled(self) -> bool {
        self.flags & FLAG_CD != 0
    }

    pub const fn opcode(self) -> u16 {
        (self.flags & FLAG_OPCODE) >> 11
    }

    pub fn total_records(self) -> usize {
        usize::from(self.answer_count)
            + usize::from(self.authority_count)
            + usize::from(self.additional_count)
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct DnsName {
    text: String,
    canonical_wire: Vec<u8>,
}

impl DnsName {
    pub fn text(&self) -> &str {
        &self.text
    }

    pub fn canonical_wire(&self) -> &[u8] {
        &self.canonical_wire
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Question {
    pub name: DnsName,
    pub rr_type: u16,
    pub class: u16,
    pub next_offset: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceRecord {
    pub name: DnsName,
    pub rr_type: u16,
    pub class: u16,
    pub ttl: u32,
    pub ttl_offset: usize,
    pub rdata_offset: usize,
    pub rdata: Vec<u8>,
    pub next_offset: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LocalRecord {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Ptr(String),
}

impl LocalRecord {
    const fn rr_type(&self) -> u16 {
        match self {
            Self::A(_) => TYPE_A,
            Self::Aaaa(_) => TYPE_AAAA,
            Self::Ptr(_) => TYPE_PTR,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WireError {
    ShortPacket,
    InvalidLabel,
    CompressionLoop,
    NameTooLong,
    TrailingData,
    WrongDirection,
    UnsupportedOpcode(u16),
    WrongQuestionCount(u16),
    NoQuestion,
    QuestionMismatch,
    InvalidName(String),
    InvalidRecord,
    ResponseTooLarge,
}

impl fmt::Display for WireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShortPacket => formatter.write_str("short DNS packet"),
            Self::InvalidLabel => formatter.write_str("invalid DNS label"),
            Self::CompressionLoop => formatter.write_str("DNS compression loop"),
            Self::NameTooLong => formatter.write_str("DNS name exceeds 255 wire octets"),
            Self::TrailingData => formatter.write_str("data follows the declared DNS sections"),
            Self::WrongDirection => formatter.write_str("unexpected DNS packet direction"),
            Self::UnsupportedOpcode(opcode) => write!(formatter, "unsupported DNS opcode {opcode}"),
            Self::WrongQuestionCount(count) => {
                write!(formatter, "DNS packet contains {count} questions")
            }
            Self::NoQuestion => formatter.write_str("DNS packet has no question"),
            Self::QuestionMismatch => {
                formatter.write_str("DNS response question does not match the query")
            }
            Self::InvalidName(name) => write!(formatter, "invalid DNS name: {name}"),
            Self::InvalidRecord => formatter.write_str("invalid DNS resource record"),
            Self::ResponseTooLarge => formatter.write_str("DNS response exceeds 65535 octets"),
        }
    }
}

impl Error for WireError {}

include!("wire/codec.rs");
include!("wire/packet.rs");
include!("wire/records.rs");
include!("wire/tests.rs");
