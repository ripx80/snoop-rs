/*
All integer values are stored in "big-endian" order, with the high-
order bits first.
*/

pub const SNOOP_HEADER_SIZE: usize = 16; // bytes
pub const SNOOP_MAGIC: &[u8] = &[0x73, 0x6E, 0x6F, 0x6F, 0x70, 0x00, 0x00, 0x00];
pub const SNOOP_VERSION: &[u8] = &[0x00, 0x00, 0x00, 0x02]; // only support version 2

pub const SNOOP_PACKET_HEADER_SIZE: usize = 24;
pub const MAX_CAPTURE_LEN: u32 = 4096;
pub const MAX_CAPTURE_PADS: u32 = 4;

#[allow(non_camel_case_types)]
#[derive(Debug, Default, PartialEq, Copy, Clone)] // realy need Copy, Clone here
pub enum DataLinkType {
    IEEE8023,
    TokenBus,
    TokenRing,
    MetroNet,
    Ethernet,
    Hdlc,
    CharacterSynchronous,
    IBM_C2C,
    Fddi,
    Other,
    #[default]
    Unassigned, // 10 - 4294967295
}

impl TryFrom<u32> for DataLinkType {
    type Error = ();
    fn try_from(v: u32) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(DataLinkType::IEEE8023),
            1 => Ok(DataLinkType::TokenBus),
            2 => Ok(DataLinkType::TokenRing),
            3 => Ok(DataLinkType::MetroNet),
            4 => Ok(DataLinkType::Ethernet),
            5 => Ok(DataLinkType::Hdlc),
            6 => Ok(DataLinkType::CharacterSynchronous),
            7 => Ok(DataLinkType::IBM_C2C),
            8 => Ok(DataLinkType::Fddi),
            9 => Ok(DataLinkType::Other),
            _ => Ok(DataLinkType::Unassigned),
        }
    }
}

#[derive(Debug, Default)]
pub struct SnoopHeader {
    pub version: u32,
    pub link_type: DataLinkType,
}

#[derive(Debug, Default, Clone)]
pub struct CapInfo {
    pub original_length: u32,        // 	OriginalLength        uint32	4
    pub included_length: u32,        // 	IncludedLength        uint32	8
    pub packet_record_length: u32,   // 	PacketRecordLength    uint32	12
    pub cumulative_drops: u32,       // 	CumulativeDrops       uint32	16
    pub timestamp_seconds: u32,      // 	TimestampSeconds      uint32	20
    pub timestamp_microseconds: u32, // 	TimestampMicroseconds uint32	24
}

pub struct SnoopPacket {
    pub ci: CapInfo,
    pub data: Vec<u8>,
}

pub struct SnoopPacketRef<'a> {
    pub ci: &'a CapInfo,
    pub data: &'a [u8],
}
