//! implementation of the snoop file format version 2.
//!
//! all integer values are stored in "big-endian" order, with the high-
//! order bits first.

/// size of the snoop header file format
pub const SNOOP_HEADER_SIZE: usize = 16; // bytes
/// magic bytes of a snoop file, in ascii "snoop"
pub const SNOOP_MAGIC: &[u8] = &[0x73, 0x6E, 0x6F, 0x6F, 0x70, 0x00, 0x00, 0x00];
/// snoop version, only version 2 is supported
pub const SNOOP_VERSION: &[u8] = &[0x00, 0x00, 0x00, 0x02];

/// size of the snoop packet header
pub const SNOOP_PACKET_HEADER_SIZE: usize = 24;
/// maximum supported capture len of packet data
pub const MAX_CAPTURE_LEN: u32 = 4096;
/// maximum supported pads that can be append to the packet data
pub const MAX_CAPTURE_PADS: u32 = 4;

/// type of the link where the package was captured.
#[allow(non_camel_case_types)]
#[derive(Debug, Default, PartialEq, Copy, Clone)]
#[allow(missing_docs)]
pub enum DataLinkType {
    #[allow(missing_docs)]
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
/// representing the file header with version and link type.
/// magic bytes are skipped
#[derive(Debug, Default)]
pub struct SnoopHeader {
    /// snoop version
    pub version: u32,
    /// captured link type
    pub link_type: DataLinkType,
}

/// contains the captured informations of the packet.
#[derive(Debug, Default, Clone)]
pub struct PacketHeader {
    /// OriginalLength uint32 4
    pub original_length: u32,
    /// IncludedLength uint32 8
    pub included_length: u32,
    /// PacketRecordLength uint32 12
    pub packet_record_length: u32,
    /// CumulativeDrops uint32 16
    pub cumulative_drops: u32,
    /// TimestampSeconds uint32 20
    pub timestamp_seconds: u32,
    /// TimestampMicroseconds uint32 24
    pub timestamp_microseconds: u32,
}

/// represents the captured packet as header and data.
pub struct SnoopPacket {
    /// packet header
    pub header: PacketHeader,
    /// packet data
    pub data: Vec<u8>,
}

/// reference to the captured packet as header and data.
/// if read function is called again, this data will be overwritten.
pub struct SnoopPacketRef<'a> {
    /// packet header reference to the internal buffer
    pub header: &'a PacketHeader,
    /// packet data reference to the internal buffer
    pub data: &'a [u8],
}
