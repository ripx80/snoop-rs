//! parse snoop headers and calculate data len and pads.
use crate::format::{
    DataLinkType, PacketHeader, SnoopHeader, MAX_CAPTURE_LEN, SNOOP_HEADER_SIZE, SNOOP_MAGIC,
    SNOOP_PACKET_HEADER_SIZE, SNOOP_VERSION,
};
use crate::Error;

/// parse bytes as snoop format
#[derive(Debug)]
pub struct Parser;

impl Parser {
    /// parse the snoop file format header.
    /// each snoop file has one snoop header as the begining of the file.
    /// look for snoop magic bytes and return [`SnoopHeader`].
    /// # Errors
    /// will return [`Error::UnknownMagic`] if no magic bytes are present at the beginning
    /// will return [`Error::UnknownVersion`] if the version not match version 2
    #[allow(clippy::missing_panics_doc)]
    pub fn parse_header(buf: &[u8; SNOOP_HEADER_SIZE]) -> Result<SnoopHeader, Error> {
        if &buf[0..8] != SNOOP_MAGIC {
            return Err(Error::UnknownMagic);
        }

        if &buf[8..12] != SNOOP_VERSION {
            return Err(Error::UnknownVersion);
        }

        Ok(SnoopHeader {
            version: u32::from_be_bytes(buf[8..12].try_into().unwrap()),
            link_type: DataLinkType::try_from(u32::from_be_bytes(buf[12..16].try_into().unwrap()))
                .unwrap(),
        })
    }

    /// parse the snoop packet header and return captured information as [`PacketHeader`].
    /// each captured packet has a packet header.
    /// # Errors
    /// will return [`Error::OriginalLenExceeded`] if the maximium original len is exceeded.
    /// will return [`Error::CaptureLenExeeded`] if the supported capture len is exceeded.
    /// will return [`Error::InvalidRecordLength`] if the record length is invalid
    #[allow(clippy::missing_panics_doc)]
    #[allow(clippy::cast_possible_truncation)]
    pub fn parse_packet_header(
        buf: &[u8; SNOOP_PACKET_HEADER_SIZE],
        ph: &mut PacketHeader,
    ) -> Result<(), Error> {
        ph.original_length = u32::from_be_bytes(buf[0..4].try_into().unwrap());
        ph.included_length = u32::from_be_bytes(buf[4..8].try_into().unwrap());
        ph.packet_record_length = u32::from_be_bytes(buf[8..12].try_into().unwrap());
        ph.cumulative_drops = u32::from_be_bytes(buf[12..16].try_into().unwrap());
        ph.timestamp_seconds = u32::from_be_bytes(buf[16..20].try_into().unwrap());
        ph.timestamp_microseconds = u32::from_be_bytes(buf[20..24].try_into().unwrap());

        if ph.included_length > ph.original_length {
            return Err(Error::OriginalLenExceeded);
        }

        if ph.included_length > MAX_CAPTURE_LEN {
            return Err(Error::CaptureLenExceeded);
        }

        if ph.packet_record_length < (SNOOP_PACKET_HEADER_SIZE as u32 + ph.original_length) {
            return Err(Error::InvalidRecordLength);
        }
        Ok(())
    }

    /// calculate how many pad bytes are append to the packet data.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn pad(ph: &PacketHeader) -> usize {
        (ph.packet_record_length - (SNOOP_PACKET_HEADER_SIZE as u32 + ph.included_length)) as usize
    }

    /// calculate the data len with pads included.
    /// pads must be stripped at the end of data bytes.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn data_len(ph: &PacketHeader) -> usize {
        (ph.packet_record_length - SNOOP_PACKET_HEADER_SIZE as u32) as usize
    }
}
