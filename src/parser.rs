use crate::format::*;
use crate::SnoopError;

#[derive(Debug)]
pub struct SnoopParser;

impl SnoopParser {
    pub fn parse_header(buf: &[u8; SNOOP_HEADER_SIZE]) -> Result<SnoopHeader, SnoopError> {
        if &buf[0..8] != SNOOP_MAGIC {
            return Err(SnoopError::UnknownMagic);
        }

        if &buf[8..12] != SNOOP_VERSION {
            return Err(SnoopError::UnknownVersion);
        }

        Ok(SnoopHeader {
            version: u32::from_be_bytes(buf[8..12].try_into().unwrap()),
            link_type: DataLinkType::try_from(u32::from_be_bytes(buf[12..16].try_into().unwrap()))
                .unwrap(),
        })
    }

    pub fn parse_packet_header(
        buf: &[u8; SNOOP_PACKET_HEADER_SIZE],
        ph: &mut PacketHeader,
    ) -> Result<(), SnoopError> {
        ph.original_length = u32::from_be_bytes(buf[0..4].try_into().unwrap());
        ph.included_length = u32::from_be_bytes(buf[4..8].try_into().unwrap());
        ph.packet_record_length = u32::from_be_bytes(buf[8..12].try_into().unwrap());
        ph.cumulative_drops = u32::from_be_bytes(buf[12..16].try_into().unwrap());
        ph.timestamp_seconds = u32::from_be_bytes(buf[16..20].try_into().unwrap());
        ph.timestamp_microseconds = u32::from_be_bytes(buf[20..24].try_into().unwrap());

        if ph.included_length > ph.original_length {
            return Err(SnoopError::OriginalLenExceeded);
        }

        if ph.included_length > MAX_CAPTURE_LEN {
            return Err(SnoopError::CaptureLenExceeded);
        }

        if ph.packet_record_length < (SNOOP_PACKET_HEADER_SIZE as u32 + ph.original_length) {
            return Err(SnoopError::InvalidRecordLength);
        }
        Ok(())
    }

    pub fn pad(ph: &PacketHeader) -> usize {
        (ph.packet_record_length - (SNOOP_PACKET_HEADER_SIZE as u32 + ph.included_length)) as usize
    }
    // with pads
    pub fn data_len(ph: &PacketHeader) -> usize {
        (ph.packet_record_length - SNOOP_PACKET_HEADER_SIZE as u32) as usize
    }
}
