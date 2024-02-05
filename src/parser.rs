use crate::snoop::*;
use crate::SnoopError;

#[derive(Debug)]
pub struct SnoopParser;

impl SnoopParser {
    pub fn parse_header(buf: &[u8]) -> Result<SnoopHeader, SnoopError> {
        // buf: &[u8;24]
        if &buf[0..8] != SNOOP_MAGIC {
            return Err(SnoopError::UnknownMagic);
        }

        if &buf[8..12] != SNOOP_VERSION {
            return Err(SnoopError::UnknownVersion);
        }
        // unwrap is safe here
        Ok(SnoopHeader {
            version: u32::from_be_bytes(buf[8..12].try_into().unwrap()),
            link_type: DataLinkType::try_from(u32::from_be_bytes(buf[12..16].try_into().unwrap()))
                .unwrap(),
        })
    }

    // change chapinfo to packet_header
    pub fn parse_packet_header(buf: &[u8], ci: &mut CapInfo) -> Result<(), SnoopError> {
        ci.original_length = u32::from_be_bytes(buf[0..4].try_into().unwrap());
        ci.included_length = u32::from_be_bytes(buf[4..8].try_into().unwrap());
        ci.packet_record_length = u32::from_be_bytes(buf[8..12].try_into().unwrap());
        ci.cumulative_drops = u32::from_be_bytes(buf[12..16].try_into().unwrap());
        ci.timestamp_seconds = u32::from_be_bytes(buf[16..20].try_into().unwrap());
        ci.timestamp_microseconds = u32::from_be_bytes(buf[20..24].try_into().unwrap());

        // refactor: needed this checks?
        if ci.included_length > ci.original_length {
            return Err(SnoopError::OriginalLenExceeded);
        }

        if ci.included_length > MAX_CAPTURE_LEN {
            return Err(SnoopError::CaptureLenExceeded);
        }

        if ci.packet_record_length < (SNOOP_PACKET_HEADER_SIZE as u32 + ci.original_length) {
            return Err(SnoopError::InvalidRecordLength);
        }
        Ok(())
    }

    // needed only for buf data?
    // pub fn parse_packe<'a>(buf: &'a [u8], ci: &'a mut CapInfo)-> Result<(u32, &'a [u8]), SnoopError> {
    //     // if buf.len() < SNOOP_PACKET_HEADER_SIZE {
    //     //     return Err(SnoopError::InvalidPacketHeader);
    //     // }
    //     SnoopParser::parse_packet_header(buf[..SNOOP_PACKET_HEADER_SIZE].try_into().unwrap(), ci)?;
    //     let bytes: u32 = 24 + ci.included_length + (ci.packet_record_length - (24 + ci.original_length));

    //     if buf.len() < bytes.try_into().unwrap(){
    //         return Err(SnoopError::InvalidPacketSize);
    //     }
    //     Ok((bytes, &buf[SNOOP_PACKET_HEADER_SIZE..(usize::try_from(ci.included_length).unwrap())]))
    // }

    pub fn pad(ci: &CapInfo) -> usize {
        (ci.packet_record_length - (24 + ci.included_length)) as usize
    }
    // with pads
    pub fn data_len(ci: &CapInfo) -> usize {
        (ci.packet_record_length - 24) as usize
    }
}
