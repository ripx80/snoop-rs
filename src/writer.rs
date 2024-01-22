use crate::snoop::*;
use crate::SnoopError;
use std::io::Write;

#[derive(Debug)]
pub struct SnoopWriter<W: std::io::Write> {
    w: W,
    header: SnoopHeader,
    pad: u32,
}

impl<W> SnoopWriter<W>
where
    W: Write,
{
    pub fn new(w: W, link_type: DataLinkType) -> Result<Self, SnoopError> {
        let mut w = Self {
            w,
            header: SnoopHeader {
                version: 2,
                link_type,
            },
            pad: 0,
        };
        w.write_header()?;
        Ok(w)
    }
    // internal only
    fn write_header(&mut self) -> Result<(), SnoopError> {
        self.header.version = 2;
        self.header.link_type = self.header.link_type;
        self.w.write(SNOOP_MAGIC).map_err(|e| SnoopError::Io(e))?;
        self.w
            .write(&SNOOP_VERSION)
            .map_err(|e| SnoopError::Io(e))?;
        self.w
            .write(&u32::to_be_bytes(self.header.link_type as u32))
            .map_err(|e| SnoopError::Io(e))?;
        Ok(())
    }
    // internal only
    fn write_packet_header(&mut self, ci: &CapInfo) -> Result<(), SnoopError> {
        if ci.included_length > ci.original_length {
            return Err(SnoopError::OriginalLenExceeded);
        }

        if ci.included_length > MAX_CAPTURE_LEN {
            return Err(SnoopError::CaptureLenExceeded);
        }

        if ci.packet_record_length < (24 + ci.original_length) {
            return Err(SnoopError::InvalidRecordLength);
        }

        self.w
            .write(&ci.original_length.to_be_bytes())
            .map_err(|e| SnoopError::Io(e))?;
        self.w
            .write(&ci.included_length.to_be_bytes())
            .map_err(|e| SnoopError::Io(e))?;
        self.w
            .write(&ci.packet_record_length.to_be_bytes())
            .map_err(|e| SnoopError::Io(e))?;
        self.w
            .write(&ci.cumulative_drops.to_be_bytes())
            .map_err(|e| SnoopError::Io(e))?;
        self.w
            .write(&ci.timestamp_seconds.to_be_bytes())
            .map_err(|e| SnoopError::Io(e))?;
        self.w
            .write(&ci.timestamp_microseconds.to_be_bytes())
            .map_err(|e| SnoopError::Io(e))?;
        self.pad = ci.packet_record_length - (24 + ci.original_length);
        Ok(())
    }
    pub fn write_data(&mut self, data: &[u8]) -> Result<(), SnoopError> {
        self.w.write(data).map_err(|e| SnoopError::Io(e))?;
        /* add pads, only 4 supported */
        match self.pad {
            0 => (),
            1..=4 => {
                let padbuf = [0u8; 4];
                self.w
                    .write(&padbuf[0..(self.pad as usize)])
                    .map_err(|e| SnoopError::Io(e))?;
            }
            _ => return Err(SnoopError::InvalidPadLen),
        };
        Ok(())
    }
    // write packet data to writer, will add padding
    pub fn write_packet(&mut self, packet: &SnoopPacket) -> Result<(), SnoopError> {
        self.write_packet_header(&packet.ci)?;
        self.write_data(&packet.data)?;
        Ok(())
    }
}
