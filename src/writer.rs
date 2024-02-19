//! write to a underlying writer like a file or a buffer.
use crate::format::{DataLinkType, MAX_CAPTURE_LEN, MAX_CAPTURE_PADS, PacketHeader, SNOOP_MAGIC, SNOOP_VERSION, SnoopHeader, SnoopPacket};
use crate::parser::SnoopParser;
use crate::SnoopError;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

/// writer to write packet data as snoop file format to a file or buffer.
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
    /// create a new writer with internal snoop header.
    /// write the internal header as snoop file header on creation.
    /// # Errors
    /// will return [`SnoopError::Io`] if something unexpected happen.
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

    /// write the snoop file header
    fn write_header(&mut self) -> Result<(), SnoopError> {
        self.header.version = 2;
        self.w.write(SNOOP_MAGIC).map_err(SnoopError::Io)?;
        self.w.write(SNOOP_VERSION).map_err(SnoopError::Io)?;
        self.w
            .write(&u32::to_be_bytes(self.header.link_type as u32))
            .map_err(SnoopError::Io)?;
        Ok(())
    }

    /// write the snoop packet header
    fn write_packet_header(&mut self, ph: &PacketHeader) -> Result<(), SnoopError> {
        if ph.included_length > ph.original_length {
            return Err(SnoopError::OriginalLenExceeded);
        }

        if ph.included_length > MAX_CAPTURE_LEN {
            return Err(SnoopError::CaptureLenExceeded);
        }

        if ph.packet_record_length < (24 + ph.original_length) {
            return Err(SnoopError::InvalidRecordLength);
        }

        self.w
            .write(&ph.original_length.to_be_bytes())
            .map_err(SnoopError::Io)?;
        self.w
            .write(&ph.included_length.to_be_bytes())
            .map_err(SnoopError::Io)?;
        self.w
            .write(&ph.packet_record_length.to_be_bytes())
            .map_err(SnoopError::Io)?;
        self.w
            .write(&ph.cumulative_drops.to_be_bytes())
            .map_err(SnoopError::Io)?;
        self.w
            .write(&ph.timestamp_seconds.to_be_bytes())
            .map_err(SnoopError::Io)?;
        self.w
            .write(&ph.timestamp_microseconds.to_be_bytes())
            .map_err(SnoopError::Io)?;
        Ok(())
    }

    /// write packet data to reader
    /// # Errors
    /// will return [`SnoopError`] if something unexpected happen.
    pub fn write_data(&mut self, data: &[u8]) -> Result<(), SnoopError> {
        self.w.write(data).map_err(SnoopError::Io)?;
        Ok(())
    }

    /// write packet header and data to writer and calculate pads from the given [`SnoopHeader`] inside [`SnoopPacket`].
    /// use this function if you want to create the packet header yourself
    /// # Errors
    /// will return [`SnoopError`] if something unexpected happen.
    #[allow(clippy::cast_possible_truncation)]
    pub fn write_packet(&mut self, packet: &SnoopPacket) -> Result<(), SnoopError> {
        self.write_packet_header(&packet.header)?;
        self.write_data(&packet.data)?;
        self.pad = SnoopParser::pad(&packet.header) as u32;
        /* add pads, only 4 supported */
        match self.pad {
            0 => (),
            1..=MAX_CAPTURE_PADS => {
                let padbuf = [0u8; MAX_CAPTURE_PADS as usize];
                self.w
                    .write(&padbuf[0..(self.pad as usize)])
                    .map_err(SnoopError::Io)?;
            }
            _ => return Err(SnoopError::InvalidPadLen),
        };
        Ok(())
    }

    /// write calculated header and the data as snoop packet data to writer.
    /// use this function if you want to auto generate the packet header.
    /// # Errors
    /// will return [`SnoopError`] if something unexpected happen.

    pub fn write(&mut self, data: Vec<u8>) -> Result<(), SnoopError> {
        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(SnoopError::Time)?;
        let mut packet = SnoopPacket {
            header: PacketHeader {
                ..Default::default()
            },
            data,
        };

        packet.header.original_length = match packet.data.len().try_into(){
            Ok(s) => s,
            Err(_) => return Err(SnoopError::OriginalLenExceeded),
        };
        packet.header.included_length = packet.header.original_length; // not truncated
        packet.header.packet_record_length = packet.header.original_length + 24; // no pads
        packet.header.cumulative_drops = 0;
        // will be supported to 2038 :-)
        packet.header.timestamp_seconds = match time.as_secs().try_into(){
            Ok(t) => t,
            Err(e) => return Err(SnoopError::TimeEpoch),
        };
        packet.header.timestamp_microseconds = time.subsec_micros();
        self.write_packet(&packet)
    }
}
