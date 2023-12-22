use crate::snoop::*;
use crate::SnoopError;
use std::io::{BufReader, Read}; //BufRead

// SnoopReader wraps an underlying io.SnoopReader to read packet data in SNOOP
// format.  See https://tools.ietf.org/html/rfc1761
// for information on the file format
// We currenty read v2 file format and convert microsecond to nanoseconds
// byte order in big-endian encoding.
#[derive(Debug)]
pub struct SnoopReader<R> {
    pub header: SnoopHeader,
    r: BufReader<R>,
    pad: u32,
    //packetBuf: [u8;100], // needed?
    buf: [u8; 24], // packet header reuse
}

impl<R> SnoopReader<R>
where
    R: Read,
{
    pub fn new(r: BufReader<R>) -> Result<Self, SnoopError> {
        let mut r = Self {
            r,
            header: SnoopHeader {
                ..Default::default()
            },
            pad: 0,
            buf: [0; 24],
        };
        r.read_header()?;
        Ok(r)
    }

    // internal use only
    fn read_header(&mut self) -> Result<[u8; 16], SnoopError> {
        let mut buffer = [0u8; SNOOP_HEADER_SIZE];

        if let Err(e) = self.r.read_exact(&mut buffer) {
            return Err(SnoopError::Io(e));
        }

        if &buffer[0..8] != SNOOP_MAGIC {
            return Err(SnoopError::UnknownMagic);
        }

        if &buffer[8..12] != SNOOP_VERSION {
            return Err(SnoopError::UnknownVersion);
        }

        self.header.version = u32::from_be_bytes(buffer[8..12].try_into().unwrap()); // unwrap here is ok, we have 4 bytes
        self.header.link_type =
            DataLinkType::try_from(u32::from_be_bytes(buffer[12..16].try_into().unwrap())).unwrap(); // is this a nice way??
        Ok(buffer)
    }

    // internal use only
    fn read_packet_header(&mut self) -> Result<CapInfo, SnoopError> {
        let mut ci = CapInfo {
            ..Default::default()
        };
        if let Err(e) = self.r.read_exact(&mut self.buf) {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                return Err(SnoopError::Eof(e)); // right way?
            }
            return Err(SnoopError::Io(e));
        }
        ci.original_length = u32::from_be_bytes(self.buf[0..4].try_into().unwrap());
        ci.included_length = u32::from_be_bytes(self.buf[4..8].try_into().unwrap());
        ci.packet_record_length = u32::from_be_bytes(self.buf[8..12].try_into().unwrap());
        ci.cumulative_drops = u32::from_be_bytes(self.buf[12..16].try_into().unwrap());
        ci.timestamp_seconds = u32::from_be_bytes(self.buf[16..20].try_into().unwrap());
        ci.timestamp_microseconds = u32::from_be_bytes(self.buf[20..24].try_into().unwrap());

        if ci.included_length > ci.original_length {
            return Err(SnoopError::OriginalLenExceeded);
        }

        if ci.included_length > MAX_CAPTURE_LEN {
            return Err(SnoopError::CaptureLenExceeded);
        }
        self.pad = ci.packet_record_length - (24 + ci.original_length);
        Ok(ci)
    }
    // get a copy of the data, todo: maybe change the name?
    pub fn read_packet(&mut self) -> Result<SnoopPacket, SnoopError> {
        let ci = match self.read_packet_header() {
            Ok(f) => f,
            Err(e) => return Err(e),
        };
        let mut data = vec![0u8; usize::try_from(ci.included_length + self.pad).unwrap()];
        if let Err(e) = self.r.read_exact(&mut data) {
            return Err(SnoopError::Io(e));
        }
        // skip pads, fastest solution?
        data.truncate(usize::try_from(ci.included_length).unwrap());
        Ok(SnoopPacket { ci, data })
    }
}

impl<R> Iterator for SnoopReader<R>
where
    R: Read,
{
    type Item = Result<SnoopPacket, SnoopError>;
    fn next(&mut self) -> Option<Self::Item> {
        match self.read_packet() {
            Ok(packet) => Some(Ok(packet)),
            Err(SnoopError::Eof(_)) => None,
            Err(e) => Some(Err(e)),
        }
    }
}
