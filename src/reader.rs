//! reads from a underlying reader like a file or a buffer.
use crate::format::*;
use crate::parser::SnoopParser;
use crate::SnoopError;
use std::io::Read;
use std::{thread, time};

/// reader to read snoop packet data from a file or buffer into a internal buffer.
#[derive(Debug)]
pub struct SnoopReader<R> {
    r: R,
    header: SnoopHeader,
    ph: PacketHeader,
    buf: Vec<u8>,
}

impl<R> SnoopReader<R>
where
    R: Read,
{
    /// create a new reader with internal buffer for the snoop header, packet header and packet data.
    /// read and parse the snoop file header on creation.
    pub fn new(r: R) -> Result<Self, SnoopError> {
        let mut r = Self {
            r,
            header: SnoopHeader {
                ..Default::default()
            },
            ph: PacketHeader {
                ..Default::default()
            },
            buf: vec![0u8; (MAX_CAPTURE_LEN + MAX_CAPTURE_PADS) as usize],
        };
        r.read_header()?;
        Ok(r)
    }

    /// get a reference to the snoop file format header
    pub fn header(&self) -> &SnoopHeader {
        &self.header
    }

    /// read and parse snoop file format header from the underlying reader
    fn read_header(&mut self) -> Result<(), SnoopError> {
        self.read_exact(0, SNOOP_HEADER_SIZE)?;
        self.header =
            SnoopParser::parse_header(&self.buf[0..SNOOP_HEADER_SIZE].try_into().unwrap())?;
        Ok(())
    }

    /// read a exact number of bytes from a underlying reader and returns how many bytes are read if a unexpected eof error occurs.
    fn read_exact(&mut self, start: usize, end: usize) -> Result<(), SnoopError> {
        let mut buf = &mut self.buf[start..end];
        let mut bytes: usize = 0;
        while !buf.is_empty() {
            match self.r.read(buf) {
                Ok(0) => break, // maybe eof, tcp close or stream end
                Ok(n) => {
                    bytes += n;
                    buf = &mut buf[n..]; // shrink buffer until its empty
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(SnoopError::Io(e)),
            }
        }
        if !buf.is_empty() {
            if bytes == 0 {
                return Err(SnoopError::Eof);
            }
            return Err(SnoopError::UnexpectedEof(bytes));
        }
        Ok(())
    }

    /// read from a reader which is not finished yet. this function blocks until a valid EOF appeared.
    /// can be used if the reader is a socket or the file is not fully written.
    fn read_until(&mut self, size: usize, time: time::Duration) -> Result<(), SnoopError> {
        let mut bytes: usize = 0;
        loop {
            match self.read_exact(bytes, size) {
                Ok(_) => break,
                Err(e) => match e {
                    SnoopError::Eof => {
                        thread::sleep(time);
                    }
                    SnoopError::UnexpectedEof(n) => {
                        bytes += n;
                        thread::sleep(time);
                    }
                    _ => return Err(e),
                },
            };
        }
        Ok(())
    }

    /// read a packet with snoop header and snoop data from the underlying reader and return a reference to internal buf.
    /// when this function is called again the data will be overwritten internaly.
    pub fn read_ref(&mut self) -> Result<SnoopPacketRef, SnoopError> {
        self.read_exact(0, SNOOP_PACKET_HEADER_SIZE)?;
        SnoopParser::parse_packet_header(
            &self.buf[..SNOOP_PACKET_HEADER_SIZE].try_into().unwrap(),
            &mut self.ph,
        )?;

        self.read_exact(0, SnoopParser::data_len(&self.ph))?;
        Ok(SnoopPacketRef {
            header: &self.ph,
            data: &self.buf[..usize::try_from(self.ph.included_length).unwrap()],
        })
    }
    /// read a packet with snoop header and snoop data from the underlying reader and return a copy of the data.
    pub fn read(&mut self) -> Result<SnoopPacket, SnoopError> {
        let pr = self.read_ref()?;
        Ok(SnoopPacket {
            header: pr.header.clone(),
            data: pr.data.to_vec(),
        })
    }

    /// read a packet with snoop header and snoop data from the underlying reader and return a reference of the data.
    /// read from a reader which is not finished yet. this function blocks until a valid EOF appeared.
    /// can be used if the reader is a socket or the file is not fully written.
    pub fn read_stream(&mut self, time: time::Duration) -> Result<SnoopPacketRef, SnoopError> {
        self.read_until(SNOOP_PACKET_HEADER_SIZE, time)?;
        SnoopParser::parse_packet_header(
            &self.buf[..SNOOP_PACKET_HEADER_SIZE].try_into().unwrap(),
            &mut self.ph,
        )?;

        self.read_until(SnoopParser::data_len(&self.ph), time)?;

        Ok(SnoopPacketRef {
            header: &self.ph,
            data: &self.buf[..usize::try_from(self.ph.included_length).unwrap()],
        })
    }

    /// iterate over packets inside a snoop file until a valid eof or error occurs and return the packet data as a reference to the underlying buffer.
    pub fn iter_ref(&mut self) -> Option<Result<SnoopPacketRef, SnoopError>> {
        match self.read_ref() {
            Ok(packet) => Some(Ok(packet)),
            Err(SnoopError::Eof) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

impl<R> Iterator for SnoopReader<R>
where
    R: Read,
{
    type Item = Result<SnoopPacket, SnoopError>;

    /// iterate over packets inside a snoop file until a valid eof or error occurs and return the packet data as a copy.
    fn next(&mut self) -> Option<Self::Item> {
        match self.read() {
            Ok(packet) => Some(Ok(packet)),
            Err(SnoopError::Eof) => None,
            Err(e) => Some(Err(e)),
        }
    }
}
