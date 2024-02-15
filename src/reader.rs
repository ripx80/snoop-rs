use crate::parser::SnoopParser;
use crate::format::*;
use crate::SnoopError;
use std::io::Read;
use std::{thread, time};

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

    pub fn header(&self) -> &SnoopHeader {
        &self.header
    }

    fn read_header(&mut self) -> Result<(), SnoopError> {
        self.read_exact(0, SNOOP_HEADER_SIZE)?;
        self.header = SnoopParser::parse_header(&self.buf[0..SNOOP_HEADER_SIZE])?;
        Ok(())
    }

    pub fn read_exact(&mut self, start: usize, end: usize) -> Result<(), SnoopError> {
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
                return Err(SnoopError::Eof); // change name
            }
            return Err(SnoopError::UnexpectedEof(bytes));
        }
        Ok(())
    }

    pub fn read_until(&mut self, size: usize, time: time::Duration) -> Result<(), SnoopError> {
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

    pub fn read_ref(&mut self) -> Result<SnoopPacketRef, SnoopError> {
        self.read_exact(0, SNOOP_PACKET_HEADER_SIZE)?;
        SnoopParser::parse_packet_header(&self.buf[..SNOOP_PACKET_HEADER_SIZE], &mut self.ph)?;

        self.read_exact(0, SnoopParser::data_len(&self.ph))?;
        Ok(SnoopPacketRef {
            header: &self.ph,
            data: &self.buf[..usize::try_from(self.ph.included_length).unwrap()],
        })
    }

    pub fn read(&mut self) -> Result<SnoopPacket, SnoopError> {
        let pr = self.read_ref()?;
        Ok(SnoopPacket {
            header: pr.header.clone(),
            data: pr.data.to_vec(),
        })
    }

    // if the R is not fully written this function blocks until new bytes
    pub fn read_stream(&mut self, time: time::Duration) -> Result<SnoopPacketRef, SnoopError> {
        self.read_until(SNOOP_PACKET_HEADER_SIZE, time)?;
        SnoopParser::parse_packet_header(&self.buf[..SNOOP_PACKET_HEADER_SIZE], &mut self.ph)?;

        self.read_until(SnoopParser::data_len(&self.ph), time)?;

        Ok(SnoopPacketRef {
            header: &self.ph,
            data: &self.buf[..usize::try_from(self.ph.included_length).unwrap()],
        })
    }

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
    fn next(&mut self) -> Option<Self::Item> {
        match self.read() {
            Ok(packet) => Some(Ok(packet)),
            Err(SnoopError::Eof) => None,
            Err(e) => Some(Err(e)),
        }
    }
}
