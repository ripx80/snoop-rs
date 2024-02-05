use crate::snoop::*;
use crate::SnoopError;
use crate::parser::SnoopParser;
use std::io::Read;
use std::{thread, time};

#[derive(Debug)]
pub struct SnoopReader<R> {
    r: R,
    header: SnoopHeader,
    ci: CapInfo,
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
            ci: CapInfo {
                ..Default::default()
            },
            buf: vec![0u8; (MAX_CAPTURE_LEN + MAX_CAPTURE_PADS) as usize],
        };
        r.read_header()?;
        Ok(r)
    }

    pub fn header(&self)->&SnoopHeader{
        &self.header
    }

    fn read_header(&mut self) -> Result<(), SnoopError> {
        self.read_exact(0,SNOOP_HEADER_SIZE)?;
        self.header = SnoopParser::parse_header(&self.buf[0..SNOOP_HEADER_SIZE])?;
        Ok(())
    }

    // return readed bytes, even if it fails to reset cursor
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
        if !buf.is_empty(){
            if bytes == 0 {
                return Err(SnoopError::EndOfFile); // change name

            }
            return Err(SnoopError::UnexpectedEof(bytes))

        }
        Ok(())
    }

    pub fn read_until(&mut self, size: usize, time: time::Duration) -> Result<(), SnoopError> {
        let mut bytes: usize = 0;
        loop {
            match self.read_exact(bytes, size){
                Ok(_) => break,
                Err(e) => match e {
                    SnoopError::EndOfFile =>{
                        thread::sleep(time);
                    }
                    SnoopError::UnexpectedEof(n) => {
                        bytes +=n;
                        thread::sleep(time);
                    },
                    _ => return Err(e),
                }
            };
        }
        Ok(())
    }

    // add: return bytes as Result and Error
    pub fn read_ref(&mut self) -> Result<SnoopPacketRef, SnoopError> {
        //let mut bytes: usize = 0;
        self.read_exact(0,SNOOP_PACKET_HEADER_SIZE)?;
        SnoopParser::parse_packet_header(&self.buf[..SNOOP_PACKET_HEADER_SIZE], &mut self.ci)?;

        self.read_exact(0,SnoopParser::data_len(&self.ci))?;
        Ok(SnoopPacketRef{
            ci: &self.ci,
            data: &self.buf[..usize::try_from(self.ci.included_length).unwrap()],
        })
    }

    // add: return bytes as Result and Error
    pub fn read(&mut self) -> Result<SnoopPacket, SnoopError> {
        let pr = self.read_ref()?;
        Ok(SnoopPacket{
            ci: pr.ci.clone(),
            data: pr.data.to_vec(),
        })
    }

    // if the R is not fully written this function blocks until new bytes
    // add: return bytes as Result and Error
    pub fn read_stream(&mut self) -> Result<SnoopPacketRef, SnoopError> {
        // blocking
        let time = time::Duration::from_millis(10000);
        self.read_until(SNOOP_PACKET_HEADER_SIZE, time)?;

        SnoopParser::parse_packet_header(&self.buf[..SNOOP_PACKET_HEADER_SIZE], &mut self.ci)?;

        self.read_until(SnoopParser::data_len(&self.ci), time)?;

        Ok(SnoopPacketRef{
            ci: &self.ci,
            data: &self.buf[..usize::try_from(self.ci.included_length).unwrap()],
        })
    }

    pub fn iter_ref(&mut self) -> Option<Result<SnoopPacketRef, SnoopError>>{
        match self.read_ref() {
            Ok(packet) => Some(Ok(packet)),
            Err(SnoopError::Eof(_)) => None,
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
            Err(SnoopError::EndOfFile) => None,
            Err(e) => Some(Err(e)),
        }
    }

}
