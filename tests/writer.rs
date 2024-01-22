mod common;

#[cfg(test)]
mod tests {
    use crate::common::HEADER;
    //use snoop::error::SnoopError;
    use snoop::snoop::DataLinkType;
    use snoop::writer::SnoopWriter;
    use std::io::BufWriter;
    //use std::io::Write;

    use snoop::reader::SnoopReader;
    use std::io::BufReader;

    #[test]
    fn test_write_header() {
        let mut buf = [0u8; 16];
        {
            let ptr = &mut buf[..];
            SnoopWriter::new(BufWriter::new(ptr), DataLinkType::Ethernet).unwrap();
            //let _ = w.w.flush(); // when close flush, maybe a defer func in writer not in test
        }
        assert_eq!(HEADER[0..16], buf[..]);
        SnoopReader::new(BufReader::new(&buf[..])).unwrap();
    }
    #[test]
    fn test_write_packet_header() {
        let mut buf = [0u8; 84];
        {
            let ptr = &mut buf[..];
            let mut writer = SnoopWriter::new(BufWriter::new(ptr), DataLinkType::Ethernet).unwrap();

            for i in SnoopReader::new(BufReader::new(HEADER)).unwrap() {
                let packet = i.unwrap();
                writer.write_packet(&packet).unwrap();
            }
        }
        assert_eq!(HEADER[..], buf[..]);
    }
}
