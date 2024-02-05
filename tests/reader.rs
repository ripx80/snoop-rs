mod common;

#[cfg(test)]
mod tests {
    use crate::common::HEADER;
    use snoop::error::SnoopError;
    use snoop::reader::SnoopReader;
    use std::io::BufReader;

    #[test]
    fn reader() {
        SnoopReader::new(BufReader::new(HEADER)).unwrap();
    }

    // this will panic in parser
    #[test]
    fn reader_header_invalid_short() {
        assert!(matches!(
            SnoopReader::new(BufReader::new(&HEADER[0..14])),
            Err(SnoopError::UnexpectedEof(_))
        ));
    }

    #[test]
    fn reader_packet_iter() {
        for i in SnoopReader::new(BufReader::new(HEADER)).unwrap() {
            assert_eq!(&HEADER[40..(HEADER.len() - 2)], &i.unwrap().data[..]);
        }
    }

    #[test]
    fn reader_small_buff() {
        let mut r = SnoopReader::new(BufReader::with_capacity(10, HEADER)).unwrap();
        let i = r.read();
        let packet = &i.unwrap();
        eprintln!("{:#?}", &packet.data[..]);
        assert_eq!(&HEADER[40..(HEADER.len() - 2)], &packet.data[..]);
    }
}
