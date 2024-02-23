mod common;

#[cfg(test)]
mod tests {
    use crate::common::HEADER;
    use snoop::error::Error;
    use snoop::read::Reader;
    use std::io::BufReader;

    #[test]
    fn reader() {
        Reader::new(BufReader::new(HEADER)).unwrap();
    }

    #[test]
    fn reader_header_invalid_short() {
        assert!(matches!(
            Reader::new(BufReader::new(&HEADER[0..14])),
            Err(Error::UnexpectedEof(_))
        ));
    }

    #[test]
    fn reader_packet_iter() {
        for i in Reader::new(BufReader::new(HEADER)).unwrap() {
            assert_eq!(&HEADER[40..(HEADER.len() - 2)], &i.unwrap().data[..]);
        }
    }

    #[test]
    fn reader_small_buff() {
        let mut r = Reader::new(BufReader::with_capacity(10, HEADER)).unwrap();
        let i = r.read();
        let packet = &i.unwrap();
        assert_eq!(&HEADER[40..(HEADER.len() - 2)], &packet.data[..]);
    }
}
