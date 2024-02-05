mod common;

#[cfg(test)]
mod tests {
    //use super::*;

    use crate::common::HEADER;
    use snoop::error::SnoopError;
    use snoop::reader::SnoopReader;
    use snoop::snoop::DataLinkType;
    use std::io::BufReader; //BufRead

    #[test]
    fn test_new_reader() {
        SnoopReader::new(BufReader::new(HEADER)).unwrap();
    }

    #[test]
    fn test_header_link_type() {
        assert_eq!(
            SnoopReader::new(BufReader::new(HEADER))
                .unwrap()
                .header()
                .link_type,
            DataLinkType::Ethernet
        );
    }

    #[test]
    fn test_header_unassigned_link_type() {
        let mut h: [u8; 16] = [0; 16];
        h.copy_from_slice(&HEADER[0..16]);
        h[14] = 0xFF;
        let s = SnoopReader::new(BufReader::new(&h[..])).unwrap();
        assert_eq!(s.header().link_type, DataLinkType::Unassigned);
    }

    #[test]
    fn test_header_invalid_magic() {
        let mut h: [u8; 16] = [0; 16];
        h.copy_from_slice(&HEADER[0..16]);
        h[2] = 0xFF;
        assert!(matches!(
            SnoopReader::new(BufReader::new(&h[..])),
            Err(SnoopError::UnknownMagic)
        ));
    }

    #[test]
    fn test_header_invalid_version() {
        let mut h: [u8; 16] = [0; 16];
        h.copy_from_slice(&HEADER[0..16]);
        h[11] = 0xFF;
        assert!(matches!(
            SnoopReader::new(BufReader::new(&h[..])),
            Err(SnoopError::UnknownVersion)
        ));
    }

    #[test]
    fn test_header_invalid_short() {
        assert!(matches!(
            SnoopReader::new(BufReader::new(&HEADER[0..14])),
            Err(SnoopError::UnexpectedEof(_))
        ));
    }

    #[test]
    fn test_packet_header_ci() {
        let packet = SnoopReader::new(BufReader::new(HEADER))
            .unwrap()
            .read()
            .unwrap();
        assert_eq!(packet.ci.original_length, 42);
        assert_eq!(packet.ci.included_length, 42);
        assert_eq!(packet.ci.packet_record_length, 68);
        assert_eq!(packet.ci.cumulative_drops, 0);
        assert_eq!(packet.ci.timestamp_seconds, 1556002892);
        assert_eq!(packet.ci.timestamp_microseconds, 831815);
    }

    #[test]
    fn test_packet_header_invalid_orig() {
        let mut h: [u8; 40] = [0; 40];
        h.copy_from_slice(&HEADER[0..40]); // 16 snoop, 24 packet header
        h[17] = 0xFF;
        h[18] = 0xFF;
        h[19] = 0xFF;
        h[20] = 0xFF;
        assert!(matches!(
            SnoopReader::new(BufReader::new(&h[..])).unwrap().read(),
            Err(SnoopError::OriginalLenExceeded)
        ));
    }

    #[test]
    fn test_packet_header_invalid_cap() {
        let mut h: [u8; 40] = [0; 40];
        h.copy_from_slice(&HEADER[0..40]); // 16 snoop, 24 packet header
        h[17] = 0x10;
        h[18] = 0x00;
        h[19] = 0x00;
        h[20] = 0x00;

        h[21] = 0x10;
        h[22] = 0x00;
        h[23] = 0x00;
        h[24] = 0x00;
        assert!(matches!(
            SnoopReader::new(BufReader::new(&h[..])).unwrap().read(),
            Err(SnoopError::CaptureLenExceeded)
        ));
    }

    #[test]
    fn test_packet_header_invalid_cap_record() {
        let mut h: [u8; 40] = [0; 40];
        h.copy_from_slice(&HEADER[0..40]); // 16 snoop, 24 packet header
                                           // this will pass the max_cap_len and orgin_len check
        h[17] = 0x00;
        h[18] = 0x10;
        h[19] = 0x00;
        h[20] = 0x00;

        h[21] = 0x00;
        h[22] = 0x10;
        h[23] = 0x00;
        h[24] = 0x00;
        assert!(matches!(
            SnoopReader::new(BufReader::new(&h[..])).unwrap().read(),
            Err(SnoopError::InvalidRecordLength)
        ));
    }

    #[test]
    fn test_packet_iter() {
        for i in SnoopReader::new(BufReader::new(HEADER)).unwrap() {
            assert_eq!(&HEADER[40..(HEADER.len() - 2)], &i.unwrap().data[..]);
        }
    }

    #[test]
    fn test_small_buff() {
        let mut r =  SnoopReader::new(BufReader::with_capacity(10,HEADER)).unwrap();
        let i = r.read();
        let packet = &i.unwrap();
            eprintln!("{:#?}",&packet.data[..]);
            assert_eq!(&HEADER[40..(HEADER.len() - 2)], &packet.data[..]);

    }
}
