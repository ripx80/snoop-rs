mod common;

#[cfg(test)]
mod tests {
    use crate::common::HEADER;
    use snoop::error::Error;
    use snoop::format::DataLinkType;
    use snoop::format::PacketHeader;
    use snoop::parser::Parser;

    #[test]
    fn parser_header() {
        Parser::parse_header(&HEADER[..16].try_into().unwrap()).unwrap();
    }

    #[test]
    fn parser_header_link_type() {
        assert_eq!(
            Parser::parse_header(&HEADER[..16].try_into().unwrap())
                .unwrap()
                .link_type,
            DataLinkType::Ethernet
        );
    }

    #[test]
    fn parser_header_unassigned_link_type() {
        let mut h: [u8; 16] = [0; 16];
        h.copy_from_slice(&HEADER[0..16]);
        h[14] = 0xFF;
        assert_eq!(
            Parser::parse_header(&h).unwrap().link_type,
            DataLinkType::Unassigned
        );
    }

    #[test]
    fn parser_header_invalid_magic() {
        let mut h: [u8; 16] = [0; 16];
        h.copy_from_slice(&HEADER[0..16]);
        h[2] = 0xFF;
        assert!(matches!(
            Parser::parse_header(&h),
            Err(Error::UnknownMagic)
        ));
    }

    #[test]
    fn parser_header_invalid_version() {
        let mut h: [u8; 16] = [0; 16];
        h.copy_from_slice(&HEADER[0..16]);
        h[11] = 0xFF;
        assert!(matches!(
            Parser::parse_header(&h),
            Err(Error::UnknownVersion)
        ));
    }

    #[test]
    fn parser_packet_header_ci() {
        let mut p = PacketHeader {
            ..Default::default()
        };
        Parser::parse_packet_header(&HEADER[16..40].try_into().unwrap(), &mut p).unwrap();
        assert_eq!(p.original_length, 42);
        assert_eq!(p.included_length, 42);
        assert_eq!(p.packet_record_length, 68);
        assert_eq!(p.cumulative_drops, 0);
        assert_eq!(p.timestamp_seconds, 1556002892);
        assert_eq!(p.timestamp_microseconds, 831815);
    }

    // refactor, needed?
    #[test]
    fn parser_packet_header_invalid_orig() {
        let mut h: [u8; 24] = [0; 24];
        h.copy_from_slice(&HEADER[16..40]);
        h[4] = 0xFF;
        h[5] = 0xFF;
        h[6] = 0xFF;
        h[7] = 0xFF;
        println!("{:#?}", &h[..]);
        let mut p = PacketHeader {
            ..Default::default()
        };
        assert!(matches!(
            Parser::parse_packet_header(&h, &mut p),
            Err(Error::OriginalLenExceeded)
        ));
    }

    // refactor, needed?
    #[test]
    fn parser_packet_header_invalid_cap() {
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
        let mut p = PacketHeader {
            ..Default::default()
        };
        assert!(matches!(
            Parser::parse_packet_header(&h[16..].try_into().unwrap(), &mut p),
            Err(Error::CaptureLenExceeded)
        ));
    }

    // refactor, needed?
    #[test]
    fn packet_header_invalid_cap_record() {
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
        let mut p = PacketHeader {
            ..Default::default()
        };
        assert!(matches!(
            Parser::parse_packet_header(&h[16..].try_into().unwrap(), &mut p),
            Err(Error::InvalidRecordLength)
        ));
    }
}
