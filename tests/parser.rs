mod common;

#[cfg(test)]
mod tests {
    use crate::common::HEADER;
    use snoop::error::SnoopError;
    use snoop::parser::SnoopParser;
    use snoop::snoop::PacketHeader;
    use snoop::snoop::DataLinkType;

    #[test]
    fn parser_header() {
        SnoopParser::parse_header(&HEADER[..16]).unwrap();
    }

    #[test]
    fn parser_header_link_type() {
        assert_eq!(
            SnoopParser::parse_header(HEADER).unwrap().link_type,
            DataLinkType::Ethernet
        );
    }

    #[test]
    fn parser_header_unassigned_link_type() {
        let mut h: [u8; 16] = [0; 16];
        h.copy_from_slice(&HEADER[0..16]);
        h[14] = 0xFF;
        assert_eq!(
            SnoopParser::parse_header(&h[..]).unwrap().link_type,
            DataLinkType::Unassigned
        );
    }

    #[test]
    fn parser_header_invalid_magic() {
        let mut h: [u8; 16] = [0; 16];
        h.copy_from_slice(&HEADER[0..16]);
        h[2] = 0xFF;
        assert!(matches!(
            SnoopParser::parse_header(&h[..]),
            Err(SnoopError::UnknownMagic)
        ));
    }

    #[test]
    fn parser_header_invalid_version() {
        let mut h: [u8; 16] = [0; 16];
        h.copy_from_slice(&HEADER[0..16]);
        h[11] = 0xFF;
        assert!(matches!(
            SnoopParser::parse_header(&h[..]),
            Err(SnoopError::UnknownVersion)
        ));
    }

    #[test]
    fn parser_packet_header_ci() {
        let mut p = PacketHeader {
            ..Default::default()
        };
        SnoopParser::parse_packet_header(&HEADER[16..], &mut p).unwrap();
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
            SnoopParser::parse_packet_header(&h[..], &mut p),
            Err(SnoopError::OriginalLenExceeded)
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
            SnoopParser::parse_packet_header(&h[16..], &mut p),
            Err(SnoopError::CaptureLenExceeded)
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
            SnoopParser::parse_packet_header(&h[16..], &mut p),
            Err(SnoopError::InvalidRecordLength)
        ));
    }
}
