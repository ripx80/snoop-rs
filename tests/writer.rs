mod common;

#[cfg(test)]
mod tests {
    use crate::common::HEADER;
    use snoop::error::Error;
    use snoop::format::DataLinkType;
    use snoop::format::PacketHeader;
    use snoop::format::SnoopPacket;
    use snoop::write::Writer;
    use std::io::BufWriter;

    use snoop::read::Reader;
    use std::io::BufReader;

    #[test]
    fn writer_header() {
        let mut buf = [0u8; 16];
        {
            let ptr = &mut buf[..];
            Writer::new(BufWriter::new(ptr), DataLinkType::Ethernet).unwrap();
        }
        assert_eq!(HEADER[0..16], buf[..]);
        Reader::new(BufReader::new(&buf[..])).unwrap();
    }
    #[test]
    fn writer_packet() {
        let mut buf = [0u8; 84];
        {
            let ptr = &mut buf[..];
            let mut writer = Writer::new(BufWriter::new(ptr), DataLinkType::Ethernet).unwrap();

            for i in Reader::new(BufReader::new(HEADER)).unwrap() {
                let packet = i.unwrap();
                writer.write_packet(&packet).unwrap();
            }
        }
        assert_eq!(HEADER[..], buf[..]);
    }

    #[test]
    fn writer_invalid_ci() {
        let mut buf = [0u8; 84];
        let ptr = &mut buf[..];
        let mut writer = Writer::new(BufWriter::new(ptr), DataLinkType::Ethernet).unwrap();
        let mut packet = SnoopPacket {
            header: PacketHeader {
                ..Default::default()
            },
            data: vec![0u8; 40],
        };
        assert!(matches!(
            writer.write_packet(&packet),
            Err(Error::InvalidRecordLength)
        ));
        packet.header.original_length = 42;
        packet.header.included_length = 42;
        packet.header.packet_record_length = 71; // 5 pads, one more then supported
        assert!(matches!(
            writer.write_packet(&packet),
            Err(Error::InvalidPadLen)
        ));

        packet.header.packet_record_length = 68; // 2 pads
        writer.write_packet(&packet).unwrap();
    }

    #[test]
    fn writer() {
        let mut buf = [0u8; 84];
        {
            let ptr = &mut buf[..];
            let mut writer = Writer::new(BufWriter::new(ptr), DataLinkType::Ethernet).unwrap();
            let data = HEADER[40..].to_vec();
            writer.write(data).unwrap();
        }
        let mut reader = Reader::new(BufReader::new(&buf[..])).unwrap();
        let packet = reader.read().unwrap();
        assert_eq!(packet.header.original_length, 44);
        assert_eq!(packet.header.included_length, 44);
        assert_eq!(packet.header.packet_record_length, 68);
        assert_eq!(packet.header.cumulative_drops, 0);
        assert_eq!(&packet.data, &HEADER[40..]);
    }
}
