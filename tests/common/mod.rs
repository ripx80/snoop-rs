/* buffer with snoop header + packet header + packet data
84 bytes
*/
pub const HEADER: &[u8] = &[
    // snoop header 16 bytes
    0x73, 0x6E, 0x6F, 0x6F, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x04,
    // packet header 24 bytes
    0x00, 0x00, 0x00, 0x2A, 0x00, 0x00, 0x00, 0x2A, 0x00, 0x00, 0x00, 0x44, 0x00, 0x00, 0x00, 0x00,
    0x5C, 0xBE, 0xB8, 0x4C, 0x00, 0x0C, 0xB1, 0x47, // packet data 44 bytes
    0x7c, 0x5a, 0x1c, 0x49, 0x3c, 0xd1, 0x1e, 0x65, 0x50, 0x7f, 0xb9, 0xca, 0x08, 0x06, 0x00, 0x01,
    0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x1e, 0x65, 0x50, 0x7f, 0xb9, 0xca, 0x0a, 0x00, 0x33, 0x68,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x33, 0x01, 0x00, 0x00,
];
