use std::error;
use std::fmt;
use std::io;
use std::time;

const INVALID_HEADER: &str = "invalid snoop header size, header is too short";
const UNKNOWN_MAGIC: &str = "unknown snoop magic bytes";
const UNKNOWN_VERSION: &str = "unknown snoop format version";
const UNKNOWN_LINKTYPE: &str = "unknown link type";

const INVALID_HEADER_FIELD: &str =
    "invalid header field while parsing, maybe the header is corrupted"; // change to INVALID_PAKET_HEADER

const INVALID_PACKET_HEADER: &str = "invalid packet header size, header is too short";
const INVALID_RECORD_LENGTH: &str = "invalid record length calculation with original len";
const INVALID_PAD_LENGTH: &str =
    "invalid pad length. only 4 bytes as pads are supported in this implementation";

const INVALID_PACKET_SIZE: &str = "invalid packet size, not enough bytes";

const ORIGINAL_LEN_EXCEEDED: &str = "capture length exceeds original packet length";
const CAPTURE_LEN_EXCEEDED: &str = "capture length exceeds max capture length";

const EOF: &str = "end of file";
const UNEXEOF: &str = "unexpected end of file";


#[derive(Debug)]
pub enum SnoopError {
    InvalidHeader,
    UnknownMagic,
    UnknownVersion,
    UnkownLinkType,
    InvalidPacketHeader,
    OriginalLenExceeded,
    CaptureLenExceeded,
    InvalidRecordLength,
    InvalidPacketSize,
    InvalidPadLen,
    InvalidHeaderField,
    EndOfFile, // change this
    UnexpectedEof(usize),
    /// An error that occurs when doing I/O, such as reading an file.
    Io(io::Error),
    Eof(io::Error), // not needed anymore
    Time(time::SystemTimeError),
}

impl fmt::Display for SnoopError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SnoopError::InvalidHeader => write!(f, "{}", INVALID_HEADER),
            SnoopError::UnknownMagic => write!(f, "{}", UNKNOWN_MAGIC),
            SnoopError::UnknownVersion => write!(f, "{}", UNKNOWN_VERSION),
            SnoopError::UnkownLinkType => write!(f, "{}", UNKNOWN_LINKTYPE),
            SnoopError::InvalidPacketHeader => write!(f, "{}", INVALID_PACKET_HEADER),
            SnoopError::OriginalLenExceeded => write!(f, "{}", ORIGINAL_LEN_EXCEEDED),
            SnoopError::CaptureLenExceeded => write!(f, "{}", CAPTURE_LEN_EXCEEDED),
            SnoopError::InvalidRecordLength => write!(f, "{}", INVALID_RECORD_LENGTH),
            SnoopError::InvalidPacketSize => write!(f, "{}", INVALID_PACKET_SIZE),
            SnoopError::InvalidPadLen => write!(f, "{}", INVALID_PAD_LENGTH),
            SnoopError::InvalidHeaderField => write!(f, "{}", INVALID_HEADER_FIELD),
            SnoopError::EndOfFile => write!(f, "{}", EOF),
            SnoopError::UnexpectedEof(_) => write!(f, "{}", UNEXEOF),
            SnoopError::Io(ref err) => err.fmt(f),
            SnoopError::Eof(ref err) => err.fmt(f),
            SnoopError::Time(ref err) => err.fmt(f),
        }
    }
}

impl error::Error for SnoopError {} // add source: https://doc.rust-lang.org/std/error/trait.Error.html#provided-methods

impl From<SnoopError> for io::Error {
    fn from(size_err: SnoopError) -> io::Error {
        io::Error::new(io::ErrorKind::Other, size_err)
    }
}

impl From<io::Error> for SnoopError {
    fn from(err: io::Error) -> SnoopError {
        SnoopError::Io(err)
    }
}
