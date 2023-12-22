use std::error;
use std::fmt;
use std::io;

const UNKNOWN_MAGIC: &str = "unknown snoop magic bytes";
const UNKNOWN_VERSION: &str = "unknown snoop format version";
const UNKNOWN_LINKTYPE: &str = "unknown link type";
const ORIGINAL_LEN_EXCEEDED: &str = "capture length exceeds original packet length";
const CAPTURE_LEN_EXCEEDED: &str = "capture length exceeds max capture length";

#[derive(Debug)]
pub enum SnoopError {
    UnknownMagic,
    UnknownVersion,
    UnkownLinkType,
    OriginalLenExceeded,
    CaptureLenExceeded,
    /// An error that occurs when doing I/O, such as reading an file.
    Io(io::Error),
    Eof(io::Error),
}

impl fmt::Display for SnoopError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SnoopError::UnknownMagic => write!(f, "{}", UNKNOWN_MAGIC),
            SnoopError::UnknownVersion => write!(f, "{}", UNKNOWN_VERSION),
            SnoopError::UnkownLinkType => write!(f, "{}", UNKNOWN_LINKTYPE),
            SnoopError::OriginalLenExceeded => write!(f, "{}", ORIGINAL_LEN_EXCEEDED),
            SnoopError::CaptureLenExceeded => write!(f, "{}", CAPTURE_LEN_EXCEEDED),
            SnoopError::Io(ref err) => err.fmt(f),
            SnoopError::Eof(ref err) => err.fmt(f),
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
