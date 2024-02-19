//! custom errors that can happen using snoop.

use std::error;
use std::fmt;
use std::io;
use std::time;

const UNKNOWN_MAGIC: &str = "unknown snoop magic bytes";
const UNKNOWN_VERSION: &str = "unknown snoop format version";
const ORIGINAL_LEN_EXCEEDED: &str = "capture length exceeds original packet length";
const CAPTURE_LEN_EXCEEDED: &str = "capture length exceeds max capture length";
const INVALID_RECORD_LENGTH: &str = "invalid record length calculation with original len";
const INVALID_PAD_LENGTH: &str =
    "invalid pad length. only 4 bytes as pads are supported in this implementation";
const EOF: &str = "end of file";
const UNEXEOF: &str = "unexpected end of file";

/// Errors that can happen inside snoop.
#[derive(Debug)]
pub enum SnoopError {
    /// no valid snoop magic bytes found.
    UnknownMagic,
    /// no valid suppordetd snoop file format version found.
    UnknownVersion,
    /// the len of original packet len exceeded.
    OriginalLenExceeded,
    /// the supported capture len exceeded.
    CaptureLenExceeded,
    /// the record len is invalid.
    InvalidRecordLength,
    /// pad len is invalid or not supported
    InvalidPadLen,
    /// valid end of file appear
    Eof,
    /// unexpected end of file
    UnexpectedEof(usize),
    /// some underlying io error occur, wrapped
    Io(io::Error),
    /// wrapped time error
    Time(time::SystemTimeError),
}

impl fmt::Display for SnoopError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SnoopError::UnknownMagic => write!(f, "{}", UNKNOWN_MAGIC),
            SnoopError::UnknownVersion => write!(f, "{}", UNKNOWN_VERSION),
            SnoopError::OriginalLenExceeded => write!(f, "{}", ORIGINAL_LEN_EXCEEDED),
            SnoopError::CaptureLenExceeded => write!(f, "{}", CAPTURE_LEN_EXCEEDED),
            SnoopError::InvalidRecordLength => write!(f, "{}", INVALID_RECORD_LENGTH),
            SnoopError::InvalidPadLen => write!(f, "{}", INVALID_PAD_LENGTH),
            SnoopError::Eof => write!(f, "{}", EOF),
            SnoopError::UnexpectedEof(n) => write!(f, "{}, read {} bytes", UNEXEOF, n),
            SnoopError::Io(ref err) => err.fmt(f),
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
