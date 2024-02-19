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
const TIME_EPOCH_EXEEDED: &str = "u32 time epoch exeeded use u64 instad";

/// Errors that can happen inside snoop.
#[derive(Debug)]
pub enum Error {
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
    /// the value of time in seconds not fit into u32 anymore
    TimeEpoch,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::UnknownMagic => write!(f, "{UNKNOWN_MAGIC}"),
            Error::UnknownVersion => write!(f, "{UNKNOWN_VERSION}"),
            Error::OriginalLenExceeded => write!(f, "{ORIGINAL_LEN_EXCEEDED}"),
            Error::CaptureLenExceeded => write!(f, "{CAPTURE_LEN_EXCEEDED}"),
            Error::InvalidRecordLength => write!(f, "{INVALID_RECORD_LENGTH}"),
            Error::InvalidPadLen => write!(f, "{INVALID_PAD_LENGTH}"),
            Error::Eof => write!(f, "{EOF}"),
            Error::UnexpectedEof(n) => write!(f, "{UNEXEOF}, read {n} bytes"),
            Error::Io(ref err) => err.fmt(f),
            Error::Time(ref err) => err.fmt(f),
            Error::TimeEpoch => write!(f, "{TIME_EPOCH_EXEEDED}"),
        }
    }
}

impl error::Error for Error {} // add source: https://doc.rust-lang.org/std/error/trait.Error.html#provided-methods

impl From<Error> for io::Error {
    fn from(size_err: Error) -> io::Error {
        io::Error::new(io::ErrorKind::Other, size_err)
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::Io(err)
    }
}
