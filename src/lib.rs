#![deny(missing_docs)]
//!
//! snoop is a rust library to read and write files in snoop file format.
//!
//! ## Example
//!
//! the default case is to read from a snoop file.
//!
//! ```console
//! $ cargo add snoop --features read
//! ```
//! Then use the snoop reader on a file in `main.rs`:
//! ```rust
//! # #[cfg(feature = "read")] {
#![doc = include_str!("../examples/read.rs")]
//! # }
//! ```
//! ## feature flags
//!
//! ### default features
//!
//! * **parser**: format parser
//!
//! ### optional features
//!
//! * **read**: read from a reader like files or buf
//! * **write**: write to a writer like files or buf
//! * **full**: include parser, reader and writer

pub mod error;
pub mod format;

use crate::error::Error;

#[cfg(feature = "parse")]
pub mod parse;

#[cfg(feature = "read")]
pub mod read;

#[cfg(feature = "write")]
pub mod write;
