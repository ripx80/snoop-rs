#![deny(missing_docs)]
//!
//! snoop is a rust library to read and write files in snoop file format.
//!
//! ## Example
//!
//! the default case is to read from a snoop file.
//!
//! ```console
//! $ cargo add snoop --features reader
//! ```
//! Then use the snoop reader on a file in `main.rs`:
//! ```rust
//! # #[cfg(feature = "reader")] {
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
//! * **reader**: read from a reader like files or buf
//! * **writer**: write to a writer like files or buf
//! * **full**: include parser, reader and writer

pub mod error;
pub mod format;

use crate::error::SnoopError;

#[cfg(feature = "parser")]
pub mod parser;

#[cfg(feature = "reader")]
pub mod reader;

#[cfg(feature = "writer")]
pub mod writer;
