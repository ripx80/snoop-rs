pub mod error;
pub mod format;

use crate::error::SnoopError;

#[cfg(feature = "parser")]
pub mod parser;

#[cfg(feature = "reader")]
pub mod reader;

#[cfg(feature = "writer")]
pub mod writer;
