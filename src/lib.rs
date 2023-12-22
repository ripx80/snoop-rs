/*
todo:
    - copyright
    - licence
    - add doc test
    - add features: reader, writer
    - add stream reader with buffio reader
*/

//#![allow(dead_code)]
//#![allow(unused_imports)]

pub mod error;
pub mod snoop;
use crate::error::SnoopError;

#[cfg(feature = "reader")]
pub mod reader;
