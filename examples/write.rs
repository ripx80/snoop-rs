extern crate snoop;

use snoop::format::DataLinkType;
use snoop::read::Reader;
use snoop::write::Writer;
use std::fs::File;
use std::io::{BufReader, BufWriter};

/// cargo run --example write -- snoop_file.cap
///
/// write a single snoop file out.cap from input of the first argument.
/// this is like a copy of the input file.
fn main() {
    let fp = match File::open(
        std::env::args()
            .nth(1)
            .expect("no path to snoop file given"),
    ) {
        Ok(f) => f,
        Err(e) => {
            println!("File Error: {}", e);
            return;
        }
    };
    let out = match File::create("out.cap") {
        Ok(f) => f,
        Err(e) => {
            println!("Output File Error: {}", e);
            return;
        }
    };
    let mut writer = Writer::new(BufWriter::new(out), DataLinkType::Ethernet).unwrap();
    for i in Reader::new(BufReader::new(fp)).unwrap() {
        let packet = i.unwrap();
        writer.write_packet(&packet).unwrap();
    }
}
