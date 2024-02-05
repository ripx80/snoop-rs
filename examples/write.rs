extern crate snoop;

use snoop::reader::SnoopReader;
use snoop::snoop::DataLinkType;
use snoop::writer::SnoopWriter;
use std::fs::File;
use std::io::{BufReader, BufWriter};

/*
cargo run --example write -- snoop_file.cap
*/
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
    let mut writer = SnoopWriter::new(BufWriter::new(out), DataLinkType::Ethernet).unwrap();
    for i in SnoopReader::new(BufReader::new(fp)).unwrap() {
        let packet = i.unwrap();
        writer.write_packet(&packet).unwrap();
        // println!(
        //     "write packet: \n{:#?}\ndata: {:x?}\n",
        //     &packet.ci,
        //     &packet.data[..]
        // );
    }
}
