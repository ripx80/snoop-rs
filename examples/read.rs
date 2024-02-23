extern crate snoop;

use snoop::read::Reader;
use std::fs::File;
use std::io::BufReader;

/// cargo run --example read -- snoop_file.cap
///
/// read a single snoop file and get a copy of the data
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
    let mut cnt = 0u32;
    for i in Reader::new(BufReader::new(fp)).unwrap() {
        cnt += 1;
        let packet = i.unwrap();
        println!(
            "packet: {}\n{:#?}\ndata: {:x?}\n",
            cnt,
            &packet.header,
            &packet.data[..]
        );
    }
}
