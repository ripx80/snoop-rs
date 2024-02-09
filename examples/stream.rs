extern crate snoop;
use snoop::reader::SnoopReader;
use std::fs::File;
use std::io::BufReader;
use std::time::Duration;

/*
cargo run --example stream -- snoop_file.cap
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

    let mut stream = SnoopReader::new(BufReader::new(fp)).unwrap();
    let time = Duration::from_millis(10000);
    let stream = stream.read_stream(time).unwrap();
    println!(
        "read stream packet: \n{:#?}\ndata: {:x?}\n",
        &stream.header,
        &stream.data[..]
    );
}
