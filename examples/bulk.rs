extern crate snoop;

use snoop::read::Reader;
use std::fs;
use std::fs::File;
use std::io::BufReader;
use std::time::Instant;

/// cargo run --example bulk -- snoop_files/
///
/// read a bulk of files in snoop_files and get a copy of this data
fn main() {
    let start = Instant::now();
    let paths = fs::read_dir(std::env::args().nth(1).unwrap()).expect("no path given");
    let mut cnt = 0u128;
    for path in paths {
        let p = path.unwrap().path();
        println!("read file: {}", p.display());

        let fp = match File::open(p) {
            Ok(f) => f,
            Err(e) => {
                println!("File Error: {}", e);
                return;
            }
        };

        for i in Reader::new(BufReader::new(fp)).unwrap() {
            cnt += 1;
            let _packet = i.unwrap();
        }
    }

    println!("read packets: {} in {:?}", cnt, start.elapsed());
}
