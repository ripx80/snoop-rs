extern crate snoop;

use snoop::reader::Reader;
use std::fs;
use std::fs::File;
use std::io::BufReader;
use std::time::Instant;

/// cargo run --example bulk_buf -- snoop_files/
///
/// read a bulk of files in snoop_files with a increased buffer.
/// this will speed up the reading if you know the exact size of your captures.
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

        let mut sr = Reader::new(BufReader::with_capacity(153600, fp)).unwrap();
        while let Some(i) = sr.iter_ref() {
            cnt += 1;
            let _packet = i.unwrap();
        }
    }
    println!("read packets: {} in {:?}", cnt, start.elapsed());
}
