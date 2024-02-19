extern crate snoop;

use snoop::reader::Reader;
use std::fs;
use std::fs::File;
use std::io::BufReader;
use std::time::Instant;

/// cargo run --example bunch_ref -- snoop_files/
///
/// read a bulk of files in snoop_files as a reference.
/// this will speed up the reading process but the underlying buffer will be overwritten by calling read.
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

        let mut sr = Reader::new(BufReader::new(fp)).unwrap();
        // check to increase the default size: 8192
        while let Some(i) = sr.iter_ref() {
            cnt += 1;
            let _packet = i.unwrap();
        }
    }
    println!("read packets: {} in {:?}", cnt, start.elapsed());
}
