extern crate snoop;

use snoop::reader::SnoopReader;
use std::fs;
use std::fs::File;
use std::io::BufReader;
use std::time::Instant;

/*
cargo run --example bulk_buf -- snoop_files/
*/

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

        let mut sr = SnoopReader::new(BufReader::with_capacity(153600, fp)).unwrap();
        while let Some(i) = sr.iter_ref() {
            cnt += 1;
            let _packet = i.unwrap();
        }
    }
    println!("read packets: {} in {:?}", cnt, start.elapsed());
}
