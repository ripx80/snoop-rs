# snoop

snoop is a rust library to read and write files in snoop format.

## think

- is usize a good idea?
- remove packet_header checks and tests?
- change SnoopPacket to Ref
- change PacketHeader to PacketHeader

## read

- read from reader
- read form reader as stream

## write

- write to file
- write to buf

## profiling

```sh
cargo build --profile profiling --example write
samply record target/profiling/examples/write genbroad.snoop

hyperfine --warmup 3 './target/debug/examples/bunchrefbuf /Users/rip/Downloads/proj/snoop-files/T0005'
```
