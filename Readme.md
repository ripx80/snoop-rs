# snoop

snoop is a rust library to read and write files in snoop format.

## read

- read from file
- read form buf
- read from stream: todo

## write

- write to file
- write to buf
- write to stream: todo

todo: reuse buffer: write, read packet buffer
todo: use bigEndian read/write: maybe bytes crate? -> no dep
todo: read_exact -> change to buffer version to safe syscalls
todo: try_into, try_from and 'as u32' are not safe, how to handle this?

https://github.com/boundary/wireshark/blob/master/wiretap/snoop.c

## profiling

```sh
cargo build --profile profiling --example write
samply record target/profiling/examples/write /Users/rip/Downloads/genbroad.snoop
```



fn as_u32_be(array: &[u8; 4]) -> u32 {
    ((array[0] as u32) << 24) |
    ((array[1] as u32) << 16) |
    ((array[2] as u32) <<  8) |
    ((array[3] as u32) <<  0)
}

fn as_u32_le(array: &[u8; 4]) -> u32 {
    ((array[0] as u32) <<  0) |
    ((array[1] as u32) <<  8) |
    ((array[2] as u32) << 16) |
    ((array[3] as u32) << 24)
}