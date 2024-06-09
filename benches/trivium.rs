#![feature(test)]
#[macro_use]
extern crate stream_cipher;
extern crate trivium;

type Trivium = trivium::Trivium;

bench_async!(Trivium);
