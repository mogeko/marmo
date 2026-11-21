#![no_main]

use libfuzzer_sys::fuzz_target;
use marmo_proto::socks5::{Greeting, Request, parse_udp};

fuzz_target!(|data: &[u8]| {
    let _ = Greeting::parse(data);
    let _ = Request::parse(data);
    let _ = parse_udp(data);
});
