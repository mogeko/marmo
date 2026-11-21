#![no_main]

use libfuzzer_sys::fuzz_target;
use marmo_proto::xudp::parse_meta;

fuzz_target!(|data: &[u8]| {
    let _ = parse_meta(data);
});
