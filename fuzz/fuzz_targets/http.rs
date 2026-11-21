#![no_main]

use libfuzzer_sys::fuzz_target;
use marmo_proto::http::{parse_absolute, parse_connect_response, parse_request};

fuzz_target!(|data: &[u8]| {
    let _ = parse_request(data);
    let _ = parse_connect_response(data);
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = parse_absolute(text);
    }
});
