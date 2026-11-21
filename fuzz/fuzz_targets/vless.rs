#![no_main]

use libfuzzer_sys::fuzz_target;
use marmo_proto::vless::{decode_address, request_progress, response_addons, udp_progress};

fuzz_target!(|data: &[u8]| {
    let _ = request_progress(data);
    let _ = response_addons(data);
    let _ = udp_progress(data);
    let _ = decode_address(data, 0, 443);
});
