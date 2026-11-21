#![no_main]

use libfuzzer_sys::fuzz_target;
use marmo_proto::trojan::{
    PasswordHash, auth_state, decode_udp_header, request_progress, udp_frame_progress,
};

fuzz_target!(|data: &[u8]| {
    let hash = PasswordHash::derive("marmo-fuzz");
    let _ = auth_state(data, &hash);
    let _ = request_progress(data);
    let _ = udp_frame_progress(data);
    let _ = decode_udp_header(data);
});
