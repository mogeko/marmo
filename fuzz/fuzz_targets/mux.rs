#![no_main]

use libfuzzer_sys::fuzz_target;
use marmo_net::Endpoint;
use marmo_proto::mux::{
    KEEPALIVE_META, MAX_DATA_LEN, NETWORK_TCP, encode_end_meta, encode_header, encode_keep_meta,
    encode_new_meta, parse_meta,
};

fuzz_target!(|data: &[u8]| {
    let _ = parse_meta(data);
    let _ = parse_meta(&KEEPALIVE_META);

    let target = Endpoint::from_domain("example.com", 443).expect("static target");
    let udp_target = Endpoint::from_domain("example.com", 53).expect("static target");
    let session = u16::from_be_bytes([
        data.first().copied().unwrap_or(0),
        data.get(1).copied().unwrap_or(0),
    ]);
    let data_len = data.len().min(MAX_DATA_LEN);

    let mut meta = [0_u8; 512];
    if let Ok(length) = encode_new_meta(session, &target, NETWORK_TCP, &mut meta) {
        let _ = parse_meta(&meta[..length]);
        let mut frame = [0_u8; 1024];
        if let Some(available) = 1024usize.checked_sub(2 + length + 2) {
            let _ = encode_header(&meta[..length], data_len.min(available), &mut frame);
        }
    }
    if let Ok(length) = encode_keep_meta(session, Some(&udp_target), &mut meta) {
        let _ = parse_meta(&meta[..length]);
    }
    if let Ok(length) = encode_end_meta(session, &mut meta) {
        let _ = parse_meta(&meta[..length]);
    }
});
