#![no_main]

use libfuzzer_sys::fuzz_target;
use marmo_proto::shadowsocks::{Direction, Method, Window, decode_udp_packet};

const PSK: [u8; 32] = [0x22; 32];

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let method = if data[0] & 1 == 0 {
        Method::Aes128Gcm
    } else {
        Method::Aes256Gcm
    };
    let key = &PSK[..method.key_len()];
    let input = &data[1..];

    let mut plain = [0_u8; 65_535];
    let _ = decode_udp_packet(
        method,
        key,
        input,
        Direction::ClientToServer,
        None,
        &mut plain,
    );
    let _ = decode_udp_packet(
        method,
        key,
        input,
        Direction::ServerToClient,
        Some([0_u8; 8]),
        &mut plain,
    );

    if let Ok(decoded) = decode_udp_packet(
        method,
        key,
        input,
        Direction::ClientToServer,
        None,
        &mut plain,
    ) {
        let mut window = Window::default();
        let _ = window.accept(decoded.packet_id);
        let _ = window.accept(decoded.packet_id);
    }
});
