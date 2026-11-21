#![no_main]

use libfuzzer_sys::fuzz_target;
use marmo_proto::shadowsocks::{
    Method, TAG_LENGTH, decode_client_fixed, decode_client_request, decode_client_variable,
    decode_server_fixed, decode_server_response, decode_server_variable, open_chunk,
};

const PSK: [u8; 32] = [0x11; 32];
const NOW: u64 = 1_700_000_000;

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
    let salt = [0_u8; 32];

    let mut plain = [0_u8; 65_535];
    let _ = decode_client_request(method, key, input, &mut plain, NOW);

    // The streaming decoder reads the fixed header first, then the variable one.
    if let Ok(fixed) = decode_client_fixed(method, key, input, NOW) {
        let fixed_len = method.salt_len() + 11 + TAG_LENGTH;
        if let Some(variable_bytes) = input.get(fixed_len..) {
            let mut variable = [0_u8; 65_535];
            let _ = decode_client_variable(method, &fixed, variable_bytes, &mut variable);
        }
    }

    let _ = decode_server_response(
        method,
        key,
        &salt[..method.salt_len()],
        input,
        &mut plain,
        NOW,
    );
    if let Ok(fixed) = decode_server_fixed(method, key, &salt[..method.salt_len()], input, NOW) {
        let fixed_len = method.salt_len() + 11 + method.salt_len() + TAG_LENGTH;
        if let Some(payload_bytes) = input.get(fixed_len..) {
            let mut plaintext = [0_u8; 65_535];
            let _ = decode_server_variable(method, &fixed, payload_bytes, &mut plaintext);
        }
    }

    let mut counter = 2;
    let _ = open_chunk(method, key, &mut counter, input, &mut plain);
});
