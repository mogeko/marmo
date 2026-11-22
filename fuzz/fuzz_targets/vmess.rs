#![no_main]

use libfuzzer_sys::fuzz_target;
use marmo_proto::vless::Uuid;
use marmo_proto::mux::parse_meta;
use marmo_proto::vmess::{
    ChunkDecoder, CmdKey, OPTION_MASKING, OPTION_PADDING, OPTION_STREAM, Security,
    request_progress,
};

fuzz_target!(|data: &[u8]| {
    let uuid = Uuid::parse("00112233-4455-6677-8899-aabbccddeeff").expect("static uuid");
    let key = CmdKey::derive(&uuid);
    let _ = request_progress(data, &key, 1_700_000_000);

    let masked = OPTION_STREAM | OPTION_MASKING | OPTION_PADDING;
    let mut decoder = ChunkDecoder::new(Security::Aes128Gcm, &[0x11; 16], &[0x22; 16], masked);
    let _ = decoder.progress(data);
    let mut decoder = ChunkDecoder::new(Security::ChaCha20Poly1305, &[0x33; 16], &[0x44; 16], masked);
    let _ = decoder.progress(data);

    let _ = parse_meta(data);
});
