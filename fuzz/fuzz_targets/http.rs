#![no_main]

use libfuzzer_sys::fuzz_target;
use marmo_proto::http::{
    build_forward_head, parse_absolute, parse_connect_response, parse_request,
};

fuzz_target!(|data: &[u8]| {
    let _ = parse_request(data);
    let _ = parse_connect_response(data);
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(request) = parse_request(data)
            && let Ok(target) = parse_absolute(request.target)
        {
            let _ = build_forward_head(
                request.method,
                request.version,
                &target,
                request.headers(),
            );
        }
        let _ = parse_absolute(text);
    }
});
