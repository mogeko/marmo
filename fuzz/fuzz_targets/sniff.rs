#![no_main]

use libfuzzer_sys::fuzz_target;
use marmo_proto::sniff::detect;

fuzz_target!(|data: &[u8]| {
    let (flags, input) = data.split_first().map_or((0, &[][..]), |(flag, rest)| (*flag, rest));
    let _ = detect(input, flags & 0x01 != 0, flags & 0x02 != 0, flags & 0x04 != 0);
});
