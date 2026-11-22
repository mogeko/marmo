//! Protocol sniffers for the first bytes of a proxied stream.
//!
//! The sniffer recognises a TLS `ClientHello` server name, an HTTP/1 `Host`
//! header, and the HPACK-encoded `:authority` of the first HTTP/2 request. It
//! is a pure decoder: callers feed it a bounded prefix and decide when to stop
//! reading. Returning [`crate::sniff::SniffError::NeedMore`] means the prefix
//! is still a valid start of the protocol; `Ok(None)` means the input is not a
//! recognised protocol or carries no domain.
//!
//! The HTTP/2 path includes a bounded HPACK decoder (RFC 7541) so plaintext
//! HTTP/2 can be sniffed without terminating the connection.

use std::collections::VecDeque;
use std::net::IpAddr;

/// Largest prefix the sniffers inspect.
pub const SNIFF_MAX: usize = 16 * 1024;

/// Largest dynamic HPACK table accepted from a peer.
const HPACK_MAX_TABLE: usize = 4096;
/// Largest number of dynamic HPACK entries kept.
const HPACK_MAX_ENTRIES: usize = 128;
/// Largest single HPACK string accepted.
const HPACK_MAX_STRING: usize = 8192;

/// The prefix is a valid start of a protocol, but needs more bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SniffError {
    /// More stream bytes are required to decide.
    NeedMore,
}

/// Detects the protocol and returns its domain, if any.
///
/// `tls`, `http`, and `http2` select the enabled sniffers. A malformed or
/// unrecognised prefix returns `Ok(None)`; only an incomplete prefix returns
/// [`SniffError::NeedMore`].
pub fn detect(
    input: &[u8], tls: bool, http: bool, http2: bool,
) -> Result<Option<String>, SniffError> {
    if input.is_empty() {
        return Err(SniffError::NeedMore);
    }
    if input[0] == 0x16 {
        if !tls {
            return Ok(None);
        }
        return tls_server_name(input);
    }
    if http2 {
        match http2_prefix(input) {
            Prefix::NeedMore => return Err(SniffError::NeedMore),
            Prefix::Matched => return http2_authority(input),
            Prefix::Mismatched => {}
        }
    }
    if http && http_candidate(input) {
        return http_host(input);
    }
    Ok(None)
}

/// Whether the prefix can still become an HTTP/1 request line.
///
/// This keeps arbitrary binary or line protocols (SSH, SMTP, early TLS bytes
/// that are not handshakes) from waiting for an HTTP head that will never
/// arrive.
fn http_candidate(input: &[u8]) -> bool {
    const METHOD_MAX: usize = 16;
    if !input.first().is_some_and(u8::is_ascii_uppercase) {
        return false;
    }
    for (index, byte) in input.iter().copied().enumerate() {
        if byte == b' ' {
            return index > 0;
        }
        if index >= METHOD_MAX || !is_http_token_byte(byte) {
            return false;
        }
    }
    true
}

fn is_http_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

enum Prefix {
    NeedMore,
    Matched,
    Mismatched,
}

const H2_PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

fn http2_prefix(input: &[u8]) -> Prefix {
    let length = input.len().min(H2_PREFACE.len());
    if input[..length] != H2_PREFACE[..length] {
        return Prefix::Mismatched;
    }
    if length < H2_PREFACE.len() {
        Prefix::NeedMore
    } else {
        Prefix::Matched
    }
}

fn tls_server_name(input: &[u8]) -> Result<Option<String>, SniffError> {
    if input.len() < 5 {
        return Err(SniffError::NeedMore);
    }
    if input[0] != 0x16 || input[1] != 0x03 {
        return Ok(None);
    }
    let record_len = usize::from(u16::from_be_bytes([input[3], input[4]]));
    let record_end = 5 + record_len;
    if input.len() < record_end {
        return Err(SniffError::NeedMore);
    }
    let record = &input[5..record_end];
    if record.len() < 4 || record[0] != 0x01 {
        return Ok(None);
    }
    let hello_len =
        usize::from(record[1]) << 16 | usize::from(record[2]) << 8 | usize::from(record[3]);
    if record.len() < 4 + hello_len {
        return Ok(None);
    }
    let hello = &record[4..4 + hello_len];
    if hello.len() < 34 {
        return Ok(None);
    }

    let mut position = 34;
    position = skip_vector(hello, position, 1)?;
    position = skip_vector(hello, position, 2)?;
    position = skip_vector(hello, position, 1)?;
    if position == hello.len() {
        return Ok(None);
    }
    if position + 2 > hello.len() {
        return Ok(None);
    }
    let extensions_len = usize::from(u16::from_be_bytes([hello[position], hello[position + 1]]));
    position += 2;
    let extensions_end = position.saturating_add(extensions_len);
    if extensions_end > hello.len() {
        return Ok(None);
    }

    while position + 4 <= extensions_end {
        let kind = u16::from_be_bytes([hello[position], hello[position + 1]]);
        let length = usize::from(u16::from_be_bytes([
            hello[position + 2],
            hello[position + 3],
        ]));
        position += 4;
        let data_end = position.saturating_add(length);
        if data_end > extensions_end {
            return Ok(None);
        }
        if kind == 0 {
            return Ok(server_name_extension(&hello[position..data_end]));
        }
        position = data_end;
    }
    Ok(None)
}

fn skip_vector(input: &[u8], position: usize, length_bytes: usize) -> Result<usize, SniffError> {
    if position + length_bytes > input.len() {
        return Ok(input.len());
    }
    let length = match length_bytes {
        1 => usize::from(input[position]),
        2 => usize::from(u16::from_be_bytes([input[position], input[position + 1]])),
        _ => return Ok(input.len()),
    };
    Ok(position + length_bytes + length)
}

fn server_name_extension(input: &[u8]) -> Option<String> {
    if input.len() < 2 {
        return None;
    }
    let list_len = usize::from(u16::from_be_bytes([input[0], input[1]]));
    let list_end = (2 + list_len).min(input.len());
    let mut position = 2;
    while position + 3 <= list_end {
        let kind = input[position];
        let length = usize::from(u16::from_be_bytes([
            input[position + 1],
            input[position + 2],
        ]));
        position += 3;
        let end = position.saturating_add(length);
        if end > list_end {
            return None;
        }
        if kind == 0 {
            return std::str::from_utf8(&input[position..end])
                .ok()
                .and_then(normalize_host);
        }
        position = end;
    }
    None
}

fn http_host(input: &[u8]) -> Result<Option<String>, SniffError> {
    use crate::http::{HttpError, parse_absolute, parse_request};

    match parse_request(input) {
        Ok(request) => {
            for header in request.headers() {
                if header.name.eq_ignore_ascii_case("host") {
                    let Ok(value) = std::str::from_utf8(header.value) else {
                        return Ok(None);
                    };
                    return Ok(authority_domain(value));
                }
            }
            if let Ok(target) = parse_absolute(request.target) {
                return Ok(target.endpoint.domain().map(str::to_owned));
            }
            Ok(None)
        }
        Err(HttpError::Incomplete) => Err(SniffError::NeedMore),
        Err(_) => Ok(None),
    }
}

fn http2_authority(input: &[u8]) -> Result<Option<String>, SniffError> {
    let mut position = H2_PREFACE.len();
    let mut table = HpackTable::new();
    let mut block = Vec::new();
    let mut in_headers = false;

    loop {
        if input.len() < position + 9 {
            return Err(SniffError::NeedMore);
        }
        let header = &input[position..position + 9];
        let length =
            usize::from(header[0]) << 16 | usize::from(header[1]) << 8 | usize::from(header[2]);
        let kind = header[3];
        let flags = header[4];
        if length > SNIFF_MAX {
            return Ok(None);
        }
        let start = position + 9;
        let end = start.saturating_add(length);
        if input.len() < end {
            return Err(SniffError::NeedMore);
        }
        let payload = &input[start..end];
        position = end;

        match kind {
            0x01 => {
                let Some(data) = headers_fragment(payload, flags) else {
                    return Ok(None);
                };
                block.clear();
                if block.len() + data.len() > SNIFF_MAX {
                    return Ok(None);
                }
                block.extend_from_slice(data);
                if flags & 0x04 != 0 {
                    return decode_authority(&block, &mut table);
                }
                in_headers = true;
            }
            0x09 => {
                if !in_headers || block.len() + payload.len() > SNIFF_MAX {
                    return Ok(None);
                }
                block.extend_from_slice(payload);
                if flags & 0x04 != 0 {
                    return decode_authority(&block, &mut table);
                }
            }
            _ => {}
        }
    }
}

fn headers_fragment(payload: &[u8], flags: u8) -> Option<&[u8]> {
    let mut start = 0;
    let mut end = payload.len();
    if flags & 0x08 != 0 {
        let padding = usize::from(*payload.first()?);
        start += 1;
        end = end.checked_sub(padding)?;
    }
    if flags & 0x20 != 0 {
        start += 5;
    }
    if start > end {
        return None;
    }
    Some(&payload[start..end])
}

fn decode_authority(block: &[u8], table: &mut HpackTable) -> Result<Option<String>, SniffError> {
    let mut position = 0;
    while position < block.len() {
        let first = block[position];
        let (name, value) = if first & 0x80 != 0 {
            let index = decode_integer(block, &mut position, 7)?;
            table.get(index)?
        } else if first & 0x40 != 0 {
            let index = decode_integer(block, &mut position, 6)?;
            let name = if index == 0 {
                decode_string(block, &mut position)?
            } else {
                table.get(index)?.0
            };
            let value = decode_string(block, &mut position)?;
            table.insert(name.clone(), value.clone());
            (name, value)
        } else if first & 0x20 != 0 {
            let size = decode_integer(block, &mut position, 5)?;
            table.resize(size);
            continue;
        } else {
            let index = decode_integer(block, &mut position, 4)?;
            let name = if index == 0 {
                decode_string(block, &mut position)?
            } else {
                table.get(index)?.0
            };
            let value = decode_string(block, &mut position)?;
            (name, value)
        };

        if name == ":authority" || name == "host" {
            return Ok(normalize_host(&value));
        }
    }
    Ok(None)
}

fn decode_integer(input: &[u8], position: &mut usize, prefix: u8) -> Result<usize, SniffError> {
    let first = *input.get(*position).ok_or(SniffError::NeedMore)?;
    *position += 1;
    let mask = (1_usize << prefix) - 1;
    let mut value = usize::from(first) & mask;
    if value < mask {
        return Ok(value);
    }
    let mut shift = 0;
    loop {
        let byte = *input.get(*position).ok_or(SniffError::NeedMore)?;
        *position += 1;
        if shift > 28 {
            return Err(SniffError::NeedMore);
        }
        let part = usize::from(byte & 0x7f)
            .checked_shl(shift)
            .ok_or(SniffError::NeedMore)?;
        value = value.checked_add(part).ok_or(SniffError::NeedMore)?;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
    }
}

fn decode_string(input: &[u8], position: &mut usize) -> Result<String, SniffError> {
    let first = *input.get(*position).ok_or(SniffError::NeedMore)?;
    let huffman = first & 0x80 != 0;
    let length = decode_integer(input, position, 7)?;
    if length > HPACK_MAX_STRING {
        return Err(SniffError::NeedMore);
    }
    let end = position.saturating_add(length);
    let bytes = input.get(*position..end).ok_or(SniffError::NeedMore)?;
    *position = end;
    let decoded = if huffman {
        huffman_decode(bytes)?
    } else {
        bytes.to_vec()
    };
    String::from_utf8(decoded).map_err(|_| SniffError::NeedMore)
}

fn huffman_decode(input: &[u8]) -> Result<Vec<u8>, SniffError> {
    let mut output = Vec::with_capacity(input.len());
    let mut code = 0_u32;
    let mut length = 0_u8;
    for byte in input {
        for bit in (0..8).rev() {
            code = (code << 1) | u32::from((byte >> bit) & 1);
            length += 1;
            if length > 30 {
                return Err(SniffError::NeedMore);
            }
            let key = (u32::from(length), code);
            if let Ok(index) = HUFFMAN.binary_search_by_key(&key, |entry| (entry.0, entry.1)) {
                output.push(HUFFMAN[index].2);
                code = 0;
                length = 0;
            }
        }
    }
    if length > 7 || (length != 0 && code != (1_u32 << length) - 1) {
        return Err(SniffError::NeedMore);
    }
    Ok(output)
}

#[derive(Clone, Debug)]
struct HpackTable {
    entries: VecDeque<(String, String)>,
    size: usize,
    max_size: usize,
}

impl HpackTable {
    fn new() -> Self {
        Self {
            entries: VecDeque::new(),
            size: 0,
            max_size: HPACK_MAX_TABLE,
        }
    }

    fn resize(&mut self, size: usize) {
        self.max_size = size.min(HPACK_MAX_TABLE);
        self.evict();
    }

    fn insert(&mut self, name: String, value: String) {
        let size = name.len() + value.len() + 32;
        if size > self.max_size {
            self.entries.clear();
            self.size = 0;
            return;
        }
        self.entries.push_front((name, value));
        self.size += size;
        if self.entries.len() > HPACK_MAX_ENTRIES {
            self.evict();
        }
        self.evict();
    }

    fn evict(&mut self) {
        while self.size > self.max_size || self.entries.len() > HPACK_MAX_ENTRIES {
            let Some((name, value)) = self.entries.pop_back() else {
                break;
            };
            self.size -= name.len() + value.len() + 32;
        }
    }

    fn get(&self, index: usize) -> Result<(String, String), SniffError> {
        if index == 0 {
            return Err(SniffError::NeedMore);
        }
        if let Some(entry) = STATIC_TABLE.get(index - 1) {
            return Ok((entry.0.to_owned(), entry.1.to_owned()));
        }
        self.entries
            .get(index - 1 - STATIC_TABLE.len())
            .cloned()
            .ok_or(SniffError::NeedMore)
    }
}

const STATIC_TABLE: [(&str, &str); 61] = [
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
];

/// RFC 7541 Appendix B Huffman codes, sorted by `(length, code)`.
const HUFFMAN: [(u32, u32, u8); 256] = [
    (5, 0x0, 48),
    (5, 0x1, 49),
    (5, 0x2, 50),
    (5, 0x3, 97),
    (5, 0x4, 99),
    (5, 0x5, 101),
    (5, 0x6, 105),
    (5, 0x7, 111),
    (5, 0x8, 115),
    (5, 0x9, 116),
    (6, 0x14, 32),
    (6, 0x15, 37),
    (6, 0x16, 45),
    (6, 0x17, 46),
    (6, 0x18, 47),
    (6, 0x19, 51),
    (6, 0x1a, 52),
    (6, 0x1b, 53),
    (6, 0x1c, 54),
    (6, 0x1d, 55),
    (6, 0x1e, 56),
    (6, 0x1f, 57),
    (6, 0x20, 61),
    (6, 0x21, 65),
    (6, 0x22, 95),
    (6, 0x23, 98),
    (6, 0x24, 100),
    (6, 0x25, 102),
    (6, 0x26, 103),
    (6, 0x27, 104),
    (6, 0x28, 108),
    (6, 0x29, 109),
    (6, 0x2a, 110),
    (6, 0x2b, 112),
    (6, 0x2c, 114),
    (6, 0x2d, 117),
    (7, 0x5c, 58),
    (7, 0x5d, 66),
    (7, 0x5e, 67),
    (7, 0x5f, 68),
    (7, 0x60, 69),
    (7, 0x61, 70),
    (7, 0x62, 71),
    (7, 0x63, 72),
    (7, 0x64, 73),
    (7, 0x65, 74),
    (7, 0x66, 75),
    (7, 0x67, 76),
    (7, 0x68, 77),
    (7, 0x69, 78),
    (7, 0x6a, 79),
    (7, 0x6b, 80),
    (7, 0x6c, 81),
    (7, 0x6d, 82),
    (7, 0x6e, 83),
    (7, 0x6f, 84),
    (7, 0x70, 85),
    (7, 0x71, 86),
    (7, 0x72, 87),
    (7, 0x73, 89),
    (7, 0x74, 106),
    (7, 0x75, 107),
    (7, 0x76, 113),
    (7, 0x77, 118),
    (7, 0x78, 119),
    (7, 0x79, 120),
    (7, 0x7a, 121),
    (7, 0x7b, 122),
    (8, 0xf8, 38),
    (8, 0xf9, 42),
    (8, 0xfa, 44),
    (8, 0xfb, 59),
    (8, 0xfc, 88),
    (8, 0xfd, 90),
    (10, 0x3f8, 33),
    (10, 0x3f9, 34),
    (10, 0x3fa, 40),
    (10, 0x3fb, 41),
    (10, 0x3fc, 63),
    (11, 0x7fa, 39),
    (11, 0x7fb, 43),
    (11, 0x7fc, 124),
    (12, 0xffa, 35),
    (12, 0xffb, 62),
    (13, 0x1ff8, 0),
    (13, 0x1ff9, 36),
    (13, 0x1ffa, 64),
    (13, 0x1ffb, 91),
    (13, 0x1ffc, 93),
    (13, 0x1ffd, 126),
    (14, 0x3ffc, 94),
    (14, 0x3ffd, 125),
    (15, 0x7ffc, 60),
    (15, 0x7ffd, 96),
    (15, 0x7ffe, 123),
    (19, 0x7fff0, 92),
    (19, 0x7fff1, 195),
    (19, 0x7fff2, 208),
    (20, 0xfffe6, 128),
    (20, 0xfffe7, 130),
    (20, 0xfffe8, 131),
    (20, 0xfffe9, 162),
    (20, 0xfffea, 184),
    (20, 0xfffeb, 194),
    (20, 0xfffec, 224),
    (20, 0xfffed, 226),
    (21, 0x1fffdc, 153),
    (21, 0x1fffdd, 161),
    (21, 0x1fffde, 167),
    (21, 0x1fffdf, 172),
    (21, 0x1fffe0, 176),
    (21, 0x1fffe1, 177),
    (21, 0x1fffe2, 179),
    (21, 0x1fffe3, 209),
    (21, 0x1fffe4, 216),
    (21, 0x1fffe5, 217),
    (21, 0x1fffe6, 227),
    (21, 0x1fffe7, 229),
    (21, 0x1fffe8, 230),
    (22, 0x3fffd2, 129),
    (22, 0x3fffd3, 132),
    (22, 0x3fffd4, 133),
    (22, 0x3fffd5, 134),
    (22, 0x3fffd6, 136),
    (22, 0x3fffd7, 146),
    (22, 0x3fffd8, 154),
    (22, 0x3fffd9, 156),
    (22, 0x3fffda, 160),
    (22, 0x3fffdb, 163),
    (22, 0x3fffdc, 164),
    (22, 0x3fffdd, 169),
    (22, 0x3fffde, 170),
    (22, 0x3fffdf, 173),
    (22, 0x3fffe0, 178),
    (22, 0x3fffe1, 181),
    (22, 0x3fffe2, 185),
    (22, 0x3fffe3, 186),
    (22, 0x3fffe4, 187),
    (22, 0x3fffe5, 189),
    (22, 0x3fffe6, 190),
    (22, 0x3fffe7, 196),
    (22, 0x3fffe8, 198),
    (22, 0x3fffe9, 228),
    (22, 0x3fffea, 232),
    (22, 0x3fffeb, 233),
    (23, 0x7fffd8, 1),
    (23, 0x7fffd9, 135),
    (23, 0x7fffda, 137),
    (23, 0x7fffdb, 138),
    (23, 0x7fffdc, 139),
    (23, 0x7fffdd, 140),
    (23, 0x7fffde, 141),
    (23, 0x7fffdf, 143),
    (23, 0x7fffe0, 147),
    (23, 0x7fffe1, 149),
    (23, 0x7fffe2, 150),
    (23, 0x7fffe3, 151),
    (23, 0x7fffe4, 152),
    (23, 0x7fffe5, 155),
    (23, 0x7fffe6, 157),
    (23, 0x7fffe7, 158),
    (23, 0x7fffe8, 165),
    (23, 0x7fffe9, 166),
    (23, 0x7fffea, 168),
    (23, 0x7fffeb, 174),
    (23, 0x7fffec, 175),
    (23, 0x7fffed, 180),
    (23, 0x7fffee, 182),
    (23, 0x7fffef, 183),
    (23, 0x7ffff0, 188),
    (23, 0x7ffff1, 191),
    (23, 0x7ffff2, 197),
    (23, 0x7ffff3, 231),
    (23, 0x7ffff4, 239),
    (24, 0xffffea, 9),
    (24, 0xffffeb, 142),
    (24, 0xffffec, 144),
    (24, 0xffffed, 145),
    (24, 0xffffee, 148),
    (24, 0xffffef, 159),
    (24, 0xfffff0, 171),
    (24, 0xfffff1, 206),
    (24, 0xfffff2, 215),
    (24, 0xfffff3, 225),
    (24, 0xfffff4, 236),
    (24, 0xfffff5, 237),
    (25, 0x1ffffec, 199),
    (25, 0x1ffffed, 207),
    (25, 0x1ffffee, 234),
    (25, 0x1ffffef, 235),
    (26, 0x3ffffe0, 192),
    (26, 0x3ffffe1, 193),
    (26, 0x3ffffe2, 200),
    (26, 0x3ffffe3, 201),
    (26, 0x3ffffe4, 202),
    (26, 0x3ffffe5, 205),
    (26, 0x3ffffe6, 210),
    (26, 0x3ffffe7, 213),
    (26, 0x3ffffe8, 218),
    (26, 0x3ffffe9, 219),
    (26, 0x3ffffea, 238),
    (26, 0x3ffffeb, 240),
    (26, 0x3ffffec, 242),
    (26, 0x3ffffed, 243),
    (26, 0x3ffffee, 255),
    (27, 0x7ffffde, 203),
    (27, 0x7ffffdf, 204),
    (27, 0x7ffffe0, 211),
    (27, 0x7ffffe1, 212),
    (27, 0x7ffffe2, 214),
    (27, 0x7ffffe3, 221),
    (27, 0x7ffffe4, 222),
    (27, 0x7ffffe5, 223),
    (27, 0x7ffffe6, 241),
    (27, 0x7ffffe7, 244),
    (27, 0x7ffffe8, 245),
    (27, 0x7ffffe9, 246),
    (27, 0x7ffffea, 247),
    (27, 0x7ffffeb, 248),
    (27, 0x7ffffec, 250),
    (27, 0x7ffffed, 251),
    (27, 0x7ffffee, 252),
    (27, 0x7ffffef, 253),
    (27, 0x7fffff0, 254),
    (28, 0xfffffe2, 2),
    (28, 0xfffffe3, 3),
    (28, 0xfffffe4, 4),
    (28, 0xfffffe5, 5),
    (28, 0xfffffe6, 6),
    (28, 0xfffffe7, 7),
    (28, 0xfffffe8, 8),
    (28, 0xfffffe9, 11),
    (28, 0xfffffea, 12),
    (28, 0xfffffeb, 14),
    (28, 0xfffffec, 15),
    (28, 0xfffffed, 16),
    (28, 0xfffffee, 17),
    (28, 0xfffffef, 18),
    (28, 0xffffff0, 19),
    (28, 0xffffff1, 20),
    (28, 0xffffff2, 21),
    (28, 0xffffff3, 23),
    (28, 0xffffff4, 24),
    (28, 0xffffff5, 25),
    (28, 0xffffff6, 26),
    (28, 0xffffff7, 27),
    (28, 0xffffff8, 28),
    (28, 0xffffff9, 29),
    (28, 0xffffffa, 30),
    (28, 0xffffffb, 31),
    (28, 0xffffffc, 127),
    (28, 0xffffffd, 220),
    (28, 0xffffffe, 249),
    (30, 0x3ffffffc, 10),
    (30, 0x3ffffffd, 13),
    (30, 0x3ffffffe, 22),
];

fn authority_domain(value: &str) -> Option<String> {
    let host = if value.starts_with('[') {
        return None;
    } else {
        match value.split_once(':') {
            Some((host, port))
                if !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()) =>
            {
                host
            }
            Some(_) => return None,
            None => value,
        }
    };
    normalize_host(host)
}

fn normalize_host(host: &str) -> Option<String> {
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty() || host.len() > 253 {
        return None;
    }
    if host.parse::<IpAddr>().is_ok() {
        return None;
    }
    if !host
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_'))
    {
        return None;
    }
    if host.starts_with('.') || host.contains("..") {
        return None;
    }
    Some(host.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_hello(server_name: Option<&str>) -> Vec<u8> {
        let mut extensions = Vec::new();
        if let Some(name) = server_name {
            let name = name.as_bytes();
            let mut sni = Vec::new();
            sni.extend_from_slice(&(name.len() as u16 + 3).to_be_bytes());
            sni.push(0);
            sni.extend_from_slice(&(name.len() as u16).to_be_bytes());
            sni.extend_from_slice(name);
            extensions.extend_from_slice(&0_u16.to_be_bytes());
            extensions.extend_from_slice(&(sni.len() as u16).to_be_bytes());
            extensions.extend_from_slice(&sni);
        }

        let mut hello = Vec::new();
        hello.extend_from_slice(&[0x03, 0x03]);
        hello.extend_from_slice(&[0x11; 32]);
        hello.push(0);
        hello.extend_from_slice(&2_u16.to_be_bytes());
        hello.extend_from_slice(&[0x13, 0x01]);
        hello.push(1);
        hello.push(0);
        hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        hello.extend_from_slice(&extensions);

        let mut handshake = Vec::new();
        handshake.push(0x01);
        handshake.extend_from_slice(&(hello.len() as u32).to_be_bytes()[1..]);
        handshake.extend_from_slice(&hello);

        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    fn h2_frame(kind: u8, flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![
            0,
            0,
            u8::try_from(payload.len()).expect("small frame"),
            kind,
            flags,
        ];
        frame.extend_from_slice(&[0, 0, 0, 1]);
        frame.extend_from_slice(payload);
        frame
    }

    fn h2_request(block: &[u8]) -> Vec<u8> {
        let mut input = H2_PREFACE.to_vec();
        input.extend_from_slice(&h2_frame(0x04, 0, &[]));
        input.extend_from_slice(&h2_frame(0x01, 0x04, block));
        input
    }

    #[test]
    fn detects_tls_server_name() {
        let hello = client_hello(Some("Example.COM"));
        assert_eq!(
            detect(&hello, true, true, true),
            Ok(Some("example.com".into()))
        );
    }

    #[test]
    fn tls_without_sni_is_recognized_without_a_domain() {
        let hello = client_hello(None);
        assert_eq!(detect(&hello, true, true, true), Ok(None));
    }

    #[test]
    fn incomplete_tls_hello_needs_more() {
        let hello = client_hello(Some("example.com"));
        assert_eq!(
            detect(&hello[..10], true, true, true),
            Err(SniffError::NeedMore)
        );
    }

    #[test]
    fn detects_http_host_and_ignores_ip_literals() {
        let request = b"GET / HTTP/1.1\r\nHost: Example.COM:8080\r\n\r\n";
        assert_eq!(
            detect(request, true, true, false),
            Ok(Some("example.com".into()))
        );

        let ip = b"GET / HTTP/1.1\r\nHost: 127.0.0.1:80\r\n\r\n";
        assert_eq!(detect(ip, true, true, false), Ok(None));

        let incomplete = b"GET / HTTP/1.1\r\nHost: example.com\r\n";
        assert_eq!(
            detect(incomplete, true, true, false),
            Err(SniffError::NeedMore)
        );
    }

    #[test]
    fn arbitrary_binary_is_not_awaited_as_http() {
        assert_eq!(detect(b"hello", true, true, true), Ok(None));
        assert_eq!(
            detect(b"SSH-2.0-OpenSSH_9.8\r\n", true, true, true),
            Ok(None)
        );
        assert_eq!(
            detect(b"GET / HT", true, true, true),
            Err(SniffError::NeedMore)
        );
    }

    #[test]
    fn detects_http2_authority() {
        // `:method: GET` (static index 2), then a literal `:authority` with a
        // raw `www.example.com` value.
        let mut block = vec![0x82, 0x41];
        block.push(15);
        block.extend_from_slice(b"www.example.com");
        let input = h2_request(&block);
        assert_eq!(
            detect(&input, true, true, true),
            Ok(Some("www.example.com".into()))
        );
    }

    #[test]
    fn decodes_huffman_authority() {
        // RFC 7541 C.4.1: Huffman-coded `www.example.com`.
        let mut block = vec![0x82, 0x41, 0x8c];
        block.extend_from_slice(&[
            0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
        ]);
        let input = h2_request(&block);
        assert_eq!(
            detect(&input, true, true, true),
            Ok(Some("www.example.com".into()))
        );
    }

    #[test]
    fn http2_without_authority_has_no_domain() {
        let block = vec![0x82];
        let input = h2_request(&block);
        assert_eq!(detect(&input, true, true, true), Ok(None));
    }

    #[test]
    fn recognises_indexed_dynamic_authority() {
        let mut table = HpackTable::new();
        let mut first = vec![0x82, 0x41, 11];
        first.extend_from_slice(b"example.com");
        assert_eq!(
            decode_authority(&first, &mut table),
            Ok(Some("example.com".into()))
        );
        assert_eq!(
            decode_authority(&[0xbe], &mut table),
            Ok(Some("example.com".into()))
        );
    }
}
