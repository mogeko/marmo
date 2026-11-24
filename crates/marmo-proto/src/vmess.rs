//! VMess AEAD codec: auth IDs, instructions, responses, and chunked bodies.
//!
//! Only the AEAD header authentication is implemented. Legacy MD5 + AES-128-CFB
//! headers, body `None`/`Zero`, and the authenticated-length experiment are
//! rejected. The codec performs no I/O and never reads the clock; callers pass
//! `now_unix` and all random material.
//!
//! Wire layout of a request:
//!
//! ```text
//! [16B EAuID][18B encrypted length][8B connection nonce][N+16B instruction]
//! ```
//!
//! Body chunks are `[2B masked length][ciphertext][padding]`, where the
//! ciphertext is `plaintext ++ 16B tag`. The 16-bit counter is closed after
//! 65,536 chunks so a GCM nonce cannot repeat.

use std::fmt;

use aes::Aes128;
use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit as BlockKeyInit};
use aes_gcm::aead::{AeadInOut, inout::InOutBuf};
use aes_gcm::{Aes128Gcm, Nonce};
use chacha20poly1305::ChaCha20Poly1305;
use hmac::{Hmac, Mac};
use marmo_net::Endpoint;
use sha2::{Digest, Sha256};
use sha3::Shake128;
use sha3::Shake128Reader;
use sha3::digest::{ExtendableOutput, XofReader};
use thiserror::Error;
use zeroize::Zeroize;

use crate::vless::{self, Uuid, VlessError};

/// VMess protocol version.
pub const VERSION: u8 = 1;
/// Auth-ID length.
pub const AUTH_ID_LEN: usize = 16;
/// Connection nonce length.
pub const CONNECTION_NONCE_LEN: usize = 8;
/// Encrypted instruction-length block: 2 bytes plus a 16-byte tag.
pub const LENGTH_BLOCK_LEN: usize = 2 + TAG_LEN;
/// AEAD tag length.
pub const TAG_LEN: usize = 16;
/// Maximum decrypted instruction length.
pub const INSTRUCTION_MAX: usize = 317;
/// Maximum padding bytes in the instruction.
pub const HEADER_PADDING_MAX: usize = 15;
/// Maximum request header on the wire.
pub const REQUEST_HEADER_MAX: usize =
    AUTH_ID_LEN + LENGTH_BLOCK_LEN + CONNECTION_NONCE_LEN + INSTRUCTION_MAX + TAG_LEN;
/// Maximum chunk length, including the tag and padding.
pub const CHUNK_LENGTH_MAX: usize = 16 * 1024;
/// Maximum chunk padding.
pub const CHUNK_PADDING_MAX: usize = 63;
/// Maximum payload the encoder accepts for one chunk.
pub const CHUNK_PLAINTEXT_MAX: usize = CHUNK_LENGTH_MAX - TAG_LEN - CHUNK_PADDING_MAX;
/// Maximum chunk bytes on the wire.
pub const CHUNK_WIRE_MAX: usize = 2 + CHUNK_LENGTH_MAX;
/// Maximum chunks per direction before the key must not be reused.
pub const MAX_CHUNKS: u32 = 65_536;
/// Accepted clock skew for the auth-ID timestamp.
pub const TIMESTAMP_WINDOW_S: u64 = 120;
/// TCP command.
pub const COMMAND_TCP: u8 = 1;
/// UDP command.
pub const COMMAND_UDP: u8 = 2;
/// Mux command.
pub const COMMAND_MUX: u8 = 3;
/// Stream option.
pub const OPTION_STREAM: u8 = 0x01;
/// Deprecated connection-reuse option; ignored when set.
pub const OPTION_REUSE: u8 = 0x02;
/// Chunk-mask option.
pub const OPTION_MASKING: u8 = 0x04;
/// Global padding option.
pub const OPTION_PADDING: u8 = 0x08;
/// Authenticated-length experiment; not supported.
pub const OPTION_AUTHENTICATED_LENGTH: u8 = 0x10;
/// Body security: AES-128-GCM.
pub const SECURITY_AES128_GCM: u8 = 0x03;
/// Body security: ChaCha20-Poly1305.
pub const SECURITY_CHACHA20_POLY1305: u8 = 0x04;
/// Synthetic Mux.Cool target domain.
pub const MUX_DOMAIN: &str = "v1.mux.cool";
/// Synthetic Mux.Cool target port.
pub const MUX_PORT: u16 = 0;

const CMD_KEY_SALT: &[u8] = b"c48619fe-8f02-49e0-b9e9-edf763e17e21";
const KDF_SALT: &[u8] = b"VMess AEAD KDF";
const LABEL_AUTH_ID: &[u8] = b"AES Auth ID Encryption";
const LABEL_LENGTH_KEY: &[u8] = b"VMess Header AEAD Key_Length";
const LABEL_LENGTH_NONCE: &[u8] = b"VMess Header AEAD Nonce_Length";
const LABEL_HEADER_KEY: &[u8] = b"VMess Header AEAD Key";
const LABEL_HEADER_NONCE: &[u8] = b"VMess Header AEAD Nonce";
const LABEL_RESPONSE_LENGTH_KEY: &[u8] = b"AEAD Resp Header Len Key";
const LABEL_RESPONSE_LENGTH_NONCE: &[u8] = b"AEAD Resp Header Len IV";
const LABEL_RESPONSE_KEY: &[u8] = b"AEAD Resp Header Key";
const LABEL_RESPONSE_NONCE: &[u8] = b"AEAD Resp Header IV";

/// Body cipher selected by the instruction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Security {
    /// AES-128-GCM (`0x03`).
    Aes128Gcm,
    /// ChaCha20-Poly1305 (`0x04`).
    ChaCha20Poly1305,
}

impl Security {
    /// Parses the four-bit security value.
    pub fn from_wire(value: u8) -> Result<Self, VmessError> {
        match value {
            SECURITY_AES128_GCM => Ok(Self::Aes128Gcm),
            SECURITY_CHACHA20_POLY1305 => Ok(Self::ChaCha20Poly1305),
            _ => Err(VmessError::UnsupportedSecurity),
        }
    }

    /// Returns the four-bit security value.
    #[must_use]
    pub const fn to_wire(self) -> u8 {
        match self {
            Self::Aes128Gcm => SECURITY_AES128_GCM,
            Self::ChaCha20Poly1305 => SECURITY_CHACHA20_POLY1305,
        }
    }
}

/// UUID-derived command key, compared and zeroized as a secret.
#[derive(Clone)]
pub struct CmdKey([u8; 16]);

impl CmdKey {
    /// Derives the command key from a UUID.
    #[must_use]
    pub fn derive(uuid: &Uuid) -> Self {
        let mut hasher = md5::Md5::new();
        hasher.update(uuid.as_bytes());
        hasher.update(CMD_KEY_SALT);
        let digest = hasher.finalize();
        let mut key = [0_u8; 16];
        key.copy_from_slice(&digest);
        Self(key)
    }

    fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Debug for CmdKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CmdKey(<redacted>)")
    }
}

impl Drop for CmdKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Caller-generated material for one request.
#[derive(Clone)]
pub struct RequestSecrets {
    /// Request body IV.
    pub body_iv: [u8; 16],
    /// Request body key.
    pub body_key: [u8; 16],
    /// One-byte response authentication value.
    pub response_auth: u8,
    /// Auth-ID random field.
    pub auth_rand: [u8; 4],
    /// Connection nonce.
    pub connection_nonce: [u8; 8],
}

impl Drop for RequestSecrets {
    fn drop(&mut self) {
        self.body_iv.zeroize();
        self.body_key.zeroize();
        self.connection_nonce.zeroize();
    }
}

/// A decoded request.
pub struct Request {
    /// Raw auth ID from the wire.
    pub auth_id: [u8; AUTH_ID_LEN],
    /// `COMMAND_TCP`, `COMMAND_UDP`, or `COMMAND_MUX`.
    pub command: u8,
    /// Requested destination; the synthetic Mux target for `COMMAND_MUX`.
    pub target: Endpoint,
    /// Body cipher.
    pub security: Security,
    /// Option bits from the instruction.
    pub option: u8,
    /// Request body key.
    pub body_key: [u8; 16],
    /// Request body IV.
    pub body_iv: [u8; 16],
    /// One-byte response authentication value.
    pub response_auth: u8,
    /// Bytes consumed by the request header.
    pub consumed: usize,
}

impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Request")
            .field("command", &self.command)
            .field("target", &self.target)
            .field("security", &self.security)
            .field("option", &self.option)
            .field("consumed", &self.consumed)
            .finish_non_exhaustive()
    }
}

impl Drop for Request {
    fn drop(&mut self) {
        self.body_key.zeroize();
        self.body_iv.zeroize();
    }
}

/// Progress of a request header.
#[derive(Debug)]
pub enum RequestProgress {
    /// More bytes are needed.
    NeedMore,
    /// The auth ID or the header is invalid.
    Invalid,
    /// The auth ID did not authenticate within the window.
    Unauthorized,
    /// A complete, authenticated request.
    Complete(Request),
}

/// Caller-supplied inputs for one request header.
pub struct RequestSpec<'a> {
    /// Destination, or the synthetic Mux target.
    pub target: &'a Endpoint,
    /// `COMMAND_TCP`, `COMMAND_UDP`, or `COMMAND_MUX`.
    pub command: u8,
    /// Body cipher.
    pub security: Security,
    /// Unix timestamp in seconds.
    pub timestamp: u64,
    /// Header padding, at most 15 bytes.
    pub padding: &'a [u8],
    /// Connection secrets.
    pub secrets: &'a RequestSecrets,
}

/// Encodes a request header.
pub fn encode_request(
    cmd_key: &CmdKey, spec: &RequestSpec<'_>, out: &mut [u8],
) -> Result<usize, VmessError> {
    let RequestSpec {
        target,
        command,
        security,
        timestamp,
        padding,
        secrets,
    } = spec;
    let command = *command;
    let security = *security;
    if command != COMMAND_TCP && command != COMMAND_UDP && command != COMMAND_MUX {
        return Err(VmessError::UnsupportedCommand);
    }
    if padding.len() > HEADER_PADDING_MAX {
        return Err(VmessError::InvalidHeader);
    }
    let auth_id = seal_auth_id(cmd_key, *timestamp, &secrets.auth_rand);

    let mut instruction = [0_u8; INSTRUCTION_MAX];
    instruction[0] = VERSION;
    instruction[1..17].copy_from_slice(&secrets.body_iv);
    instruction[17..33].copy_from_slice(&secrets.body_key);
    instruction[33] = secrets.response_auth;
    let option = OPTION_STREAM | OPTION_MASKING | OPTION_PADDING;
    instruction[34] = option;
    let padding_len = u8::try_from(padding.len()).map_err(|_| VmessError::InvalidHeader)?;
    instruction[35] = (padding_len << 4) | security.to_wire();
    instruction[36] = 0;
    instruction[37] = command;
    let mut position = if command == COMMAND_MUX {
        38
    } else {
        instruction[38..40].copy_from_slice(&target.port().to_be_bytes());
        let address = vless::encode_address(target, &mut instruction[40..]).map_err(map_vless)?;
        40 + address
    };
    if position + padding.len() + 4 > INSTRUCTION_MAX {
        return Err(VmessError::InvalidHeader);
    }
    instruction[position..position + padding.len()].copy_from_slice(padding);
    position += padding.len();
    let checksum = fnv1a(&instruction[..position]);
    instruction[position..position + 4].copy_from_slice(&checksum.to_be_bytes());
    position += 4;

    let total = AUTH_ID_LEN + LENGTH_BLOCK_LEN + CONNECTION_NONCE_LEN + position + TAG_LEN;
    if out.len() < total {
        return Err(VmessError::NoSpace);
    }
    out[..AUTH_ID_LEN].copy_from_slice(&auth_id);
    let nonce = &secrets.connection_nonce;
    let (length_key, length_nonce) = header_keys(
        cmd_key,
        LABEL_LENGTH_KEY,
        LABEL_LENGTH_NONCE,
        &auth_id,
        nonce,
    );
    let length = u16::try_from(position).map_err(|_| VmessError::HeaderTooBig)?;
    aes_seal(
        &length_key,
        &length_nonce,
        &auth_id,
        &length.to_be_bytes(),
        &mut out[16..],
    )?;
    out[34..42].copy_from_slice(nonce);
    let (header_key, header_nonce) = header_keys(
        cmd_key,
        LABEL_HEADER_KEY,
        LABEL_HEADER_NONCE,
        &auth_id,
        nonce,
    );
    let seal_start = 42;
    let seal_end = seal_start + position + TAG_LEN;
    aes_seal(
        &header_key,
        &header_nonce,
        &auth_id,
        &instruction[..position],
        &mut out[seal_start..seal_end],
    )?;
    Ok(total)
}

/// Evaluates the bytes read so far as a request header.
#[must_use]
pub fn request_progress(bytes: &[u8], cmd_key: &CmdKey, now_unix: u64) -> RequestProgress {
    if bytes.len() < AUTH_ID_LEN {
        return RequestProgress::NeedMore;
    }
    let mut auth_id = [0_u8; AUTH_ID_LEN];
    auth_id.copy_from_slice(&bytes[..AUTH_ID_LEN]);
    if open_auth_id(cmd_key, &auth_id, now_unix).is_none() {
        return RequestProgress::Unauthorized;
    }
    if bytes.len() < AUTH_ID_LEN + LENGTH_BLOCK_LEN + CONNECTION_NONCE_LEN {
        return RequestProgress::NeedMore;
    }
    let nonce_start = AUTH_ID_LEN + LENGTH_BLOCK_LEN;
    let mut connection_nonce = [0_u8; CONNECTION_NONCE_LEN];
    connection_nonce.copy_from_slice(&bytes[nonce_start..nonce_start + CONNECTION_NONCE_LEN]);
    let (length_key, length_nonce) = header_keys(
        cmd_key,
        LABEL_LENGTH_KEY,
        LABEL_LENGTH_NONCE,
        &auth_id,
        &connection_nonce,
    );
    let mut length_bytes = [0_u8; 2];
    if aes_open(
        &length_key,
        &length_nonce,
        &auth_id,
        &bytes[AUTH_ID_LEN..nonce_start],
        &mut length_bytes,
    )
    .is_err()
    {
        return RequestProgress::Invalid;
    }
    let length = usize::from(u16::from_be_bytes(length_bytes));
    if length > INSTRUCTION_MAX {
        return RequestProgress::Invalid;
    }
    let total = nonce_start + CONNECTION_NONCE_LEN + length + TAG_LEN;
    if bytes.len() < total {
        return RequestProgress::NeedMore;
    }
    let (header_key, header_nonce) = header_keys(
        cmd_key,
        LABEL_HEADER_KEY,
        LABEL_HEADER_NONCE,
        &auth_id,
        &connection_nonce,
    );
    let mut instruction = [0_u8; INSTRUCTION_MAX];
    if aes_open(
        &header_key,
        &header_nonce,
        &auth_id,
        &bytes[nonce_start + CONNECTION_NONCE_LEN..total],
        &mut instruction[..length],
    )
    .is_err()
    {
        return RequestProgress::Invalid;
    }
    match parse_instruction(&instruction[..length]) {
        Ok(instruction) => RequestProgress::Complete(Request {
            auth_id,
            command: instruction.command,
            target: instruction.target,
            security: instruction.security,
            option: instruction.option,
            body_key: instruction.body_key,
            body_iv: instruction.body_iv,
            response_auth: instruction.response_auth,
            consumed: total,
        }),
        Err(_) => RequestProgress::Invalid,
    }
}

/// Encodes the encrypted response header.
pub fn encode_response(request: &Request, out: &mut [u8]) -> Result<usize, VmessError> {
    let (response_key, response_iv) = response_keys(&request.body_key, &request.body_iv);
    let mut plaintext = [0_u8; 4];
    plaintext[0] = request.response_auth;
    let length_block = LENGTH_BLOCK_LEN;
    let payload_start = length_block;
    let payload_end = payload_start + plaintext.len() + TAG_LEN;
    if out.len() < payload_end {
        return Err(VmessError::NoSpace);
    }
    let (length_key, length_nonce) = response_header_keys(
        &response_key,
        &response_iv,
        LABEL_RESPONSE_LENGTH_KEY,
        LABEL_RESPONSE_LENGTH_NONCE,
    );
    aes_seal(
        &length_key,
        &length_nonce,
        b"",
        &(plaintext.len() as u16).to_be_bytes(),
        &mut out[..length_block],
    )?;
    let (key, nonce) = response_header_keys(
        &response_key,
        &response_iv,
        LABEL_RESPONSE_KEY,
        LABEL_RESPONSE_NONCE,
    );
    aes_seal(
        &key,
        &nonce,
        b"",
        &plaintext,
        &mut out[payload_start..payload_end],
    )?;
    Ok(payload_end)
}

/// Progress of a response header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseProgress {
    /// More bytes are needed.
    NeedMore {
        /// Bytes needed to make progress.
        needed: usize,
    },
    /// The header is malformed or fails authentication.
    Invalid,
    /// A complete response header.
    Complete {
        /// Bytes consumed.
        consumed: usize,
    },
}

/// Evaluates the bytes read so far as a response header.
#[must_use]
pub fn response_progress(bytes: &[u8], request: &Request) -> ResponseProgress {
    let (response_key, response_iv) = response_keys(&request.body_key, &request.body_iv);
    let (length_key, length_nonce) = response_header_keys(
        &response_key,
        &response_iv,
        LABEL_RESPONSE_LENGTH_KEY,
        LABEL_RESPONSE_LENGTH_NONCE,
    );
    if bytes.len() < LENGTH_BLOCK_LEN {
        return ResponseProgress::NeedMore {
            needed: LENGTH_BLOCK_LEN,
        };
    }
    let mut length_bytes = [0_u8; 2];
    if aes_open(
        &length_key,
        &length_nonce,
        b"",
        &bytes[..LENGTH_BLOCK_LEN],
        &mut length_bytes,
    )
    .is_err()
    {
        return ResponseProgress::Invalid;
    }
    let length = usize::from(u16::from_be_bytes(length_bytes));
    if length == 0 || length > 255 {
        return ResponseProgress::Invalid;
    }
    let total = LENGTH_BLOCK_LEN + length + TAG_LEN;
    if bytes.len() < total {
        return ResponseProgress::NeedMore { needed: total };
    }
    let (key, nonce) = response_header_keys(
        &response_key,
        &response_iv,
        LABEL_RESPONSE_KEY,
        LABEL_RESPONSE_NONCE,
    );
    let mut plaintext = [0_u8; 255];
    if aes_open(
        &key,
        &nonce,
        b"",
        &bytes[LENGTH_BLOCK_LEN..total],
        &mut plaintext[..length],
    )
    .is_err()
    {
        return ResponseProgress::Invalid;
    }
    if plaintext[0] != request.response_auth || length < 4 {
        return ResponseProgress::Invalid;
    }
    match plaintext[2] {
        0 => {}
        _ => return ResponseProgress::Invalid,
    }
    if plaintext[3] != 0 {
        return ResponseProgress::Invalid;
    }
    ResponseProgress::Complete { consumed: total }
}

/// Progress of one body chunk.
#[derive(Debug)]
pub enum ChunkProgress {
    /// More bytes are needed; `needed` is absolute against the passed slice.
    NeedMore {
        /// Bytes needed to complete the current chunk.
        needed: usize,
    },
    /// One complete chunk.
    Complete {
        /// Bytes consumed.
        consumed: usize,
        /// Decrypted payload.
        data: Vec<u8>,
    },
}

struct Pending {
    total: usize,
    padding: usize,
}

enum BodyCipherKind {
    Aes(Box<Aes128Gcm>),
    ChaCha(Box<ChaCha20Poly1305>),
}

struct BodyCipher {
    kind: BodyCipherKind,
    key: [u8; 16],
}

impl BodyCipher {
    fn new(security: Security, key: &[u8; 16]) -> Self {
        let kind = match security {
            Security::Aes128Gcm => BodyCipherKind::Aes(Box::new(
                Aes128Gcm::new_from_slice(key).expect("16-byte AES-128-GCM key"),
            )),
            Security::ChaCha20Poly1305 => BodyCipherKind::ChaCha(Box::new(
                ChaCha20Poly1305::new_from_slice(&chacha_key(key))
                    .expect("32-byte ChaCha20-Poly1305 key"),
            )),
        };
        Self { kind, key: *key }
    }

    fn seal(
        &self, nonce: &[u8; 12], plaintext: &[u8], out: &mut [u8],
    ) -> Result<[u8; 16], VmessError> {
        let nonce = Nonce::try_from(&nonce[..]).map_err(|_| VmessError::Crypto)?;
        let inout = InOutBuf::new(plaintext, out).map_err(|_| VmessError::NoSpace)?;
        let tag = match &self.kind {
            BodyCipherKind::Aes(cipher) => cipher
                .encrypt_inout_detached(&nonce, b"", inout)
                .map_err(|_| VmessError::Crypto)?,
            BodyCipherKind::ChaCha(cipher) => cipher
                .encrypt_inout_detached(&nonce, b"", inout)
                .map_err(|_| VmessError::Crypto)?,
        };
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(tag.as_slice());
        Ok(bytes)
    }

    fn open(
        &self, nonce: &[u8; 12], ciphertext: &[u8], tag: &[u8], out: &mut [u8],
    ) -> Result<(), VmessError> {
        let nonce = Nonce::try_from(&nonce[..]).map_err(|_| VmessError::Crypto)?;
        let tag = aes_gcm::Tag::try_from(tag).map_err(|_| VmessError::AuthenticationFailed)?;
        let inout = InOutBuf::new(ciphertext, out).map_err(|_| VmessError::NoSpace)?;
        match &self.kind {
            BodyCipherKind::Aes(cipher) => cipher
                .decrypt_inout_detached(&nonce, b"", inout, &tag)
                .map_err(|_| VmessError::AuthenticationFailed),
            BodyCipherKind::ChaCha(cipher) => cipher
                .decrypt_inout_detached(&nonce, b"", inout, &tag)
                .map_err(|_| VmessError::AuthenticationFailed),
        }
    }
}

impl Drop for BodyCipher {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// Decodes body chunks in one direction.
pub struct ChunkDecoder {
    cipher: BodyCipher,
    iv: [u8; 16],
    mask: Option<Shake128Reader>,
    global_padding: bool,
    counter: u16,
    chunks: u32,
    pending: Option<Pending>,
}

impl ChunkDecoder {
    /// Builds a decoder for one direction.
    pub fn new(security: Security, key: &[u8; 16], iv: &[u8; 16], option: u8) -> Self {
        Self {
            cipher: BodyCipher::new(security, key),
            iv: *iv,
            mask: if option & OPTION_MASKING != 0 {
                Some(shake(iv))
            } else {
                None
            },
            global_padding: option & OPTION_PADDING != 0,
            counter: 0,
            chunks: 0,
            pending: None,
        }
    }

    /// Parses as much of the current chunk as `bytes` contains.
    pub fn progress(&mut self, bytes: &[u8]) -> Result<ChunkProgress, VmessError> {
        if self.pending.is_none() {
            if bytes.len() < 2 {
                return Ok(ChunkProgress::NeedMore { needed: 2 });
            }
            if self.chunks >= MAX_CHUNKS {
                return Err(VmessError::ChunkLimit);
            }
            let padding = if self.global_padding {
                let mask = self.mask.as_mut().ok_or(VmessError::InvalidHeader)?;
                usize::from(mask.next_u16() % 64)
            } else {
                0
            };
            let wire = u16::from_be_bytes([bytes[0], bytes[1]]);
            let length = match self.mask.as_mut() {
                Some(mask) => usize::from(wire ^ mask.next_u16()),
                None => usize::from(wire),
            };
            if length > CHUNK_LENGTH_MAX || length < TAG_LEN + padding {
                return Err(VmessError::InvalidHeader);
            }
            self.pending = Some(Pending {
                total: length,
                padding,
            });
        }
        let pending = self.pending.as_ref().ok_or(VmessError::InvalidHeader)?;
        let total = 2 + pending.total;
        if bytes.len() < total {
            return Ok(ChunkProgress::NeedMore { needed: total });
        }
        let ciphertext_len = pending.total - pending.padding;
        let body_len = ciphertext_len - TAG_LEN;
        let nonce = chunk_nonce(self.counter, &self.iv);
        let mut data = vec![0_u8; body_len];
        if body_len > 0 {
            self.cipher.open(
                &nonce,
                &bytes[2..2 + body_len],
                &bytes[2 + body_len..2 + ciphertext_len],
                &mut data,
            )?;
        }
        self.pending = None;
        self.chunks += 1;
        self.counter = self.counter.wrapping_add(1);
        Ok(ChunkProgress::Complete {
            consumed: total,
            data,
        })
    }
}

/// Encodes body chunks in one direction.
pub struct ChunkEncoder {
    cipher: BodyCipher,
    iv: [u8; 16],
    mask: Option<Shake128Reader>,
    global_padding: bool,
    counter: u16,
    chunks: u32,
    padding_source: [u8; 64],
    padding_offset: usize,
}

impl ChunkEncoder {
    /// Builds an encoder for one direction; `padding_source` supplies cover
    /// bytes for global padding.
    pub fn new(
        security: Security, key: &[u8; 16], iv: &[u8; 16], option: u8, padding_source: [u8; 64],
    ) -> Self {
        Self {
            cipher: BodyCipher::new(security, key),
            iv: *iv,
            mask: if option & OPTION_MASKING != 0 {
                Some(shake(iv))
            } else {
                None
            },
            global_padding: option & OPTION_PADDING != 0,
            counter: 0,
            chunks: 0,
            padding_source,
            padding_offset: 0,
        }
    }

    /// Encodes one chunk into `out`, replacing any previous contents.
    pub fn encode(&mut self, plaintext: &[u8], out: &mut Vec<u8>) -> Result<(), VmessError> {
        if plaintext.len() > CHUNK_PLAINTEXT_MAX {
            return Err(VmessError::MessageTooBig);
        }
        if self.chunks >= MAX_CHUNKS {
            return Err(VmessError::ChunkLimit);
        }
        let padding = if self.global_padding {
            let mask = self.mask.as_mut().ok_or(VmessError::InvalidHeader)?;
            usize::from(mask.next_u16() % 64)
        } else {
            0
        };
        let length_mask = self.mask.as_mut().map(Mask::next_u16).unwrap_or(0);
        let ciphertext_len = plaintext.len() + TAG_LEN;
        let total = ciphertext_len + padding;
        if total > CHUNK_LENGTH_MAX {
            return Err(VmessError::MessageTooBig);
        }
        out.clear();
        out.reserve(2 + total);
        out.extend_from_slice(&[0, 0]);
        let start = out.len();
        out.resize(start + ciphertext_len, 0);
        let nonce = chunk_nonce(self.counter, &self.iv);
        if !plaintext.is_empty() {
            let tag =
                self.cipher
                    .seal(&nonce, plaintext, &mut out[start..start + plaintext.len()])?;
            out[start + plaintext.len()..start + ciphertext_len].copy_from_slice(&tag);
        } else {
            let tag = self.cipher.seal(&nonce, &[], &mut [])?;
            out[start..start + TAG_LEN].copy_from_slice(&tag);
        }
        for index in 0..padding {
            let byte = self.padding_source[(self.padding_offset + index) % 64];
            out.push(byte);
        }
        self.padding_offset = (self.padding_offset + padding) % 64;
        let wire = (total as u16) ^ length_mask;
        out[0..2].copy_from_slice(&wire.to_be_bytes());
        self.chunks += 1;
        self.counter = self.counter.wrapping_add(1);
        Ok(())
    }
}

trait Mask {
    fn next_u16(&mut self) -> u16;
}

impl Mask for Shake128Reader {
    fn next_u16(&mut self) -> u16 {
        let mut bytes = [0_u8; 2];
        self.read(&mut bytes);
        u16::from_be_bytes(bytes)
    }
}

fn shake(iv: &[u8; 16]) -> Shake128Reader {
    let mut hasher = Shake128::default();
    sha3::digest::Update::update(&mut hasher, iv);
    hasher.finalize_xof()
}

fn chacha_key(key: &[u8; 16]) -> [u8; 32] {
    let first = md5_digest(key);
    let second = md5_digest(&first);
    let mut out = [0_u8; 32];
    out[..16].copy_from_slice(&first);
    out[16..].copy_from_slice(&second);
    out
}

fn md5_digest(data: &[u8]) -> [u8; 16] {
    let mut hasher = md5::Md5::new();
    hasher.update(data);
    let digest = hasher.finalize();
    let mut out = [0_u8; 16];
    out.copy_from_slice(&digest);
    out
}

fn chunk_nonce(counter: u16, iv: &[u8; 16]) -> [u8; 12] {
    let mut nonce = [0_u8; 12];
    nonce[..2].copy_from_slice(&counter.to_be_bytes());
    nonce[2..].copy_from_slice(&iv[2..12]);
    nonce
}

fn kdf(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
    kdf_level(path.len(), path, key)
}

/// The reference KDF nests the previous HMAC as the next HMAC's hash function:
///
/// ```text
/// H0(y) = HMAC-SHA256("VMess AEAD KDF", y)
/// Hn(y) = H(n-1)(opad || H(n-1)(ipad || y)), keyed by path[n-1]
/// ```
///
/// It is not a chain of HMAC keys; a plain keyed chain does not interoperate.
fn kdf_level(level: usize, path: &[&[u8]], message: &[u8]) -> [u8; 32] {
    if level == 0 {
        let mut state = Hmac::<Sha256>::new_from_slice(KDF_SALT).expect("static KDF salt");
        state.update(message);
        let digest = state.finalize().into_bytes();
        let mut out = [0_u8; 32];
        out.copy_from_slice(&digest);
        return out;
    }
    let item = path[level - 1];
    let mut block = [0_u8; 64];
    if item.len() > 64 {
        let digest = kdf_level(level - 1, path, item);
        block[..32].copy_from_slice(&digest);
    } else {
        block[..item.len()].copy_from_slice(item);
    }
    let mut inner = Vec::with_capacity(64 + message.len());
    let mut outer = Vec::with_capacity(64 + 32);
    for byte in &block {
        inner.push(byte ^ 0x36);
        outer.push(byte ^ 0x5c);
    }
    inner.extend_from_slice(message);
    let inner_digest = kdf_level(level - 1, path, &inner);
    outer.extend_from_slice(&inner_digest);
    kdf_level(level - 1, path, &outer)
}

fn header_keys(
    cmd_key: &CmdKey, key_label: &[u8], nonce_label: &[u8], auth_id: &[u8; 16], nonce: &[u8; 8],
) -> ([u8; 16], [u8; 12]) {
    let key_path = [key_label, &auth_id[..], &nonce[..]];
    let nonce_path = [nonce_label, &auth_id[..], &nonce[..]];
    key_and_nonce(
        &kdf(cmd_key.as_bytes(), &key_path),
        &kdf(cmd_key.as_bytes(), &nonce_path),
    )
}

/// Derives the response header and body key/IV from the request material.
///
/// Both peers derive these from the request body key and IV, so the codec
/// exposes the derivation for the stream layer.
#[must_use]
pub fn response_keys(body_key: &[u8; 16], body_iv: &[u8; 16]) -> ([u8; 16], [u8; 16]) {
    let key = Sha256::digest(body_key);
    let iv = Sha256::digest(body_iv);
    let mut key16 = [0_u8; 16];
    let mut iv16 = [0_u8; 16];
    key16.copy_from_slice(&key[..16]);
    iv16.copy_from_slice(&iv[..16]);
    (key16, iv16)
}

fn response_header_keys(
    key: &[u8; 16], iv: &[u8; 16], key_label: &[u8], nonce_label: &[u8],
) -> ([u8; 16], [u8; 12]) {
    key_and_nonce(&kdf(key, &[key_label]), &kdf(iv, &[nonce_label]))
}

fn key_and_nonce(key: &[u8; 32], nonce: &[u8; 32]) -> ([u8; 16], [u8; 12]) {
    let mut key_out = [0_u8; 16];
    let mut nonce_out = [0_u8; 12];
    key_out.copy_from_slice(&key[..16]);
    nonce_out.copy_from_slice(&nonce[..12]);
    (key_out, nonce_out)
}

fn aes_seal(
    key: &[u8; 16], nonce: &[u8; 12], aad: &[u8], plaintext: &[u8], out: &mut [u8],
) -> Result<(), VmessError> {
    if out.len() < plaintext.len() + TAG_LEN {
        return Err(VmessError::NoSpace);
    }
    let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| VmessError::Crypto)?;
    let nonce = Nonce::try_from(&nonce[..]).map_err(|_| VmessError::Crypto)?;
    let (body, tag_out) = out.split_at_mut(plaintext.len());
    let inout = InOutBuf::new(plaintext, body).map_err(|_| VmessError::NoSpace)?;
    let tag = cipher
        .encrypt_inout_detached(&nonce, aad, inout)
        .map_err(|_| VmessError::Crypto)?;
    tag_out[..TAG_LEN].copy_from_slice(tag.as_slice());
    Ok(())
}

fn aes_open(
    key: &[u8; 16], nonce: &[u8; 12], aad: &[u8], ciphertext: &[u8], out: &mut [u8],
) -> Result<(), VmessError> {
    if ciphertext.len() < TAG_LEN {
        return Err(VmessError::AuthenticationFailed);
    }
    let split = ciphertext.len() - TAG_LEN;
    let (body, tag) = ciphertext.split_at(split);
    let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| VmessError::Crypto)?;
    let nonce = Nonce::try_from(&nonce[..]).map_err(|_| VmessError::Crypto)?;
    let tag = aes_gcm::Tag::try_from(tag).map_err(|_| VmessError::AuthenticationFailed)?;
    let inout = InOutBuf::new(body, out).map_err(|_| VmessError::NoSpace)?;
    cipher
        .decrypt_inout_detached(&nonce, aad, inout, &tag)
        .map_err(|_| VmessError::AuthenticationFailed)
}

fn seal_auth_id(cmd_key: &CmdKey, timestamp: u64, rand: &[u8; 4]) -> [u8; 16] {
    let key = auth_id_key(cmd_key);
    let mut block = [0_u8; 16];
    block[..8].copy_from_slice(&timestamp.to_be_bytes());
    block[8..12].copy_from_slice(rand);
    let crc = crc32_ieee(&block[..12]);
    block[12..].copy_from_slice(&crc.to_be_bytes());
    let cipher = Aes128::new_from_slice(&key).expect("16-byte AES key");
    let mut aes_block = aes::Block::from(block);
    cipher.encrypt_block(&mut aes_block);
    let mut out = [0_u8; 16];
    out.copy_from_slice(&aes_block);
    out
}

fn open_auth_id(cmd_key: &CmdKey, auth_id: &[u8; 16], now_unix: u64) -> Option<u64> {
    let key = auth_id_key(cmd_key);
    let cipher = Aes128::new_from_slice(&key).expect("16-byte AES key");
    let mut block = aes::Block::from(*auth_id);
    cipher.decrypt_block(&mut block);
    let mut plaintext = [0_u8; 16];
    plaintext.copy_from_slice(&block);
    let crc = u32::from_be_bytes([plaintext[12], plaintext[13], plaintext[14], plaintext[15]]);
    if crc != crc32_ieee(&plaintext[..12]) {
        plaintext.zeroize();
        return None;
    }
    let timestamp = u64::from_be_bytes([
        plaintext[0],
        plaintext[1],
        plaintext[2],
        plaintext[3],
        plaintext[4],
        plaintext[5],
        plaintext[6],
        plaintext[7],
    ]);
    plaintext.zeroize();
    (timestamp.abs_diff(now_unix) <= TIMESTAMP_WINDOW_S).then_some(timestamp)
}

fn auth_id_key(cmd_key: &CmdKey) -> [u8; 16] {
    let derived = kdf(cmd_key.as_bytes(), &[LABEL_AUTH_ID]);
    let mut key = [0_u8; 16];
    key.copy_from_slice(&derived[..16]);
    key
}

struct Instruction {
    command: u8,
    target: Endpoint,
    security: Security,
    option: u8,
    body_key: [u8; 16],
    body_iv: [u8; 16],
    response_auth: u8,
}

fn parse_instruction(instruction: &[u8]) -> Result<Instruction, VmessError> {
    if instruction.len() < 42 || instruction[0] != VERSION {
        return Err(VmessError::InvalidHeader);
    }
    let option = instruction[34];
    if option & (OPTION_AUTHENTICATED_LENGTH | 0xE0) != 0 || option & OPTION_STREAM == 0 {
        return Err(VmessError::UnsupportedOption);
    }
    if option & OPTION_PADDING != 0 && option & OPTION_MASKING == 0 {
        return Err(VmessError::UnsupportedOption);
    }
    if instruction[36] != 0 {
        return Err(VmessError::InvalidHeader);
    }
    let security = Security::from_wire(instruction[35] & 0x0F)?;
    let padding = usize::from(instruction[35] >> 4);
    let command = instruction[37];
    if command != COMMAND_TCP && command != COMMAND_UDP && command != COMMAND_MUX {
        return Err(VmessError::UnsupportedCommand);
    }
    let (target, next) = if command == COMMAND_MUX {
        (
            Endpoint::from_domain(MUX_DOMAIN, MUX_PORT).map_err(|_| VmessError::InvalidHeader)?,
            38,
        )
    } else {
        let port = u16::from_be_bytes([instruction[38], instruction[39]]);
        match vless::decode_address(instruction, 40, port) {
            Ok(Some(value)) => value,
            _ => return Err(VmessError::InvalidHeader),
        }
    };
    if next + padding + 4 != instruction.len() {
        return Err(VmessError::InvalidHeader);
    }
    let checksum_offset = instruction.len() - 4;
    let expected = u32::from_be_bytes([
        instruction[checksum_offset],
        instruction[checksum_offset + 1],
        instruction[checksum_offset + 2],
        instruction[checksum_offset + 3],
    ]);
    if fnv1a(&instruction[..checksum_offset]) != expected {
        return Err(VmessError::InvalidHeader);
    }
    let mut body_key = [0_u8; 16];
    let mut body_iv = [0_u8; 16];
    body_iv.copy_from_slice(&instruction[1..17]);
    body_key.copy_from_slice(&instruction[17..33]);
    Ok(Instruction {
        command,
        target,
        security,
        option,
        body_key,
        body_iv,
        response_auth: instruction[33],
    })
}

/// Returns true when `endpoint` is the synthetic Mux.Cool target.
#[must_use]
pub fn is_mux_target(endpoint: &Endpoint) -> bool {
    endpoint.domain() == Some(MUX_DOMAIN)
}

fn map_vless(error: VlessError) -> VmessError {
    match error {
        VlessError::NoSpace => VmessError::NoSpace,
        _ => VmessError::InvalidHeader,
    }
}

fn fnv1a(data: &[u8]) -> u32 {
    let mut hash = 0x811c_9dc5_u32;
    for byte in data {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFF_u32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Why a VMess operation failed.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum VmessError {
    /// The output buffer was too small.
    #[error("output buffer is too small")]
    NoSpace,
    /// The instruction or a frame is malformed.
    #[error("invalid VMess header")]
    InvalidHeader,
    /// The instruction length exceeds the fixed bound.
    #[error("VMess header is too big")]
    HeaderTooBig,
    /// The command is not supported.
    #[error("unsupported VMess command")]
    UnsupportedCommand,
    /// The body security value is not supported.
    #[error("unsupported VMess security")]
    UnsupportedSecurity,
    /// An option bit is not supported.
    #[error("unsupported VMess option")]
    UnsupportedOption,
    /// The authenticated data did not verify.
    #[error("VMess authentication failed")]
    AuthenticationFailed,
    /// The 16-bit chunk counter is exhausted.
    #[error("VMess chunk limit reached")]
    ChunkLimit,
    /// A payload is too large for one chunk.
    #[error("VMess message is too big")]
    MessageTooBig,
    /// A cryptographic primitive rejected its input.
    #[error("VMess crypto error")]
    Crypto,
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID_TEXT: &str = "00112233-4455-6677-8899-aabbccddeeff";

    fn cmd_key() -> CmdKey {
        CmdKey::derive(&Uuid::parse(UUID_TEXT).expect("uuid"))
    }

    fn secrets() -> RequestSecrets {
        RequestSecrets {
            body_iv: [0x11; 16],
            body_key: [0x22; 16],
            response_auth: 0x5a,
            auth_rand: [0x33; 4],
            connection_nonce: [0x44; 8],
        }
    }

    fn request(command: u8, security: Security) -> Request {
        let target = Endpoint::from_domain("example.com", 443).expect("target");
        let mut header = [0_u8; REQUEST_HEADER_MAX];
        let length = encode_request(
            &cmd_key(),
            &RequestSpec {
                target: &target,
                command,
                security,
                timestamp: 1_700_000_000,
                padding: &[0xaa, 0xbb],
                secrets: &secrets(),
            },
            &mut header,
        )
        .expect("encode");
        let RequestProgress::Complete(request) =
            request_progress(&header[..length], &cmd_key(), 1_700_000_000)
        else {
            panic!("expected a complete request");
        };
        assert_eq!(request.consumed, length);
        request
    }

    #[test]
    fn round_trips_requests() {
        for security in [Security::Aes128Gcm, Security::ChaCha20Poly1305] {
            for command in [COMMAND_TCP, COMMAND_UDP] {
                let request = request(command, security);
                assert_eq!(request.command, command);
                assert_eq!(request.security, security);
                assert_eq!(request.target.domain(), Some("example.com"));
                assert_eq!(request.target.port(), 443);
                assert_eq!(request.response_auth, 0x5a);
            }
        }
        let mux = request(COMMAND_MUX, Security::Aes128Gcm);
        assert_eq!(mux.target.domain(), Some(MUX_DOMAIN));
        assert!(is_mux_target(&mux.target));
    }

    #[test]
    fn rejects_bad_timestamps_and_tampering() {
        let target = Endpoint::from_domain("example.com", 80).expect("target");
        let mut header = [0_u8; REQUEST_HEADER_MAX];
        let length = encode_request(
            &cmd_key(),
            &RequestSpec {
                target: &target,
                command: COMMAND_TCP,
                security: Security::Aes128Gcm,
                timestamp: 1_700_000_000,
                padding: &[],
                secrets: &secrets(),
            },
            &mut header,
        )
        .expect("encode");
        assert!(matches!(
            request_progress(
                &header[..length],
                &cmd_key(),
                1_700_000_000 + TIMESTAMP_WINDOW_S + 1
            ),
            RequestProgress::Unauthorized
        ));
        let mut tampered = header;
        tampered[length - 1] ^= 1;
        assert!(matches!(
            request_progress(&tampered[..length], &cmd_key(), 1_700_000_000),
            RequestProgress::Invalid
        ));
        for split in 0..length {
            assert!(matches!(
                request_progress(&header[..split], &cmd_key(), 1_700_000_000),
                RequestProgress::NeedMore | RequestProgress::Unauthorized
            ));
        }
    }

    #[test]
    fn response_round_trips() {
        let request = request(COMMAND_TCP, Security::Aes128Gcm);
        let mut response = [0_u8; 128];
        let length = encode_response(&request, &mut response).expect("encode");
        assert_eq!(
            response_progress(&response[..length], &request),
            ResponseProgress::Complete { consumed: length }
        );
        let mut wrong = response;
        wrong[length - 1] ^= 1;
        assert_eq!(
            response_progress(&wrong[..length], &request),
            ResponseProgress::Invalid
        );
    }

    #[test]
    fn chunk_round_trips_and_rejects_tampering() {
        let key = [0x22_u8; 16];
        let iv = [0x11_u8; 16];
        let option = OPTION_STREAM | OPTION_MASKING | OPTION_PADDING;
        for security in [Security::Aes128Gcm, Security::ChaCha20Poly1305] {
            let mut encoder = ChunkEncoder::new(security, &key, &iv, option, [0x7f; 64]);
            let mut decoder = ChunkDecoder::new(security, &key, &iv, option);
            let mut wire = Vec::new();
            for payload in [b"first".as_slice(), b"second chunk".as_slice()] {
                encoder.encode(payload, &mut wire).expect("encode");
                let ChunkProgress::Complete { consumed, data } =
                    decoder.progress(&wire).expect("decode")
                else {
                    panic!("expected a chunk");
                };
                assert_eq!(data, payload);
                assert_eq!(consumed, wire.len());
            }

            encoder.encode(b"tamper", &mut wire).expect("encode");
            wire[2] ^= 1;
            assert!(decoder.progress(&wire).is_err());
        }
    }

    #[test]
    fn chunk_handles_every_split() {
        let key = [0x22_u8; 16];
        let iv = [0x11_u8; 16];
        let option = OPTION_STREAM | OPTION_MASKING | OPTION_PADDING;
        let mut encoder = ChunkEncoder::new(Security::Aes128Gcm, &key, &iv, option, [0; 64]);
        let mut wire = Vec::new();
        encoder.encode(&[0x55; 1000], &mut wire).expect("encode");
        let mut decoder = ChunkDecoder::new(Security::Aes128Gcm, &key, &iv, option);
        for split in 0..wire.len() {
            let empty: &[u8] = &[];
            let _ = decoder.progress(empty);
            match decoder.progress(&wire[..split]) {
                Ok(ChunkProgress::NeedMore { needed }) => assert!(needed > split || split == 0),
                other => panic!("unexpected result at split {split}: {other:?}"),
            }
        }
        let ChunkProgress::Complete { data, .. } = decoder.progress(&wire).expect("decode") else {
            panic!("expected a chunk");
        };
        assert_eq!(data, vec![0x55; 1000]);
    }

    #[test]
    fn checksum_vectors() {
        assert_eq!(crc32_ieee(b"123456789"), 0xCBF4_3926);
        assert_eq!(fnv1a(b""), 0x811C_9DC5);
    }

    #[test]
    fn kdf_matches_the_spec_vectors() {
        fn hex(bytes: &[u8]) -> String {
            bytes.iter().map(|byte| format!("{byte:02x}")).collect()
        }

        let key = CmdKey::derive(&Uuid::parse(UUID_TEXT).expect("uuid"));
        assert_eq!(
            hex(&kdf(key.as_bytes(), &[LABEL_AUTH_ID])),
            "870e934a0d8e955ec8df4c2ee2390b5d4e44e24acacff61a7c9b53425d5a8974"
        );
        assert_eq!(
            hex(&kdf(
                key.as_bytes(),
                &[LABEL_LENGTH_KEY, &[0x11; 16], &[0x22; 8]],
            )),
            "9af7a347279d6b2986737eee8d5957c38b6a2a07b4ae360f4c5375142164d5cf"
        );
        assert_eq!(
            hex(&kdf(&[0x33; 16], &[LABEL_RESPONSE_KEY])),
            "c92ac826ca67227abb0908a6ca97c4b4497584a578a57d3291d0055aebfe7a2b"
        );
    }
}
