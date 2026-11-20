//! Shadowsocks 2022 (SIP022): keys, AEAD framing, addresses, and UDP packets.
//!
//! Only `2022-blake3-aes-128-gcm` and `2022-blake3-aes-256-gcm` are
//! implemented. The TCP request/response streams and replay caches build on
//! these primitives in the inbound/outbound layers.

use std::fmt;

use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit as BlockKeyInit};
use aes::{Aes128, Aes256};
use aes_gcm::aead::{AeadInOut, inout::InOutBuf};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce, Tag};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use marmo_net::Endpoint;
use thiserror::Error;
use zeroize::Zeroize;

/// AEAD tag length.
pub const TAG_LENGTH: usize = 16;
/// AEAD nonce length.
pub const NONCE_LENGTH: usize = 12;
/// Maximum plaintext body for one UDP packet.
pub const MAX_PAYLOAD: usize = 65_535;
/// Allowed timestamp skew in seconds.
pub const TIMESTAMP_WINDOW_S: u64 = 30;
/// Maximum request padding accepted by the server.
pub const MAX_PADDING: usize = 900;

const SUBKEY_CONTEXT: &str = "shadowsocks 2022 session subkey";

/// Supported Shadowsocks 2022 methods.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Method {
    /// `2022-blake3-aes-128-gcm`.
    Aes128Gcm,
    /// `2022-blake3-aes-256-gcm`.
    Aes256Gcm,
}

impl Method {
    /// Parses the configured method string.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "2022-blake3-aes-128-gcm" => Some(Self::Aes128Gcm),
            "2022-blake3-aes-256-gcm" => Some(Self::Aes256Gcm),
            _ => None,
        }
    }

    /// Returns the PSK and salt length.
    #[must_use]
    pub const fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm => 32,
        }
    }

    /// Returns the salt length (equal to the key length).
    #[must_use]
    pub const fn salt_len(self) -> usize {
        self.key_len()
    }
}

/// A decoded PSK.
pub struct Key {
    bytes: [u8; 32],
    len: u8,
}

impl Key {
    /// Decodes a base64 PSK and checks its length against `method`.
    pub fn parse(method: Method, password: &str) -> Result<Self, SsError> {
        let mut decoded = STANDARD.decode(password).map_err(|_| SsError::InvalidKey)?;
        if decoded.len() != method.key_len() {
            decoded.zeroize();
            return Err(SsError::InvalidKey);
        }
        let mut bytes = [0_u8; 32];
        bytes[..decoded.len()].copy_from_slice(&decoded);
        decoded.zeroize();
        Ok(Self {
            bytes,
            len: method.key_len() as u8,
        })
    }

    /// Returns the key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Key(<redacted>)")
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        self.bytes.zeroize();
        self.len = 0;
    }
}

/// Derives the per-session subkey from the PSK and salt.
#[must_use]
pub fn derive_subkey(method: Method, psk: &[u8], salt: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(SUBKEY_CONTEXT);
    hasher.update(psk);
    hasher.update(salt);
    let mut out = [0_u8; 32];
    hasher.finalize_xof().fill(&mut out[..method.key_len()]);
    out
}

/// Encrypts `plaintext` and appends the tag to `out`.
pub fn seal(
    method: Method,
    key: &[u8],
    nonce: [u8; NONCE_LENGTH],
    plaintext: &[u8],
    out: &mut [u8],
) -> Result<usize, SsError> {
    if key.len() < method.key_len() {
        return Err(SsError::InvalidKey);
    }
    let total = plaintext.len() + TAG_LENGTH;
    if out.len() < total {
        return Err(SsError::NoSpace);
    }
    let tag = match method {
        Method::Aes128Gcm => {
            let cipher = Aes128Gcm::new_from_slice(&key[..16]).map_err(|_| SsError::Crypto)?;
            let nonce = Nonce::try_from(&nonce[..]).map_err(|_| SsError::Crypto)?;
            let inout = InOutBuf::new(plaintext, &mut out[..plaintext.len()])
                .map_err(|_| SsError::NoSpace)?;
            cipher
                .encrypt_inout_detached(&nonce, b"", inout)
                .map_err(|_| SsError::Crypto)?
        }
        Method::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(&key[..32]).map_err(|_| SsError::Crypto)?;
            let nonce = Nonce::try_from(&nonce[..]).map_err(|_| SsError::Crypto)?;
            let inout = InOutBuf::new(plaintext, &mut out[..plaintext.len()])
                .map_err(|_| SsError::NoSpace)?;
            cipher
                .encrypt_inout_detached(&nonce, b"", inout)
                .map_err(|_| SsError::Crypto)?
        }
    };
    out[plaintext.len()..total].copy_from_slice(&tag);
    Ok(total)
}

/// Decrypts `ciphertext` into `out`, verifying the tag.
pub fn open(
    method: Method,
    key: &[u8],
    nonce: [u8; NONCE_LENGTH],
    ciphertext: &[u8],
    out: &mut [u8],
) -> Result<usize, SsError> {
    if key.len() < method.key_len() {
        return Err(SsError::InvalidKey);
    }
    let plaintext_len = ciphertext
        .len()
        .checked_sub(TAG_LENGTH)
        .ok_or(SsError::AuthenticationFailed)?;
    if out.len() < plaintext_len {
        return Err(SsError::NoSpace);
    }
    out[..plaintext_len].copy_from_slice(&ciphertext[..plaintext_len]);
    let tag =
        Tag::try_from(&ciphertext[plaintext_len..]).map_err(|_| SsError::AuthenticationFailed)?;
    match method {
        Method::Aes128Gcm => {
            let cipher = Aes128Gcm::new_from_slice(&key[..16]).map_err(|_| SsError::Crypto)?;
            let nonce = Nonce::try_from(&nonce[..]).map_err(|_| SsError::Crypto)?;
            let inout = InOutBuf::new(&ciphertext[..plaintext_len], &mut out[..plaintext_len])
                .map_err(|_| SsError::NoSpace)?;
            cipher
                .decrypt_inout_detached(&nonce, b"", inout, &tag)
                .map_err(|_| SsError::AuthenticationFailed)?;
        }
        Method::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(&key[..32]).map_err(|_| SsError::Crypto)?;
            let nonce = Nonce::try_from(&nonce[..]).map_err(|_| SsError::Crypto)?;
            let inout = InOutBuf::new(&ciphertext[..plaintext_len], &mut out[..plaintext_len])
                .map_err(|_| SsError::NoSpace)?;
            cipher
                .decrypt_inout_detached(&nonce, b"", inout, &tag)
                .map_err(|_| SsError::AuthenticationFailed)?;
        }
    }
    Ok(plaintext_len)
}

/// Builds the little-endian nonce for a counter.
#[must_use]
pub fn nonce_from_counter(counter: u64) -> [u8; NONCE_LENGTH] {
    let mut nonce = [0_u8; NONCE_LENGTH];
    nonce[..8].copy_from_slice(&counter.to_le_bytes());
    nonce
}

/// Returns the current counter and advances it, rejecting exhaustion.
pub fn next_counter(counter: &mut u64) -> Result<u64, SsError> {
    let value = *counter;
    *counter = counter.checked_add(1).ok_or(SsError::CounterExhausted)?;
    Ok(value)
}

/// Decodes an `ATYP` address from `bytes` at `start`.
pub fn decode_address(bytes: &[u8], start: usize) -> Result<(Endpoint, usize), SsError> {
    if start >= bytes.len() {
        return Err(SsError::MalformedAddress);
    }
    let mut offset = start;
    let address_type = bytes[offset];
    offset += 1;
    match address_type {
        0x01 => {
            if offset + 6 > bytes.len() {
                return Err(SsError::MalformedAddress);
            }
            let address = std::net::Ipv4Addr::from([
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
            ]);
            let port = read_u16(&bytes[offset + 4..offset + 6]);
            Ok((Endpoint::from_ip(address.into(), port), offset + 6))
        }
        0x03 => {
            if offset + 1 > bytes.len() {
                return Err(SsError::MalformedAddress);
            }
            let length = usize::from(bytes[offset]);
            offset += 1;
            if length == 0 || offset + length + 2 > bytes.len() {
                return Err(SsError::MalformedAddress);
            }
            let name = std::str::from_utf8(&bytes[offset..offset + length])
                .map_err(|_| SsError::InvalidDomain)?;
            offset += length;
            let port = read_u16(&bytes[offset..offset + 2]);
            let endpoint = Endpoint::from_domain(name, port).map_err(|_| SsError::InvalidDomain)?;
            Ok((endpoint, offset + 2))
        }
        0x04 => {
            if offset + 18 > bytes.len() {
                return Err(SsError::MalformedAddress);
            }
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&bytes[offset..offset + 16]);
            let port = read_u16(&bytes[offset + 16..offset + 18]);
            Ok((
                Endpoint::from_ip(std::net::Ipv6Addr::from(octets).into(), port),
                offset + 18,
            ))
        }
        _ => Err(SsError::UnsupportedAddress),
    }
}

/// Encodes an `ATYP` address into `out`.
pub fn encode_address(endpoint: &Endpoint, out: &mut [u8]) -> Result<usize, SsError> {
    match endpoint.ip() {
        Some(std::net::IpAddr::V4(address)) => {
            if out.len() < 7 {
                return Err(SsError::NoSpace);
            }
            out[0] = 0x01;
            out[1..5].copy_from_slice(&address.octets());
            out[5..7].copy_from_slice(&endpoint.port().to_be_bytes());
            Ok(7)
        }
        Some(std::net::IpAddr::V6(address)) => {
            if out.len() < 19 {
                return Err(SsError::NoSpace);
            }
            out[0] = 0x04;
            out[1..17].copy_from_slice(&address.octets());
            out[17..19].copy_from_slice(&endpoint.port().to_be_bytes());
            Ok(19)
        }
        None => {
            let domain = endpoint.domain().ok_or(SsError::InvalidDomain)?;
            let length = u8::try_from(domain.len()).map_err(|_| SsError::InvalidDomain)?;
            if length == 0 {
                return Err(SsError::InvalidDomain);
            }
            let needed = 1 + 1 + domain.len() + 2;
            if out.len() < needed {
                return Err(SsError::NoSpace);
            }
            out[0] = 0x03;
            out[1] = length;
            out[2..2 + domain.len()].copy_from_slice(domain.as_bytes());
            out[2 + domain.len()..needed].copy_from_slice(&endpoint.port().to_be_bytes());
            Ok(needed)
        }
    }
}

fn read_u16(bytes: &[u8]) -> u16 {
    u16::from_be_bytes([bytes[0], bytes[1]])
}

/// UDP direction, selecting the authenticated body type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    /// Client to server.
    ClientToServer,
    /// Server to client.
    ServerToClient,
}

/// One UDP packet before encoding.
pub struct UdpPacket<'a> {
    /// Direction and body type.
    pub direction: Direction,
    /// Session ID (also the subkey salt).
    pub session_id: [u8; 8],
    /// Monotonic packet ID.
    pub packet_id: u64,
    /// Client session echoed by server-to-client packets.
    pub client_session_id: Option<[u8; 8]>,
    /// Destination or source address.
    pub destination: &'a Endpoint,
    /// Payload after the address.
    pub payload: &'a [u8],
    /// Padding length; padding bytes are zero.
    pub padding_len: u16,
    /// Unix timestamp in seconds.
    pub timestamp: u64,
}

/// A decoded UDP packet borrowing the plaintext buffer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpDecoded<'a> {
    /// Direction read from the authenticated body.
    pub direction: Direction,
    /// Session ID.
    pub session_id: [u8; 8],
    /// Packet ID.
    pub packet_id: u64,
    /// Client session echoed by server-to-client packets.
    pub client_session_id: Option<[u8; 8]>,
    /// Timestamp from the body.
    pub timestamp: u64,
    /// Source or destination address.
    pub destination: Endpoint,
    /// Payload.
    pub payload: &'a [u8],
}

/// Encodes one UDP packet.
pub fn encode_udp_packet(
    method: Method,
    psk: &[u8],
    packet: &UdpPacket<'_>,
    out: &mut [u8],
) -> Result<usize, SsError> {
    if psk.len() < method.key_len() {
        return Err(SsError::InvalidKey);
    }
    if packet.padding_len as usize > MAX_PADDING {
        return Err(SsError::NoSpace);
    }

    let mut body = [0_u8; MAX_PAYLOAD];
    let mut offset = 0;
    body[offset] = match packet.direction {
        Direction::ClientToServer => 0,
        Direction::ServerToClient => 1,
    };
    offset += 1;
    body[offset..offset + 8].copy_from_slice(&packet.timestamp.to_be_bytes());
    offset += 8;
    if packet.direction == Direction::ServerToClient {
        let client_session = packet
            .client_session_id
            .ok_or(SsError::MissingClientSession)?;
        body[offset..offset + 8].copy_from_slice(&client_session);
        offset += 8;
    }
    body[offset..offset + 2].copy_from_slice(&packet.padding_len.to_be_bytes());
    offset += 2;
    offset += usize::from(packet.padding_len);
    if offset > body.len() {
        return Err(SsError::NoSpace);
    }
    offset += encode_address(packet.destination, &mut body[offset..])?;
    if packet.payload.len() > body.len().saturating_sub(offset) {
        return Err(SsError::NoSpace);
    }
    body[offset..offset + packet.payload.len()].copy_from_slice(packet.payload);
    offset += packet.payload.len();

    if out.len() < 16 + offset + TAG_LENGTH {
        return Err(SsError::NoSpace);
    }
    let mut separate_plain = [0_u8; 16];
    separate_plain[..8].copy_from_slice(&packet.session_id);
    separate_plain[8..].copy_from_slice(&packet.packet_id.to_be_bytes());
    let separate_cipher = aes_block_encrypt(method, psk, &separate_plain)?;
    out[..16].copy_from_slice(&separate_cipher);

    let subkey = derive_subkey(method, psk, &packet.session_id);
    let mut nonce = [0_u8; NONCE_LENGTH];
    nonce.copy_from_slice(&separate_plain[4..16]);
    let sealed = seal(method, &subkey, nonce, &body[..offset], &mut out[16..])?;
    Ok(16 + sealed)
}

/// Decodes one UDP packet into `plaintext`.
pub fn decode_udp_packet<'a>(
    method: Method,
    psk: &[u8],
    packet: &[u8],
    expected_direction: Direction,
    expected_client_session: Option<[u8; 8]>,
    plaintext: &'a mut [u8],
) -> Result<UdpDecoded<'a>, SsError> {
    if psk.len() < method.key_len() {
        return Err(SsError::InvalidKey);
    }
    if packet.len() < 16 + TAG_LENGTH + 3 {
        return Err(SsError::MalformedPacket);
    }
    let separate_plain = aes_block_decrypt(method, psk, &packet[..16])?;
    let mut session_id = [0_u8; 8];
    session_id.copy_from_slice(&separate_plain[..8]);
    let packet_id = u64::from_be_bytes(
        separate_plain[8..16]
            .try_into()
            .map_err(|_| SsError::MalformedPacket)?,
    );

    let subkey = derive_subkey(method, psk, &session_id);
    let mut nonce = [0_u8; NONCE_LENGTH];
    nonce.copy_from_slice(&separate_plain[4..16]);
    let body_len = open(method, &subkey, nonce, &packet[16..], plaintext)?;
    if body_len < 11 {
        return Err(SsError::MalformedPacket);
    }

    let expected_type = match expected_direction {
        Direction::ClientToServer => 0,
        Direction::ServerToClient => 1,
    };
    if plaintext[0] != expected_type {
        return Err(SsError::ProtocolViolation);
    }
    let timestamp = u64::from_be_bytes(
        plaintext[1..9]
            .try_into()
            .map_err(|_| SsError::MalformedPacket)?,
    );
    let mut offset = 9;
    let mut client_session_id = None;
    if expected_direction == Direction::ServerToClient {
        if offset + 8 > body_len {
            return Err(SsError::MalformedPacket);
        }
        let mut id = [0_u8; 8];
        id.copy_from_slice(&plaintext[offset..offset + 8]);
        if let Some(expected) = expected_client_session {
            if id != expected {
                return Err(SsError::ProtocolViolation);
            }
        }
        client_session_id = Some(id);
        offset += 8;
    }
    if offset + 2 > body_len {
        return Err(SsError::MalformedPacket);
    }
    let padding_len = usize::from(read_u16(&plaintext[offset..offset + 2]));
    offset += 2;
    if offset + padding_len > body_len {
        return Err(SsError::MalformedPacket);
    }
    offset += padding_len;

    let (destination, next) = decode_address(&plaintext[..body_len], offset)?;
    Ok(UdpDecoded {
        direction: expected_direction,
        session_id,
        packet_id,
        client_session_id,
        timestamp,
        destination,
        payload: &plaintext[next..body_len],
    })
}

fn aes_block_encrypt(method: Method, key: &[u8], input: &[u8; 16]) -> Result<[u8; 16], SsError> {
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(input);
    let mut block = aes::Block::from(bytes);
    match method {
        Method::Aes128Gcm => {
            let cipher = Aes128::new_from_slice(&key[..16]).map_err(|_| SsError::Crypto)?;
            cipher.encrypt_block(&mut block);
        }
        Method::Aes256Gcm => {
            let cipher = Aes256::new_from_slice(&key[..32]).map_err(|_| SsError::Crypto)?;
            cipher.encrypt_block(&mut block);
        }
    }
    let mut out = [0_u8; 16];
    out.copy_from_slice(&block);
    Ok(out)
}

fn aes_block_decrypt(method: Method, key: &[u8], input: &[u8]) -> Result<[u8; 16], SsError> {
    if input.len() != 16 {
        return Err(SsError::MalformedPacket);
    }
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(input);
    let mut block = aes::Block::from(bytes);
    match method {
        Method::Aes128Gcm => {
            let cipher = Aes128::new_from_slice(&key[..16]).map_err(|_| SsError::Crypto)?;
            cipher.decrypt_block(&mut block);
        }
        Method::Aes256Gcm => {
            let cipher = Aes256::new_from_slice(&key[..32]).map_err(|_| SsError::Crypto)?;
            cipher.decrypt_block(&mut block);
        }
    }
    let mut out = [0_u8; 16];
    out.copy_from_slice(&block);
    Ok(out)
}

/// Validates a timestamp against the allowed skew.
#[must_use]
pub fn validate_timestamp(timestamp: u64, now: u64) -> bool {
    timestamp.abs_diff(now) <= TIMESTAMP_WINDOW_S
}

/// Sliding replay window for UDP packet IDs.
#[derive(Clone, Copy, Debug, Default)]
pub struct Window {
    initialized: bool,
    max_id: u64,
    bitmap: u64,
}

impl Window {
    /// Returns false for duplicates and packet IDs older than the window.
    pub fn accept(&mut self, packet_id: u64) -> bool {
        if !self.initialized {
            self.initialized = true;
            self.max_id = packet_id;
            self.bitmap = 1;
            return true;
        }
        if packet_id == self.max_id {
            return false;
        }
        if packet_id > self.max_id {
            let shift = packet_id - self.max_id;
            self.bitmap = if shift >= 64 {
                1
            } else {
                (self.bitmap << shift) | 1
            };
            self.max_id = packet_id;
            return true;
        }
        let delta = self.max_id - packet_id;
        if delta >= 64 {
            return false;
        }
        let bit = 1_u64 << delta;
        if self.bitmap & bit != 0 {
            return false;
        }
        self.bitmap |= bit;
        true
    }
}

/// The authenticated fixed header of a TCP client request.
#[derive(Debug, PartialEq, Eq)]
pub struct ClientRequestFixed {
    /// Request salt (zero-padded).
    pub salt: [u8; 32],
    /// Salt length.
    pub salt_len: u8,
    /// Subkey for the request body.
    pub recv_key: [u8; 32],
    /// Variable-header length declared by the fixed header.
    pub variable_len: usize,
}

/// Decodes only the fixed header of a TCP client request.
///
/// `bytes` must hold `salt_len + 11 + TAG_LENGTH` bytes; the caller reads the
/// variable header next using [`decode_client_variable`].
pub fn decode_client_fixed(
    method: Method,
    psk: &[u8],
    bytes: &[u8],
    now: u64,
) -> Result<ClientRequestFixed, SsError> {
    let salt_len = method.salt_len();
    if psk.len() < method.key_len() || bytes.len() < salt_len + 11 + TAG_LENGTH {
        return Err(SsError::MalformedPacket);
    }
    let salt = &bytes[..salt_len];
    let mut subkey = derive_subkey(method, psk, salt);

    let mut fixed = [0_u8; 11];
    let fixed_len = open(
        method,
        &subkey,
        nonce_from_counter(0),
        &bytes[salt_len..salt_len + 11 + TAG_LENGTH],
        &mut fixed,
    )?;
    if fixed_len != 11 || fixed[0] != 0 {
        return Err(SsError::ProtocolViolation);
    }
    let timestamp = u64::from_be_bytes(
        fixed[1..9]
            .try_into()
            .map_err(|_| SsError::MalformedPacket)?,
    );
    if !validate_timestamp(timestamp, now) {
        return Err(SsError::ProtocolViolation);
    }
    let variable_len = usize::from(u16::from_be_bytes([fixed[9], fixed[10]]));
    if variable_len == 0 {
        return Err(SsError::ProtocolViolation);
    }

    let mut salt_copy = [0_u8; 32];
    salt_copy[..salt_len].copy_from_slice(salt);
    let mut recv_key = [0_u8; 32];
    recv_key[..method.key_len()].copy_from_slice(&subkey[..method.key_len()]);
    subkey.zeroize();

    Ok(ClientRequestFixed {
        salt: salt_copy,
        salt_len: salt_len as u8,
        recv_key,
        variable_len,
    })
}

/// Decodes the variable header of a TCP client request.
///
/// `bytes` must hold `fixed.variable_len + TAG_LENGTH` bytes, and `plaintext`
/// must have room for `fixed.variable_len` bytes.
pub fn decode_client_variable<'a>(
    method: Method,
    fixed: &ClientRequestFixed,
    bytes: &[u8],
    plaintext: &'a mut [u8],
) -> Result<(Endpoint, &'a [u8]), SsError> {
    let variable_len = fixed.variable_len;
    if bytes.len() < variable_len + TAG_LENGTH || plaintext.len() < variable_len {
        return Err(SsError::MalformedPacket);
    }
    let plain_len = open(
        method,
        &fixed.recv_key,
        nonce_from_counter(1),
        &bytes[..variable_len + TAG_LENGTH],
        &mut plaintext[..variable_len],
    )?;
    if plain_len != variable_len {
        return Err(SsError::ProtocolViolation);
    }

    let (target, mut offset) = decode_address(&plaintext[..variable_len], 0)?;
    if offset + 2 > variable_len {
        return Err(SsError::ProtocolViolation);
    }
    let padding_len = usize::from(read_u16(&plaintext[offset..offset + 2]));
    offset += 2;
    if padding_len > MAX_PADDING || offset + padding_len > variable_len {
        return Err(SsError::ProtocolViolation);
    }
    offset += padding_len;
    let initial_payload = &plaintext[offset..variable_len];
    if initial_payload.is_empty() && padding_len == 0 {
        return Err(SsError::ProtocolViolation);
    }
    Ok((target, initial_payload))
}

/// A decoded TCP client request header.
#[derive(Debug, PartialEq, Eq)]
pub struct ClientRequest<'a> {
    /// Request salt (zero-padded).
    pub salt: [u8; 32],
    /// Salt length.
    pub salt_len: u8,
    /// Subkey for the request body.
    pub recv_key: [u8; 32],
    /// Requested target.
    pub target: Endpoint,
    /// Initial payload carried in the variable header.
    pub initial_payload: &'a [u8],
    /// Bytes consumed from the request buffer.
    pub consumed: usize,
}

/// Encodes a TCP client request (salt, fixed header, variable header).
#[allow(clippy::too_many_arguments)]
pub fn encode_client_request(
    method: Method,
    psk: &[u8],
    salt: &[u8],
    target: &Endpoint,
    timestamp: u64,
    padding: &[u8],
    initial_payload: &[u8],
    out: &mut [u8],
) -> Result<usize, SsError> {
    if salt.len() != method.salt_len() || psk.len() < method.key_len() {
        return Err(SsError::InvalidKey);
    }

    let mut variable = [0_u8; MAX_PAYLOAD];
    let mut offset = 0;
    offset += encode_address(target, &mut variable[offset..])?;
    let padding_len = u16::try_from(padding.len()).map_err(|_| SsError::NoSpace)?;
    if variable.len() < offset + 2 + padding.len() + initial_payload.len() {
        return Err(SsError::NoSpace);
    }
    variable[offset..offset + 2].copy_from_slice(&padding_len.to_be_bytes());
    offset += 2;
    variable[offset..offset + padding.len()].copy_from_slice(padding);
    offset += padding.len();
    variable[offset..offset + initial_payload.len()].copy_from_slice(initial_payload);
    offset += initial_payload.len();
    let variable_len = u16::try_from(offset).map_err(|_| SsError::NoSpace)?;

    let total = salt.len() + 11 + TAG_LENGTH + offset + TAG_LENGTH;
    if out.len() < total {
        return Err(SsError::NoSpace);
    }
    out[..salt.len()].copy_from_slice(salt);

    let mut fixed = [0_u8; 11];
    fixed[0] = 0;
    fixed[1..9].copy_from_slice(&timestamp.to_be_bytes());
    fixed[9..11].copy_from_slice(&variable_len.to_be_bytes());

    let mut subkey = derive_subkey(method, psk, salt);
    let mut position = salt.len();
    position += seal(
        method,
        &subkey,
        nonce_from_counter(0),
        &fixed,
        &mut out[position..],
    )?;
    position += seal(
        method,
        &subkey,
        nonce_from_counter(1),
        &variable[..offset],
        &mut out[position..],
    )?;
    subkey.zeroize();
    Ok(position)
}

/// Decodes and authenticates a TCP client request.
pub fn decode_client_request<'a>(
    method: Method,
    psk: &[u8],
    bytes: &[u8],
    plaintext: &'a mut [u8],
    now: u64,
) -> Result<ClientRequest<'a>, SsError> {
    let fixed = decode_client_fixed(method, psk, bytes, now)?;
    let variable_start = usize::from(fixed.salt_len) + 11 + TAG_LENGTH;
    let total = variable_start + fixed.variable_len + TAG_LENGTH;
    if bytes.len() < total {
        return Err(SsError::MalformedPacket);
    }
    let (target, initial_payload) =
        decode_client_variable(method, &fixed, &bytes[variable_start..total], plaintext)?;
    Ok(ClientRequest {
        salt: fixed.salt,
        salt_len: fixed.salt_len,
        recv_key: fixed.recv_key,
        target,
        initial_payload,
        consumed: total,
    })
}

/// The authenticated fixed header of a TCP server response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerResponseFixed {
    /// Response salt (zero-padded).
    pub salt: [u8; 32],
    /// Salt length.
    pub salt_len: u8,
    /// Subkey for the response body.
    pub send_key: [u8; 32],
    /// Length of the first payload carried after the fixed header.
    pub first_len: usize,
}

/// Decodes only the fixed header of a TCP server response.
///
/// `bytes` must hold `salt_len + 11 + request_salt.len() + TAG_LENGTH` bytes;
/// the caller reads the first payload next using [`decode_server_variable`].
pub fn decode_server_fixed(
    method: Method,
    psk: &[u8],
    request_salt: &[u8],
    bytes: &[u8],
    now: u64,
) -> Result<ServerResponseFixed, SsError> {
    let salt_len = method.salt_len();
    let fixed_len = 11 + salt_len;
    if request_salt.len() != salt_len
        || psk.len() < method.key_len()
        || bytes.len() < salt_len + fixed_len + TAG_LENGTH
    {
        return Err(SsError::MalformedPacket);
    }
    let salt = &bytes[..salt_len];
    let mut subkey = derive_subkey(method, psk, salt);
    let mut fixed = [0_u8; 43];
    let opened = open(
        method,
        &subkey,
        nonce_from_counter(0),
        &bytes[salt_len..salt_len + fixed_len + TAG_LENGTH],
        &mut fixed[..fixed_len],
    )?;
    if opened != fixed_len || fixed[0] != 1 {
        return Err(SsError::ProtocolViolation);
    }
    let timestamp = u64::from_be_bytes(
        fixed[1..9]
            .try_into()
            .map_err(|_| SsError::MalformedPacket)?,
    );
    if !validate_timestamp(timestamp, now) {
        return Err(SsError::ProtocolViolation);
    }
    if &fixed[9..9 + salt_len] != request_salt {
        return Err(SsError::ProtocolViolation);
    }
    let first_len = usize::from(u16::from_be_bytes([
        fixed[9 + salt_len],
        fixed[10 + salt_len],
    ]));
    if first_len == 0 {
        return Err(SsError::ProtocolViolation);
    }

    let mut salt_copy = [0_u8; 32];
    salt_copy[..salt_len].copy_from_slice(salt);
    let mut send_key = [0_u8; 32];
    send_key[..method.key_len()].copy_from_slice(&subkey[..method.key_len()]);
    subkey.zeroize();
    Ok(ServerResponseFixed {
        salt: salt_copy,
        salt_len: salt_len as u8,
        send_key,
        first_len,
    })
}

/// Decodes the first payload of a TCP server response.
///
/// `bytes` must hold `fixed.first_len + TAG_LENGTH` bytes, and `plaintext`
/// must have room for `fixed.first_len` bytes.
pub fn decode_server_variable<'a>(
    method: Method,
    fixed: &ServerResponseFixed,
    bytes: &[u8],
    plaintext: &'a mut [u8],
) -> Result<&'a [u8], SsError> {
    let first_len = fixed.first_len;
    if bytes.len() < first_len + TAG_LENGTH || plaintext.len() < first_len {
        return Err(SsError::MalformedPacket);
    }
    let opened = open(
        method,
        &fixed.send_key,
        nonce_from_counter(1),
        &bytes[..first_len + TAG_LENGTH],
        &mut plaintext[..first_len],
    )?;
    if opened != first_len {
        return Err(SsError::ProtocolViolation);
    }
    Ok(&plaintext[..first_len])
}

/// A decoded TCP server response header.
#[derive(Debug, PartialEq, Eq)]
pub struct ServerResponse<'a> {
    /// Response salt (zero-padded).
    pub salt: [u8; 32],
    /// Salt length.
    pub salt_len: u8,
    /// Subkey for the response body.
    pub send_key: [u8; 32],
    /// First payload chunk.
    pub first_payload: &'a [u8],
    /// Bytes consumed from the response buffer.
    pub consumed: usize,
}

/// Encodes a TCP server response (salt, fixed header, first payload).
pub fn encode_server_response(
    method: Method,
    psk: &[u8],
    request_salt: &[u8],
    salt: &[u8],
    timestamp: u64,
    first_payload: &[u8],
    out: &mut [u8],
) -> Result<usize, SsError> {
    if salt.len() != method.salt_len()
        || request_salt.len() != method.salt_len()
        || psk.len() < method.key_len()
        || first_payload.is_empty()
    {
        return Err(SsError::InvalidKey);
    }
    let fixed_len = 11 + request_salt.len();
    let total = salt.len() + fixed_len + TAG_LENGTH + first_payload.len() + TAG_LENGTH;
    if out.len() < total {
        return Err(SsError::NoSpace);
    }
    let first_len = u16::try_from(first_payload.len()).map_err(|_| SsError::NoSpace)?;
    let mut fixed = [0_u8; 43];
    fixed[0] = 1;
    fixed[1..9].copy_from_slice(&timestamp.to_be_bytes());
    fixed[9..9 + request_salt.len()].copy_from_slice(request_salt);
    fixed[9 + request_salt.len()..fixed_len].copy_from_slice(&first_len.to_be_bytes());

    out[..salt.len()].copy_from_slice(salt);
    let mut subkey = derive_subkey(method, psk, salt);
    let mut position = salt.len();
    position += seal(
        method,
        &subkey,
        nonce_from_counter(0),
        &fixed[..fixed_len],
        &mut out[position..],
    )?;
    position += seal(
        method,
        &subkey,
        nonce_from_counter(1),
        first_payload,
        &mut out[position..],
    )?;
    subkey.zeroize();
    Ok(position)
}

/// Decodes and authenticates a TCP server response.
pub fn decode_server_response<'a>(
    method: Method,
    psk: &[u8],
    request_salt: &[u8],
    bytes: &[u8],
    plaintext: &'a mut [u8],
    now: u64,
) -> Result<ServerResponse<'a>, SsError> {
    let fixed = decode_server_fixed(method, psk, request_salt, bytes, now)?;
    let salt_len = usize::from(fixed.salt_len);
    let payload_start = salt_len + 11 + salt_len + TAG_LENGTH;
    let total = payload_start + fixed.first_len + TAG_LENGTH;
    if bytes.len() < total {
        return Err(SsError::MalformedPacket);
    }
    let first_payload =
        decode_server_variable(method, &fixed, &bytes[payload_start..total], plaintext)?;
    Ok(ServerResponse {
        salt: fixed.salt,
        salt_len: fixed.salt_len,
        send_key: fixed.send_key,
        first_payload,
        consumed: total,
    })
}

/// Encodes one TCP length/payload chunk.
pub fn seal_chunk(
    method: Method,
    key: &[u8],
    counter: &mut u64,
    payload: &[u8],
    out: &mut [u8],
) -> Result<usize, SsError> {
    let length = u16::try_from(payload.len()).map_err(|_| SsError::NoSpace)?;
    if length == 0 {
        return Err(SsError::ProtocolViolation);
    }
    let total = 2 + TAG_LENGTH + payload.len() + TAG_LENGTH;
    if out.len() < total {
        return Err(SsError::NoSpace);
    }
    let length_plain = length.to_be_bytes();
    let mut position = seal(
        method,
        key,
        nonce_from_counter(next_counter(counter)?),
        &length_plain,
        &mut out[..2 + TAG_LENGTH],
    )?;
    position += seal(
        method,
        key,
        nonce_from_counter(next_counter(counter)?),
        payload,
        &mut out[position..],
    )?;
    Ok(position)
}

/// Decodes one TCP length/payload chunk into `plaintext`.
pub fn open_chunk(
    method: Method,
    key: &[u8],
    counter: &mut u64,
    bytes: &[u8],
    plaintext: &mut [u8],
) -> Result<(usize, usize), SsError> {
    if bytes.len() < 2 + TAG_LENGTH {
        return Err(SsError::MalformedPacket);
    }
    let mut length_plain = [0_u8; 2];
    let opened = open(
        method,
        key,
        nonce_from_counter(next_counter(counter)?),
        &bytes[..2 + TAG_LENGTH],
        &mut length_plain,
    )?;
    if opened != 2 {
        return Err(SsError::ProtocolViolation);
    }
    let length = usize::from(u16::from_be_bytes(length_plain));
    if length == 0 {
        return Err(SsError::ProtocolViolation);
    }
    let total = 2 + TAG_LENGTH + length + TAG_LENGTH;
    if bytes.len() < total || plaintext.len() < length {
        return Err(SsError::MalformedPacket);
    }
    let opened = open(
        method,
        key,
        nonce_from_counter(next_counter(counter)?),
        &bytes[2 + TAG_LENGTH..total],
        &mut plaintext[..length],
    )?;
    if opened != length {
        return Err(SsError::ProtocolViolation);
    }
    Ok((length, total))
}

/// Why a Shadowsocks 2022 operation failed.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum SsError {
    /// The PSK was not valid base64 or had the wrong length.
    #[error("invalid pre-shared key")]
    InvalidKey,
    /// An AEAD operation failed.
    #[error("cryptographic failure")]
    Crypto,
    /// The authentication tag did not verify.
    #[error("authentication failed")]
    AuthenticationFailed,
    /// The output buffer was too small.
    #[error("output buffer is too small")]
    NoSpace,
    /// The UDP replay counter is exhausted.
    #[error("counter exhausted")]
    CounterExhausted,
    /// The address type is unknown.
    #[error("unsupported address type")]
    UnsupportedAddress,
    /// The address was truncated.
    #[error("malformed address")]
    MalformedAddress,
    /// The domain was empty, too long, or not UTF-8.
    #[error("invalid domain")]
    InvalidDomain,
    /// The authenticated body had the wrong type or fields.
    #[error("protocol violation")]
    ProtocolViolation,
    /// The packet was too short.
    #[error("malformed packet")]
    MalformedPacket,
    /// A server-to-client packet omitted the client session.
    #[error("missing client session")]
    MissingClientSession,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn key(method: Method) -> Vec<u8> {
        (0..method.key_len()).map(|value| value as u8).collect()
    }

    #[test]
    fn parses_methods_and_keys() {
        assert_eq!(
            Method::parse("2022-blake3-aes-128-gcm"),
            Some(Method::Aes128Gcm)
        );
        assert_eq!(
            Method::parse("2022-blake3-aes-256-gcm"),
            Some(Method::Aes256Gcm)
        );
        assert_eq!(Method::parse("aes-128-gcm"), None);

        let short = STANDARD.encode([1_u8; 16]);
        let key = Key::parse(Method::Aes128Gcm, &short).expect("key");
        assert_eq!(key.as_bytes().len(), 16);
        assert!(Key::parse(Method::Aes256Gcm, &short).is_err());
        assert!(Key::parse(Method::Aes128Gcm, "not base64!").is_err());
    }

    #[test]
    fn subkeys_have_method_lengths() {
        let salt = [7_u8; 16];
        let subkey = derive_subkey(Method::Aes128Gcm, &[1_u8; 16], &salt);
        assert!(subkey[..16].iter().any(|byte| *byte != 0));
        let subkey = derive_subkey(Method::Aes256Gcm, &[1_u8; 32], &salt);
        assert!(subkey.iter().any(|byte| *byte != 0));
    }

    #[test]
    fn seals_and_opens_both_methods() {
        for method in [Method::Aes128Gcm, Method::Aes256Gcm] {
            let key = key(method);
            let nonce = nonce_from_counter(3);
            let plaintext = b"marmo shadowsocks 2022";
            let mut ciphertext = [0_u8; 64];
            let length = seal(method, &key, nonce, plaintext, &mut ciphertext).expect("seal");
            let mut opened = [0_u8; 64];
            let opened_len =
                open(method, &key, nonce, &ciphertext[..length], &mut opened).expect("open");
            assert_eq!(&opened[..opened_len], plaintext);

            ciphertext[0] ^= 1;
            assert_eq!(
                open(method, &key, nonce, &ciphertext[..length], &mut opened),
                Err(SsError::AuthenticationFailed)
            );
        }
    }

    #[test]
    fn addresses_round_trip() {
        let endpoints = [
            Endpoint::from_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 80),
            Endpoint::from_ip(IpAddr::V6(Ipv6Addr::LOCALHOST), 443),
            Endpoint::from_domain("example.com", 443).expect("domain"),
        ];
        for endpoint in endpoints {
            let mut buffer = [0_u8; 300];
            let length = encode_address(&endpoint, &mut buffer).expect("encode");
            let (decoded, next) = decode_address(&buffer[..length], 0).expect("decode");
            assert_eq!(decoded, endpoint);
            assert_eq!(next, length);
        }
    }

    #[test]
    fn udp_packets_round_trip() {
        let method = Method::Aes128Gcm;
        let key = key(method);
        let destination = Endpoint::from_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 53);
        let session_id = *b"session1";
        let packet = UdpPacket {
            direction: Direction::ClientToServer,
            session_id,
            packet_id: 42,
            client_session_id: None,
            destination: &destination,
            payload: b"query",
            padding_len: 3,
            timestamp: 100,
        };
        let mut encoded = [0_u8; 256];
        let length = encode_udp_packet(method, &key, &packet, &mut encoded).expect("encode");
        let mut plaintext = [0_u8; 256];
        let decoded = decode_udp_packet(
            method,
            &key,
            &encoded[..length],
            Direction::ClientToServer,
            None,
            &mut plaintext,
        )
        .expect("decode");
        assert_eq!(decoded.destination, destination);
        assert_eq!(decoded.payload, b"query");
        assert_eq!(decoded.packet_id, 42);
        assert_eq!(decoded.timestamp, 100);

        let server = UdpPacket {
            direction: Direction::ServerToClient,
            session_id,
            packet_id: 43,
            client_session_id: Some(session_id),
            destination: &destination,
            payload: b"answer",
            padding_len: 0,
            timestamp: 101,
        };
        let length = encode_udp_packet(method, &key, &server, &mut encoded).expect("encode server");
        let decoded = decode_udp_packet(
            method,
            &key,
            &encoded[..length],
            Direction::ServerToClient,
            Some(session_id),
            &mut plaintext,
        )
        .expect("decode server");
        assert_eq!(decoded.client_session_id, Some(session_id));
        assert_eq!(decoded.payload, b"answer");
    }

    #[test]
    fn udp_packets_reject_tampering() {
        let method = Method::Aes128Gcm;
        let key = key(method);
        let destination = Endpoint::from_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 53);
        let packet = UdpPacket {
            direction: Direction::ClientToServer,
            session_id: *b"session1",
            packet_id: 1,
            client_session_id: None,
            destination: &destination,
            payload: b"x",
            padding_len: 0,
            timestamp: 1,
        };
        let mut encoded = [0_u8; 256];
        let length = encode_udp_packet(method, &key, &packet, &mut encoded).expect("encode");
        encoded[length - 1] ^= 1;
        let mut plaintext = [0_u8; 256];
        assert_eq!(
            decode_udp_packet(
                method,
                &key,
                &encoded[..length],
                Direction::ClientToServer,
                None,
                &mut plaintext,
            ),
            Err(SsError::AuthenticationFailed)
        );
    }

    #[test]
    fn timestamps_and_windows() {
        assert!(validate_timestamp(100, 130));
        assert!(!validate_timestamp(100, 131));

        let mut window = Window::default();
        assert!(window.accept(10));
        assert!(window.accept(11));
        assert!(!window.accept(11));
        assert!(window.accept(9));
        assert!(!window.accept(9));
        assert!(window.accept(100));
        assert!(!window.accept(20));
    }
    #[test]
    fn tcp_requests_round_trip() {
        for method in [Method::Aes128Gcm, Method::Aes256Gcm] {
            let psk = key(method);
            let salt = vec![9_u8; method.salt_len()];
            let target = Endpoint::from_domain("example.com", 443).expect("domain");
            let mut encoded = [0_u8; 1024];
            let length = encode_client_request(
                method,
                &psk,
                &salt,
                &target,
                1_000,
                b"pad",
                b"hello",
                &mut encoded,
            )
            .expect("encode");
            let mut plaintext = [0_u8; 1024];
            let request =
                decode_client_request(method, &psk, &encoded[..length], &mut plaintext, 1_000)
                    .expect("decode");
            assert_eq!(request.target, target);
            assert_eq!(request.initial_payload, b"hello");
            assert_eq!(request.consumed, length);
            assert_eq!(&request.salt[..method.salt_len()], &salt[..]);

            encoded[length - 1] ^= 1;
            assert_eq!(
                decode_client_request(method, &psk, &encoded[..length], &mut plaintext, 1_000,),
                Err(SsError::AuthenticationFailed)
            );
        }
    }

    #[test]
    fn tcp_request_headers_decode_in_two_steps() {
        let method = Method::Aes256Gcm;
        let psk = key(method);
        let salt = [7_u8; 32];
        let target = Endpoint::from_domain("two-step.example", 80).expect("domain");
        let mut encoded = [0_u8; 1024];
        let length = encode_client_request(
            method,
            &psk,
            &salt,
            &target,
            1_000,
            b"pad",
            b"payload",
            &mut encoded,
        )
        .expect("encode");

        let fixed_len = salt.len() + 11 + TAG_LENGTH;
        let fixed = decode_client_fixed(method, &psk, &encoded[..fixed_len], 1_000).expect("fixed");
        assert_eq!(fixed.variable_len, length - fixed_len - TAG_LENGTH);
        assert_eq!(&fixed.salt[..32], &salt[..]);

        let mut plaintext = [0_u8; 1024];
        let (decoded_target, payload) =
            decode_client_variable(method, &fixed, &encoded[fixed_len..length], &mut plaintext)
                .expect("variable");
        assert_eq!(decoded_target, target);
        assert_eq!(payload, b"payload");

        let response_salt = [3_u8; 32];
        let mut response = [0_u8; 512];
        let response_len = encode_server_response(
            method,
            &psk,
            &salt,
            &response_salt,
            1_000,
            b"first",
            &mut response,
        )
        .expect("encode response");
        let response_fixed_len = salt.len() + 11 + 32 + TAG_LENGTH;
        let fixed =
            decode_server_fixed(method, &psk, &salt, &response[..response_fixed_len], 1_000)
                .expect("response fixed");
        assert_eq!(fixed.first_len, 5);
        let mut plaintext = [0_u8; 64];
        let first = decode_server_variable(
            method,
            &fixed,
            &response[response_fixed_len..response_len],
            &mut plaintext,
        )
        .expect("response variable");
        assert_eq!(first, b"first");
    }

    #[test]
    fn tcp_requests_reject_stale_timestamps() {
        let method = Method::Aes128Gcm;
        let psk = key(method);
        let salt = [8_u8; 16];
        let target = Endpoint::from_ip(IpAddr::V4(Ipv4Addr::LOCALHOST), 80);
        let mut encoded = [0_u8; 512];
        let length =
            encode_client_request(method, &psk, &salt, &target, 1_000, b"x", b"", &mut encoded)
                .expect("encode");
        let mut plaintext = [0_u8; 512];
        assert_eq!(
            decode_client_request(method, &psk, &encoded[..length], &mut plaintext, 1_031,),
            Err(SsError::ProtocolViolation)
        );
    }

    #[test]
    fn tcp_responses_round_trip() {
        let method = Method::Aes128Gcm;
        let psk = key(method);
        let request_salt = [1_u8; 16];
        let salt = [2_u8; 16];
        let mut encoded = [0_u8; 512];
        let length = encode_server_response(
            method,
            &psk,
            &request_salt,
            &salt,
            1_000,
            b"first",
            &mut encoded,
        )
        .expect("encode");
        let mut plaintext = [0_u8; 512];
        let response = decode_server_response(
            method,
            &psk,
            &request_salt,
            &encoded[..length],
            &mut plaintext,
            1_000,
        )
        .expect("decode");
        assert_eq!(response.first_payload, b"first");
        assert_eq!(response.consumed, length);

        assert_eq!(
            decode_server_response(
                method,
                &psk,
                &[3_u8; 16],
                &encoded[..length],
                &mut plaintext,
                1_000,
            ),
            Err(SsError::ProtocolViolation)
        );
    }

    #[test]
    fn tcp_chunks_round_trip() {
        let method = Method::Aes128Gcm;
        let psk = key(method);
        let mut send_counter = 2;
        let mut sealed = [0_u8; 256];
        let length =
            seal_chunk(method, &psk, &mut send_counter, b"data", &mut sealed).expect("seal");
        assert_eq!(send_counter, 4);

        let mut recv_counter = 2;
        let mut plaintext = [0_u8; 64];
        let (length_plain, consumed) = open_chunk(
            method,
            &psk,
            &mut recv_counter,
            &sealed[..length],
            &mut plaintext,
        )
        .expect("open");
        assert_eq!(length_plain, 4);
        assert_eq!(consumed, length);
        assert_eq!(&plaintext[..length_plain], b"data");
        assert_eq!(recv_counter, 4);

        sealed[length - 1] ^= 1;
        let mut recv_counter = 2;
        assert_eq!(
            open_chunk(
                method,
                &psk,
                &mut recv_counter,
                &sealed[..length],
                &mut plaintext,
            ),
            Err(SsError::AuthenticationFailed)
        );

        let mut counter = 0;
        assert_eq!(
            seal_chunk(method, &psk, &mut counter, b"", &mut sealed),
            Err(SsError::ProtocolViolation)
        );
    }
}
