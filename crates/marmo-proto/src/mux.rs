//! Mux.Cool framing used by the VMess Mux command.
//!
//! A frame is `[2B metadata length][metadata][2B data length][data]`, where
//! metadata starts with a session id, a status, and an option byte. New frames
//! carry a network, port, and address; Keep frames may carry a target for
//! per-packet UDP destinations. The trailing eight-byte GlobalID used by Xray
//! XUDP is accepted and ignored.

use marmo_net::Endpoint;
use thiserror::Error;

use crate::vless::{self, VlessError};

/// New session.
pub const STATUS_NEW: u8 = 1;
/// Data frame for an existing session.
pub const STATUS_KEEP: u8 = 2;
/// Session end.
pub const STATUS_END: u8 = 3;
/// Keep-alive without data.
pub const STATUS_KEEPALIVE: u8 = 4;
/// The frame carries data.
pub const OPTION_DATA: u8 = 1;
/// The frame carries an error message.
pub const OPTION_ERROR: u8 = 2;
/// TCP session network.
pub const NETWORK_TCP: u8 = 1;
/// UDP session network.
pub const NETWORK_UDP: u8 = 2;
/// Maximum metadata length.
pub const MAX_META_LEN: usize = 512;
/// Maximum data length in one frame.
pub const MAX_DATA_LEN: usize = 65_535;
/// GlobalID length accepted after a New target.
pub const GLOBAL_ID_LEN: usize = 8;

/// Metadata of one Mux.Cool frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Meta {
    /// Session id; zero is reserved for keep-alives.
    pub session: u16,
    /// Frame status.
    pub status: u8,
    /// Option bits.
    pub option: u8,
    /// Session network for New or a targeted Keep; zero otherwise.
    pub network: u8,
    /// Session target, or a per-packet UDP destination.
    pub target: Option<Endpoint>,
}

/// Parses and validates Mux.Cool metadata.
pub fn parse_meta(meta: &[u8]) -> Result<Meta, MuxError> {
    if meta.len() < 4 || meta.len() > MAX_META_LEN {
        return Err(MuxError::Invalid);
    }
    let session = u16::from_be_bytes([meta[0], meta[1]]);
    let status = meta[2];
    let option = meta[3];
    if option & !(OPTION_DATA | OPTION_ERROR) != 0 {
        return Err(MuxError::Invalid);
    }
    let (network, target) = match status {
        STATUS_NEW => {
            let (network, target, next) = parse_target(meta, 4)?;
            let remaining = meta.len() - next;
            if remaining != 0 && remaining != GLOBAL_ID_LEN {
                return Err(MuxError::Invalid);
            }
            (network, Some(target))
        }
        STATUS_KEEP => {
            if meta.len() == 4 {
                (0, None)
            } else {
                let (network, target, next) = parse_target(meta, 4)?;
                if next != meta.len() {
                    return Err(MuxError::Invalid);
                }
                (network, Some(target))
            }
        }
        STATUS_END => {
            if meta.len() == 4 {
                (0, None)
            } else {
                let (network, target, next) = parse_target(meta, 4)?;
                if next != meta.len() {
                    return Err(MuxError::Invalid);
                }
                (network, Some(target))
            }
        }
        STATUS_KEEPALIVE => {
            if meta.len() != 4 {
                return Err(MuxError::Invalid);
            }
            (0, None)
        }
        _ => return Err(MuxError::Invalid),
    };
    Ok(Meta {
        session,
        status,
        option,
        network,
        target,
    })
}

fn parse_target(meta: &[u8], offset: usize) -> Result<(u8, Endpoint, usize), MuxError> {
    if meta.len() < offset + 3 {
        return Err(MuxError::Invalid);
    }
    let network = meta[offset];
    if network != NETWORK_TCP && network != NETWORK_UDP {
        return Err(MuxError::Invalid);
    }
    let port = u16::from_be_bytes([meta[offset + 1], meta[offset + 2]]);
    match vless::decode_address(meta, offset + 3, port) {
        Ok(Some((target, next))) => Ok((network, target, next)),
        _ => Err(MuxError::Invalid),
    }
}

/// Encodes New metadata, including a zero GlobalID.
pub fn encode_new_meta(
    session: u16, target: &Endpoint, network: u8, out: &mut [u8],
) -> Result<usize, MuxError> {
    if network != NETWORK_TCP && network != NETWORK_UDP {
        return Err(MuxError::Invalid);
    }
    if out.len() < 4 + 3 {
        return Err(MuxError::NoSpace);
    }
    out[0..2].copy_from_slice(&session.to_be_bytes());
    out[2] = STATUS_NEW;
    out[3] = OPTION_DATA;
    out[4] = network;
    out[5..7].copy_from_slice(&target.port().to_be_bytes());
    let address = vless::encode_address(target, &mut out[7..]).map_err(map_vless)?;
    let end = 7 + address;
    if out.len() < end + GLOBAL_ID_LEN {
        return Err(MuxError::NoSpace);
    }
    out[end..end + GLOBAL_ID_LEN].fill(0);
    Ok(end + GLOBAL_ID_LEN)
}

/// Encodes Keep metadata, optionally carrying a per-packet target.
pub fn encode_keep_meta(
    session: u16, target: Option<&Endpoint>, out: &mut [u8],
) -> Result<usize, MuxError> {
    if out.len() < 4 {
        return Err(MuxError::NoSpace);
    }
    out[0..2].copy_from_slice(&session.to_be_bytes());
    out[2] = STATUS_KEEP;
    out[3] = OPTION_DATA;
    let Some(target) = target else {
        return Ok(4);
    };
    if out.len() < 7 {
        return Err(MuxError::NoSpace);
    }
    out[4] = NETWORK_UDP;
    out[5..7].copy_from_slice(&target.port().to_be_bytes());
    let address = vless::encode_address(target, &mut out[7..]).map_err(map_vless)?;
    Ok(7 + address)
}

/// Encodes End metadata, optionally carrying an error message as data.
pub fn encode_end_meta(session: u16, out: &mut [u8]) -> Result<usize, MuxError> {
    if out.len() < 4 {
        return Err(MuxError::NoSpace);
    }
    out[0..2].copy_from_slice(&session.to_be_bytes());
    out[2] = STATUS_END;
    out[3] = 0;
    Ok(4)
}

/// Encodes a keep-alive frame metadata.
pub const KEEPALIVE_META: [u8; 4] = [0, 0, STATUS_KEEPALIVE, 0];

/// Encodes `meta length | meta | data length`.
pub fn encode_header(meta: &[u8], data_len: usize, out: &mut [u8]) -> Result<usize, MuxError> {
    if meta.len() < 4 || meta.len() > MAX_META_LEN {
        return Err(MuxError::Invalid);
    }
    if data_len > MAX_DATA_LEN {
        return Err(MuxError::MessageTooBig);
    }
    let total = 2 + meta.len() + 2;
    if out.len() < total {
        return Err(MuxError::NoSpace);
    }
    let meta_len = u16::try_from(meta.len()).map_err(|_| MuxError::Invalid)?;
    let data_len = u16::try_from(data_len).map_err(|_| MuxError::MessageTooBig)?;
    out[..2].copy_from_slice(&meta_len.to_be_bytes());
    out[2..2 + meta.len()].copy_from_slice(meta);
    out[2 + meta.len()..total].copy_from_slice(&data_len.to_be_bytes());
    Ok(total)
}

fn map_vless(error: VlessError) -> MuxError {
    match error {
        VlessError::NoSpace => MuxError::NoSpace,
        _ => MuxError::Invalid,
    }
}

/// Why a Mux.Cool frame was rejected.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum MuxError {
    /// The metadata or address was malformed.
    #[error("invalid Mux.Cool frame")]
    Invalid,
    /// The output buffer was too small.
    #[error("output buffer is too small")]
    NoSpace,
    /// The data section is too large for one frame.
    #[error("Mux.Cool data is too big")]
    MessageTooBig,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn target() -> Endpoint {
        Endpoint::from_domain("example.com", 53).expect("domain")
    }

    #[test]
    fn round_trips_new_and_keep() {
        let mut meta = [0_u8; MAX_META_LEN];
        let length = encode_new_meta(7, &target(), NETWORK_UDP, &mut meta).expect("new");
        let parsed = parse_meta(&meta[..length]).expect("parse");
        assert_eq!(parsed.session, 7);
        assert_eq!(parsed.status, STATUS_NEW);
        assert_eq!(parsed.network, NETWORK_UDP);
        assert_eq!(parsed.target.as_ref(), Some(&target()));

        let length = encode_keep_meta(7, Some(&target()), &mut meta).expect("keep");
        let parsed = parse_meta(&meta[..length]).expect("parse");
        assert_eq!(parsed.status, STATUS_KEEP);
        assert_eq!(parsed.target.as_ref(), Some(&target()));

        let length = encode_keep_meta(7, None, &mut meta).expect("keep");
        assert_eq!(length, 4);
        assert_eq!(parse_meta(&meta[..length]).expect("parse").target, None);

        let length = encode_end_meta(7, &mut meta).expect("end");
        assert_eq!(
            parse_meta(&meta[..length]).expect("parse").status,
            STATUS_END
        );
        assert_eq!(
            parse_meta(&KEEPALIVE_META).expect("keepalive").status,
            STATUS_KEEPALIVE
        );
    }

    #[test]
    fn accepts_tcp_and_optional_global_id() {
        let mut meta = [0_u8; MAX_META_LEN];
        let length = encode_new_meta(1, &target(), NETWORK_TCP, &mut meta).expect("new");
        let parsed = parse_meta(&meta[..length - GLOBAL_ID_LEN]).expect("without global id");
        assert_eq!(parsed.network, NETWORK_TCP);
        let parsed = parse_meta(&meta[..length]).expect("with global id");
        assert_eq!(parsed.target.as_ref(), Some(&target()));
        assert!(parse_meta(&meta[..length - GLOBAL_ID_LEN + 1]).is_err());
    }

    #[test]
    fn rejects_malformed_metadata() {
        assert!(parse_meta(&[]).is_err());
        assert!(parse_meta(&[0, 0, STATUS_NEW, OPTION_DATA]).is_err());
        assert!(parse_meta(&[0, 0, 9, 0]).is_err());
        assert!(parse_meta(&[0, 0, STATUS_KEEPALIVE, 0, 0]).is_err());
        let mut meta = [0_u8; MAX_META_LEN];
        let length = encode_new_meta(1, &target(), NETWORK_UDP, &mut meta).expect("new");
        meta[4] = 3;
        assert!(parse_meta(&meta[..length]).is_err());
        meta[4] = NETWORK_UDP;
        meta[3] = 0x80;
        assert!(parse_meta(&meta[..length]).is_err());
    }

    #[test]
    fn encodes_frame_headers() {
        let mut out = [0_u8; 600];
        let length = encode_header(&KEEPALIVE_META, 3, &mut out).expect("header");
        assert_eq!(length, 8);
        assert_eq!(&out[..2], &4_u16.to_be_bytes());
        assert_eq!(&out[6..8], &3_u16.to_be_bytes());
        assert!(matches!(
            encode_header(&KEEPALIVE_META, MAX_DATA_LEN + 1, &mut out),
            Err(MuxError::MessageTooBig)
        ));
    }

    #[test]
    fn encodes_ipv6_targets() {
        let target = Endpoint::from_ip(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
        let mut meta = [0_u8; MAX_META_LEN];
        let length = encode_new_meta(2, &target, NETWORK_TCP, &mut meta).expect("new");
        assert_eq!(
            parse_meta(&meta[..length]).expect("parse").target,
            Some(target)
        );
    }
}
