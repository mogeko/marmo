//! XUDP framing carried under a VLESS Mux command.
//!
//! `[2B metadata length][metadata][2B data length][data]`, where the metadata
//! starts with a zero session id, status, and option bytes. New frames carry a
//! UDP network byte, port, address, and an eight-byte GlobalID; Keep frames
//! may omit the address when the target is fixed.

use marmo_net::Endpoint;
use thiserror::Error;

use crate::vless::{self, VlessError};

/// Fixed XUDP session id.
pub const SESSION_ID: u16 = 0;
/// New session frame.
pub const STATUS_NEW: u8 = 1;
/// Keep-alive data frame.
pub const STATUS_KEEP: u8 = 2;
/// End of session.
pub const STATUS_END: u8 = 3;
/// Keep-alive without data.
pub const STATUS_KEEPALIVE: u8 = 4;
/// The frame carries a data section.
pub const OPTION_DATA: u8 = 1;
/// UDP network byte.
pub const NETWORK_UDP: u8 = 2;
/// Maximum metadata length.
pub const MAX_META_LEN: usize = 512;
/// Maximum data length in one frame.
pub const MAX_DATA_LEN: usize = 65_535;

/// Metadata of one XUDP frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Meta {
    /// Frame status.
    pub status: u8,
    /// Option bits; only `OPTION_DATA` is interpreted.
    pub option: u8,
    /// Per-frame destination for New or Keep frames.
    pub target: Option<Endpoint>,
}

/// Parses and validates XUDP metadata.
pub fn parse_meta(meta: &[u8]) -> Result<Meta, XudpError> {
    if meta.len() < 4 || meta.len() > MAX_META_LEN {
        return Err(XudpError::Invalid);
    }
    if meta[0] != 0 || meta[1] != 0 {
        return Err(XudpError::Invalid);
    }
    let status = meta[2];
    let option = meta[3];
    let target = match status {
        STATUS_NEW => {
            if meta.len() < 7 || meta[4] != NETWORK_UDP {
                return Err(XudpError::Invalid);
            }
            let port = u16::from_be_bytes([meta[5], meta[6]]);
            let (endpoint, next) = address(meta, 7, port)?;
            let remaining = meta.len() - next;
            if remaining != 0 && remaining != 8 {
                return Err(XudpError::Invalid);
            }
            Some(endpoint)
        }
        STATUS_KEEP => {
            if meta.len() == 4 {
                None
            } else {
                if meta.len() < 7 || meta[4] != NETWORK_UDP {
                    return Err(XudpError::Invalid);
                }
                let port = u16::from_be_bytes([meta[5], meta[6]]);
                let (endpoint, next) = address(meta, 7, port)?;
                if next != meta.len() {
                    return Err(XudpError::Invalid);
                }
                Some(endpoint)
            }
        }
        STATUS_END | STATUS_KEEPALIVE => {
            if meta.len() != 4 {
                return Err(XudpError::Invalid);
            }
            None
        }
        _ => return Err(XudpError::Invalid),
    };
    Ok(Meta {
        status,
        option,
        target,
    })
}

/// Encodes New metadata for `target`, including the zero GlobalID.
pub fn encode_new_meta(target: &Endpoint, out: &mut [u8]) -> Result<usize, XudpError> {
    if out.len() < 7 {
        return Err(XudpError::NoSpace);
    }
    out[0] = 0;
    out[1] = 0;
    out[2] = STATUS_NEW;
    out[3] = OPTION_DATA;
    out[4] = NETWORK_UDP;
    out[5..7].copy_from_slice(&target.port().to_be_bytes());
    let address = vless::encode_address(target, &mut out[7..]).map_err(map_vless)?;
    let end = 7 + address;
    if out.len() < end + 8 {
        return Err(XudpError::NoSpace);
    }
    out[end..end + 8].fill(0);
    Ok(end + 8)
}

/// Keep metadata for a data frame with a fixed target.
pub const KEEP_META: [u8; 4] = [0, 0, STATUS_KEEP, OPTION_DATA];

/// Encodes `meta length | meta | data length`.
pub fn encode_header(meta: &[u8], data_len: usize, out: &mut [u8]) -> Result<usize, XudpError> {
    if meta.len() < 4 || meta.len() > MAX_META_LEN {
        return Err(XudpError::Invalid);
    }
    if data_len > MAX_DATA_LEN {
        return Err(XudpError::MessageTooBig);
    }
    let total = 2 + meta.len() + 2;
    if out.len() < total {
        return Err(XudpError::NoSpace);
    }
    let meta_len = u16::try_from(meta.len()).map_err(|_| XudpError::Invalid)?;
    let data_len = u16::try_from(data_len).map_err(|_| XudpError::MessageTooBig)?;
    out[..2].copy_from_slice(&meta_len.to_be_bytes());
    out[2..2 + meta.len()].copy_from_slice(meta);
    out[2 + meta.len()..total].copy_from_slice(&data_len.to_be_bytes());
    Ok(total)
}

fn address(meta: &[u8], offset: usize, port: u16) -> Result<(Endpoint, usize), XudpError> {
    match vless::decode_address(meta, offset, port) {
        Ok(Some(value)) => Ok(value),
        _ => Err(XudpError::Invalid),
    }
}

fn map_vless(error: VlessError) -> XudpError {
    match error {
        VlessError::NoSpace => XudpError::NoSpace,
        _ => XudpError::Invalid,
    }
}

/// Why an XUDP frame was rejected.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum XudpError {
    /// The metadata or address was malformed.
    #[error("invalid XUDP frame")]
    Invalid,
    /// The output buffer was too small.
    #[error("output buffer is too small")]
    NoSpace,
    /// The data section is too large for one frame.
    #[error("XUDP data is too big")]
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
    fn round_trips_new_metadata() {
        let mut meta = [0_u8; MAX_META_LEN];
        let length = encode_new_meta(&target(), &mut meta).expect("encode");
        let parsed = parse_meta(&meta[..length]).expect("parse");
        assert_eq!(parsed.status, STATUS_NEW);
        assert_eq!(parsed.option, OPTION_DATA);
        assert_eq!(parsed.target.as_ref(), Some(&target()));

        // A zero GlobalID is optional for parsing.
        let without = parse_meta(&meta[..length - 8]).expect("parse without GlobalID");
        assert_eq!(without.target.as_ref(), Some(&target()));

        // One trailing byte is neither absent nor a full GlobalID.
        assert!(matches!(
            parse_meta(&meta[..length - 8 + 1]),
            Err(XudpError::Invalid)
        ));
    }

    #[test]
    fn parses_keep_and_control_metadata() {
        assert_eq!(
            parse_meta(&KEEP_META).expect("keep"),
            Meta {
                status: STATUS_KEEP,
                option: OPTION_DATA,
                target: None,
            }
        );
        assert_eq!(
            parse_meta(&[0, 0, STATUS_END, 0]).expect("end"),
            Meta {
                status: STATUS_END,
                option: 0,
                target: None,
            }
        );
        assert_eq!(
            parse_meta(&[0, 0, STATUS_KEEPALIVE, 0]).expect("keepalive"),
            Meta {
                status: STATUS_KEEPALIVE,
                option: 0,
                target: None,
            }
        );

        let mut keep_with_address = [0_u8; 64];
        keep_with_address[..4].copy_from_slice(&[0, 0, STATUS_KEEP, OPTION_DATA]);
        keep_with_address[4] = NETWORK_UDP;
        keep_with_address[5..7].copy_from_slice(&53_u16.to_be_bytes());
        let address = vless::encode_address(
            &Endpoint::from_ip(IpAddr::V4(Ipv4Addr::LOCALHOST), 53),
            &mut keep_with_address[7..],
        )
        .expect("address");
        let parsed = parse_meta(&keep_with_address[..7 + address]).expect("keep address");
        assert_eq!(
            parsed.target,
            Some(Endpoint::from_ip(IpAddr::V4(Ipv4Addr::LOCALHOST), 53))
        );
    }

    #[test]
    fn rejects_malformed_metadata() {
        assert!(parse_meta(&[]).is_err());
        assert!(parse_meta(&[1, 0, STATUS_NEW, OPTION_DATA]).is_err());
        assert!(parse_meta(&[0, 0, 9, 0]).is_err());
        assert!(parse_meta(&[0, 0, STATUS_NEW, OPTION_DATA]).is_err());
        assert!(parse_meta(&[0, 0, STATUS_END, 0, 0]).is_err());
        let mut wrong_network = [0_u8; MAX_META_LEN];
        let length = encode_new_meta(&target(), &mut wrong_network).expect("encode");
        wrong_network[4] = 1;
        assert!(parse_meta(&wrong_network[..length]).is_err());
    }

    #[test]
    fn encodes_frame_headers() {
        let mut out = [0_u8; 600];
        let length = encode_header(&KEEP_META, 4096, &mut out).expect("header");
        assert_eq!(length, 2 + KEEP_META.len() + 2);
        assert_eq!(&out[..2], &4_u16.to_be_bytes());
        assert_eq!(&out[2..6], &KEEP_META);
        assert_eq!(&out[6..8], &4096_u16.to_be_bytes());
        assert!(matches!(
            encode_header(&KEEP_META, MAX_DATA_LEN + 1, &mut out),
            Err(XudpError::MessageTooBig)
        ));
        assert!(matches!(
            encode_header(&[0, 0, STATUS_KEEP], 1, &mut out),
            Err(XudpError::Invalid)
        ));
    }
}
