//! The transport carried by a connection.

/// Transport carried by a connection or session.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Network {
    /// Stream-oriented TCP.
    Tcp,
    /// Datagram-oriented UDP.
    Udp,
}
