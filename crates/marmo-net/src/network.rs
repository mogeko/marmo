//! The transport carried by a connection.

/// Transport carried by a connection or session.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Network {
    /// Stream-oriented TCP.
    Tcp,
    /// Datagram-oriented UDP.
    Udp,
}
