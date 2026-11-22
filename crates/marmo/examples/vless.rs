//! VLESS over TCP/TLS, WebSocket, or HTTP/2.
//!
//! Server:
//! ```sh
//! cargo run -p marmo --example vless -- server 0.0.0.0:443 UUID cert.pem key.pem [tcp|ws|h2] [path]
//! ```
//! Client (SOCKS5 front):
//! ```sh
//! cargo run -p marmo --example vless -- client 127.0.0.1:1080 proxy.example:443 UUID [tcp|ws|h2] [path] [xudp|mux] [insecure]
//! ```
//! `xudp` selects XUDP framing for UDP instead of simple UoT; `mux` enables
//! client-side Mux.Cool pooling; the two are mutually exclusive, and `-`
//! selects neither. `insecure` skips certificate verification and is accepted
//! only for a loopback test server; it is the default when the server is
//! loopback.

#[path = "common/mod.rs"]
mod common;

use std::error::Error;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let mode = common::required(1, "mode (server|client)")?;
    match mode.as_str() {
        "server" => {
            let listen = common::required(2, "listen")?;
            let uuid = common::required(3, "uuid")?;
            let certificate = common::read(&common::required(4, "certificate path")?)?;
            let private_key = common::read(&common::required(5, "private key path")?)?;
            let network = common::arg(6).unwrap_or_else(|| "tcp".into());
            let path = common::arg(7).unwrap_or_else(|| "/".into());
            let transport = transport_json(&network, &path)?;
            let json = format!(
                r#"{{ "inbounds": [ {{ "tag": "vless", "protocol": "vless", "listen": "{listen}",
                                       "uuid": "{uuid}",
                                       "tls": {{ "certificate": {}, "private_key": {} }},
                                       "transport": {transport} }} ],
                      "outbounds": [ {{ "tag": "direct", "protocol": "direct" }} ],
                      "route": {{ "final": "direct" }} }}"#,
                common::json_string(&certificate),
                common::json_string(&private_key)
            );
            common::serve(json).await
        }
        "client" => {
            let listen = common::required(2, "front listen")?;
            let server = common::required(3, "server endpoint")?;
            let uuid = common::required(4, "uuid")?;
            let network = common::arg(5).unwrap_or_else(|| "tcp".into());
            let path = common::arg(6).unwrap_or_else(|| "/".into());
            let (xudp, mux) = match common::arg(7).as_deref() {
                None | Some("-" | "") => (false, false),
                Some("xudp") => (true, false),
                Some("mux") => (false, true),
                Some(other) => return Err(format!("unknown client option '{other}'").into()),
            };
            let insecure =
                common::arg(8).as_deref() == Some("insecure") || common::is_loopback(&server);
            let transport = transport_json(&network, &path)?;
            let json = format!(
                r#"{{ "inbounds": [ {{ "tag": "socks", "protocol": "socks5", "listen": "{listen}" }} ],
                      "outbounds": [ {{ "tag": "vless", "protocol": "vless", "server": "{server}",
                                        "uuid": "{uuid}", "tls": {{ "insecure": {insecure} }},
                                        "xudp": {xudp}, "mux": {mux},
                                        "transport": {transport} }} ],
                      "route": {{ "final": "vless" }} }}"#
            );
            common::serve(json).await
        }
        other => Err(format!("unknown mode '{other}'").into()),
    }
}

fn transport_json(network: &str, path: &str) -> Result<String, Box<dyn Error>> {
    Ok(match network {
        "tcp" => r#"{ "network": "tcp" }"#.into(),
        "ws" => format!(
            r#"{{ "network": "ws", "path": {}, "compression": true }}"#,
            common::json_string(path)
        ),
        "h2" => format!(
            r#"{{ "network": "h2", "path": {} }}"#,
            common::json_string(path)
        ),
        other => return Err(format!("unknown transport '{other}'").into()),
    })
}
