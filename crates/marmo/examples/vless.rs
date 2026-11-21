//! VLESS over TCP/TLS, WebSocket, or HTTP/2.
//!
//! Server:
//! ```sh
//! cargo run -p marmo --example vless -- server 0.0.0.0:443 UUID cert.pem key.pem [tcp|ws|h2] [path]
//! ```
//! Client (SOCKS5 front):
//! ```sh
//! cargo run -p marmo --example vless -- client 127.0.0.1:1080 proxy.example:443 UUID [tcp|ws|h2] [path] [xudp] [insecure]
//! ```
//! `xudp` selects XUDP framing for UDP instead of simple UoT. `insecure`
//! skips certificate verification and is accepted only for a loopback test
//! server.

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
            let xudp = common::arg(7).as_deref() == Some("xudp");
            let insecure = common::arg(8).as_deref() == Some("insecure");
            let transport = transport_json(&network, &path)?;
            let json = format!(
                r#"{{ "inbounds": [ {{ "tag": "socks", "protocol": "socks5", "listen": "{listen}" }} ],
                      "outbounds": [ {{ "tag": "vless", "protocol": "vless", "server": "{server}",
                                        "uuid": "{uuid}", "tls": {{ "insecure": {insecure} }},
                                        "xudp": {xudp}, "transport": {transport} }} ],
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
        "ws" => format!(r#"{{ "network": "ws", "path": "{path}", "compression": true }}"#),
        "h2" => format!(r#"{{ "network": "h2", "path": "{path}" }}"#),
        other => return Err(format!("unknown transport '{other}'").into()),
    })
}
