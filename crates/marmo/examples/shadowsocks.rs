//! Shadowsocks 2022 server, or a SOCKS5 front using it as an outbound.
//!
//! Server:
//! ```sh
//! cargo run -p marmo --example shadowsocks -- server 127.0.0.1:8388 \
//!   2022-blake3-aes-128-gcm AAECAwQFBgcICQoLDA0ODw==
//! ```
//! Client (SOCKS5 front):
//! ```sh
//! cargo run -p marmo --example shadowsocks -- client 127.0.0.1:1080 \
//!   proxy.example:8388 2022-blake3-aes-128-gcm AAECAwQFBgcICQoLDA0ODw==
//! ```

#[path = "common/mod.rs"]
mod common;

use std::error::Error;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let mode = common::arg(1).unwrap_or_else(|| "server".into());
    match mode.as_str() {
        "server" => {
            let listen = common::arg(2).unwrap_or_else(|| "127.0.0.1:8388".into());
            let method = common::arg(3).unwrap_or_else(|| "2022-blake3-aes-128-gcm".into());
            let password = common::arg(4).unwrap_or_else(|| "AAECAwQFBgcICQoLDA0ODw==".into());
            let json = format!(
                r#"{{ "inbounds": [ {{ "tag": "ss", "protocol": "shadowsocks", "listen": "{listen}",
                                       "method": "{method}", "password": "{password}" }} ],
                      "outbounds": [ {{ "tag": "direct", "protocol": "direct" }} ],
                      "route": {{ "final": "direct" }} }}"#
            );
            common::serve(json).await
        }
        "client" => {
            let listen = common::arg(2).unwrap_or_else(|| "127.0.0.1:1080".into());
            let server = common::required(3, "server endpoint")?;
            let method = common::arg(4).unwrap_or_else(|| "2022-blake3-aes-128-gcm".into());
            let password = common::arg(5).unwrap_or_else(|| "AAECAwQFBgcICQoLDA0ODw==".into());
            let json = format!(
                r#"{{ "inbounds": [ {{ "tag": "socks", "protocol": "socks5", "listen": "{listen}" }} ],
                      "outbounds": [ {{ "tag": "ss", "protocol": "shadowsocks", "server": "{server}",
                                        "method": "{method}", "password": "{password}" }} ],
                      "route": {{ "final": "ss" }} }}"#
            );
            common::serve(json).await
        }
        other => Err(format!("unknown mode '{other}'").into()),
    }
}
