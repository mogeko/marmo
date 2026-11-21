//! Trojan over TLS.
//!
//! Server:
//! ```sh
//! cargo run -p marmo --example trojan -- server 0.0.0.0:443 cert.pem key.pem secret
//! ```
//! Client (SOCKS5 front):
//! ```sh
//! cargo run -p marmo --example trojan -- client 127.0.0.1:1080 proxy.example:443 secret
//! ```

#[path = "common/mod.rs"]
mod common;

use std::error::Error;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let mode = common::required(1, "mode (server|client)")?;
    match mode.as_str() {
        "server" => {
            let listen = common::required(2, "listen")?;
            let certificate = common::read(&common::required(3, "certificate path")?)?;
            let private_key = common::read(&common::required(4, "private key path")?)?;
            let password = common::required(5, "password")?;
            let fallback = common::arg(6)
                .map(|value| format!(r#", "fallback": "{value}""#))
                .unwrap_or_default();
            let json = format!(
                r#"{{ "inbounds": [ {{ "tag": "trojan", "protocol": "trojan", "listen": "{listen}",
                                       "password": "{password}"{fallback},
                                       "tls": {{ "certificate": {}, "private_key": {} }} }} ],
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
            let password = common::required(4, "password")?;
            let tls = match common::arg(5) {
                Some(sni) => format!(r#"{{ "sni": "{sni}" }}"#),
                None => r#"{ "insecure": true }"#.into(),
            };
            let json = format!(
                r#"{{ "inbounds": [ {{ "tag": "socks", "protocol": "socks5", "listen": "{listen}" }} ],
                      "outbounds": [ {{ "tag": "trojan", "protocol": "trojan",
                                        "server": "{server}", "password": "{password}",
                                        "tls": {tls} }} ],
                      "route": {{ "final": "trojan" }} }}"#
            );
            common::serve(json).await
        }
        other => Err(format!("unknown mode '{other}'").into()),
    }
}
