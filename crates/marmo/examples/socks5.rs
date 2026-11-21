//! SOCKS5 inbound with a direct outbound.
//!
//! ```sh
//! cargo run -p marmo --example socks5 -- 127.0.0.1:1080
//! ```

#[path = "common/mod.rs"]
mod common;

use std::error::Error;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let listen = common::arg(1).unwrap_or_else(|| "127.0.0.1:1080".into());
    let json = format!(
        r#"{{ "inbounds": [ {{ "tag": "socks", "protocol": "socks5", "listen": "{listen}" }} ],
              "outbounds": [ {{ "tag": "direct", "protocol": "direct" }} ],
              "route": {{ "final": "direct" }} }}"#
    );
    common::serve(json).await
}
