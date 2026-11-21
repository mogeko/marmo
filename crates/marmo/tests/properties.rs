//! Property tests for parsing boundaries that see untrusted text.

use marmo::{Config, Endpoint, Router};
use proptest::prelude::*;

proptest! {
    #[test]
    fn config_never_panics(text in "\\PC{0,2048}") {
        let _ = Config::from_json(&text);
    }

    #[test]
    fn endpoint_never_panics(text in "\\PC{0,128}") {
        let _ = Endpoint::parse(&text);
    }

    #[test]
    fn routing_compiles_or_errors(text in "\\PC{0,2048}") {
        if let Ok(config) = Config::from_json(&text) {
            let _ = Router::compile(&config);
        }
    }
}
