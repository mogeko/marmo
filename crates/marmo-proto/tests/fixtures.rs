//! Golden wire fixtures for every protocol codec.
//!
//! These bytes are fixed, self-generated or spec-derived vectors. They break
//! the encode/decode symmetry of round-trip tests: both sides must match the
//! same committed wire image. Cryptographic fixtures use fixed keys,
//! timestamps, and nonces; see `tests/fixtures/README.md`.

use marmo_net::Endpoint;
use marmo_proto::http::{parse_absolute, parse_connect_response, parse_request};
use marmo_proto::mux::{
    KEEPALIVE_META, NETWORK_TCP, NETWORK_UDP, STATUS_END, STATUS_KEEP, STATUS_KEEPALIVE,
    STATUS_NEW, encode_end_meta, encode_header, encode_keep_meta, encode_new_meta, parse_meta,
};
use marmo_proto::shadowsocks::{Direction, Method, decode_client_request, decode_udp_packet};
use marmo_proto::socks5::{Command, Greeting, Request, parse_udp};
use marmo_proto::trojan::{
    AuthState, PasswordHash, RequestProgress as TrojanProgress, auth_state, decode_udp_header,
    request_progress as trojan_request_progress,
};
use marmo_proto::vless::{
    COMMAND_MUX, COMMAND_TCP, RequestProgress as VlessProgress, Uuid, is_mux_target,
    request_progress as vless_request_progress, udp_progress,
};
use marmo_proto::vmess::{
    ChunkDecoder, ChunkProgress, CmdKey, OPTION_MASKING, OPTION_PADDING, OPTION_STREAM,
    RequestProgress as VmessProgress, ResponseProgress, Security,
    request_progress as vmess_request_progress, response_progress,
};

const UUID: &str = "00112233-4455-6677-8899-aabbccddeeff";
const NOW: u64 = 1_700_000_000;

fn endpoint(domain: &str, port: u16) -> Endpoint {
    Endpoint::from_domain(domain, port).expect("fixture endpoint")
}

fn ip_endpoint(ip: &str, port: u16) -> Endpoint {
    Endpoint::from_ip(ip.parse().expect("fixture IP"), port)
}

#[test]
fn http_fixtures_match() {
    let connect = include_bytes!("fixtures/http/request-connect.http");
    let head = parse_request(connect).expect("CONNECT request");
    assert_eq!(head.method, "CONNECT");
    assert_eq!(head.target, "example.com:443");
    assert_eq!(head.version, 1);

    let forward = include_bytes!("fixtures/http/request-forward.http");
    let head = parse_request(forward).expect("forward request");
    assert_eq!(head.method, "GET");
    let target = parse_absolute(head.target).expect("absolute target");
    assert_eq!(target.endpoint, endpoint("example.com", 80));
    assert_eq!(target.path, "/a?b=1");

    let response = include_bytes!("fixtures/http/response-connect.http");
    let (status, consumed) = parse_connect_response(response).expect("CONNECT response");
    assert_eq!(status, 200);
    assert_eq!(consumed, response.len());
}

#[test]
fn socks5_fixtures_match() {
    let greeting =
        Greeting::parse(include_bytes!("fixtures/socks5/greeting.bin")).expect("greeting");
    assert!(greeting.accepts_no_auth());
    assert_eq!(greeting.methods(), &[0]);

    let request =
        Request::parse(include_bytes!("fixtures/socks5/connect-ipv4.bin")).expect("IPv4 request");
    assert_eq!(request.command, Command::Connect);
    assert_eq!(request.destination, ip_endpoint("127.0.0.1", 443));

    let request = Request::parse(include_bytes!("fixtures/socks5/connect-domain.bin"))
        .expect("domain request");
    assert_eq!(request.command, Command::Connect);
    assert_eq!(request.destination, endpoint("example.com", 443));

    let udp = parse_udp(include_bytes!("fixtures/socks5/udp-ipv4.bin")).expect("UDP datagram");
    assert_eq!(udp.destination, ip_endpoint("127.0.0.1", 53));
    assert_eq!(udp.payload, b"hello");
}

#[test]
fn shadowsocks_fixtures_match() {
    let method = Method::Aes128Gcm;
    let psk = [0x11_u8; 32];
    let mut plaintext = [0_u8; 65_535];
    let request = decode_client_request(
        method,
        &psk,
        include_bytes!("fixtures/shadowsocks/tcp-request.bin"),
        &mut plaintext,
        NOW,
    )
    .expect("SS2022 TCP request");
    assert_eq!(request.target, endpoint("example.com", 443));
    assert_eq!(request.initial_payload, b"hello");
    assert_eq!(
        request.consumed,
        include_bytes!("fixtures/shadowsocks/tcp-request.bin").len()
    );
    drop(request);

    let packet = decode_udp_packet(
        method,
        &psk,
        include_bytes!("fixtures/shadowsocks/udp-packet.bin"),
        Direction::ClientToServer,
        None,
        &mut plaintext,
    )
    .expect("SS2022 UDP packet");
    assert_eq!(packet.session_id, [0x33; 8]);
    assert_eq!(packet.packet_id, 7);
    assert_eq!(packet.timestamp, NOW);
    assert_eq!(packet.destination, endpoint("example.com", 53));
    assert_eq!(packet.payload, b"datagram");
}

#[test]
fn trojan_fixtures_match() {
    let hash = PasswordHash::derive("password");
    assert_eq!(
        auth_state(include_bytes!("fixtures/trojan/auth.bin"), &hash),
        AuthState::Matched
    );

    let request_bytes = include_bytes!("fixtures/trojan/request-ipv4.bin");
    let TrojanProgress::Complete(request) = trojan_request_progress(request_bytes) else {
        panic!("expected a complete Trojan request");
    };
    assert_eq!(
        request.target,
        Endpoint::from_ip("1.2.3.4".parse().unwrap(), 443)
    );
    assert_eq!(request.consumed, request_bytes.len());

    let (target, payload_len, consumed) =
        decode_udp_header(include_bytes!("fixtures/trojan/udp-ipv4.bin")).expect("Trojan UDP");
    assert_eq!(target, ip_endpoint("127.0.0.1", 53));
    assert_eq!(payload_len, 5);
    assert_eq!(consumed, 11);
}

#[test]
fn vless_fixtures_match() {
    let uuid = Uuid::parse(UUID).expect("uuid");
    for (fixture, target) in [
        (
            include_bytes!("fixtures/vless/request-ipv4.bin").as_slice(),
            Endpoint::from_ip("1.2.3.4".parse().unwrap(), 443),
        ),
        (
            include_bytes!("fixtures/vless/request-domain.bin").as_slice(),
            endpoint("example.com", 443),
        ),
    ] {
        let VlessProgress::Complete(request) = vless_request_progress(fixture) else {
            panic!("expected a complete VLESS request");
        };
        assert!(request.uuid.matches(uuid.as_bytes()));
        assert_eq!(request.command, COMMAND_TCP);
        assert_eq!(request.target, target);
        assert_eq!(request.consumed, fixture.len());
    }

    let mux = include_bytes!("fixtures/vless/mux-request.bin");
    let VlessProgress::Complete(request) = vless_request_progress(mux) else {
        panic!("expected a complete VLESS mux request");
    };
    assert_eq!(request.command, COMMAND_MUX);
    assert!(is_mux_target(&request.target));

    let uot = include_bytes!("fixtures/vless/uot-frame.bin");
    assert_eq!(
        udp_progress(&uot[..2]),
        marmo_proto::vless::UdpProgress::Complete { payload_len: 4 }
    );
    assert_eq!(&uot[2..], b"hi!!");
}

#[test]
fn vmess_fixtures_match() {
    let uuid = Uuid::parse(UUID).expect("uuid");
    let key = CmdKey::derive(&uuid);
    let request_bytes = include_bytes!("fixtures/vmess/request.bin");
    let VmessProgress::Complete(request) = vmess_request_progress(request_bytes, &key, NOW) else {
        panic!("expected a complete VMess request");
    };
    assert_eq!(request.command, marmo_proto::vmess::COMMAND_TCP);
    assert_eq!(request.target, endpoint("example.com", 443));
    assert_eq!(request.security, Security::Aes128Gcm);
    assert_eq!(request.response_auth, 0x5a);
    assert_eq!(request.consumed, request_bytes.len());

    let response = include_bytes!("fixtures/vmess/response.bin");
    assert_eq!(
        response_progress(response, &request),
        ResponseProgress::Complete {
            consumed: response.len()
        }
    );

    let chunk = include_bytes!("fixtures/vmess/chunk.bin");
    let mut decoder = ChunkDecoder::new(
        Security::Aes128Gcm,
        &[0x22; 16],
        &[0x11; 16],
        OPTION_STREAM | OPTION_MASKING | OPTION_PADDING,
    );
    let ChunkProgress::Complete { consumed, data } = decoder.progress(chunk).expect("VMess chunk")
    else {
        panic!("expected a complete VMess chunk");
    };
    assert_eq!(consumed, chunk.len());
    assert_eq!(data, b"first");
}

#[test]
fn mux_fixtures_match() {
    let target = endpoint("example.com", 443);
    let new = include_bytes!("fixtures/mux/new-tcp.meta");
    let meta = parse_meta(new).expect("New metadata");
    assert_eq!(meta.session, 7);
    assert_eq!(meta.status, STATUS_NEW);
    assert_eq!(meta.network, NETWORK_TCP);
    assert_eq!(meta.target, Some(target.clone()));

    let keep = include_bytes!("fixtures/mux/keep-udp.meta");
    let meta = parse_meta(keep).expect("Keep metadata");
    assert_eq!(meta.session, 7);
    assert_eq!(meta.status, STATUS_KEEP);
    assert_eq!(meta.network, NETWORK_UDP);
    assert_eq!(meta.target, Some(endpoint("example.com", 53)));

    let end = include_bytes!("fixtures/mux/end.meta");
    let meta = parse_meta(end).expect("End metadata");
    assert_eq!(meta.session, 7);
    assert_eq!(meta.status, STATUS_END);
    assert_eq!(meta.target, None);

    let keepalive = include_bytes!("fixtures/mux/keepalive.meta");
    assert_eq!(keepalive, &KEEPALIVE_META);
    assert_eq!(
        parse_meta(keepalive).expect("KeepAlive metadata").status,
        STATUS_KEEPALIVE
    );

    let mut out = [0_u8; 600];
    let length = encode_new_meta(7, &target, NETWORK_TCP, &mut out).expect("encode New");
    assert_eq!(&out[..length], new);
    let length =
        encode_keep_meta(7, Some(&endpoint("example.com", 53)), &mut out).expect("encode Keep");
    assert_eq!(&out[..length], keep);
    let length = encode_end_meta(7, &mut out).expect("encode End");
    assert_eq!(&out[..length], end);

    let frame = include_bytes!("fixtures/mux/new-tcp.frame");
    let length = encode_header(new, 9, &mut out).expect("encode frame header");
    assert_eq!(&out[..length], &frame[..length]);
    assert_eq!(&frame[length..], b"hello mux");
}
