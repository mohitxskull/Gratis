//! Throwaway, non-committed verification script: performs a real userspace WireGuard
//! handshake against a live Proton server (via `boringtun`, no root/TUN/`sudo` needed — just
//! a plain UDP socket) using the exact keys/config `generate_config` would produce, then sends
//! an ICMP echo request to the internal gateway (10.2.0.1) through the tunnel and checks for a
//! reply. This answers the open question from the session: does Proton actually route traffic
//! through the tunnel without the "Local Agent" authorization step this daemon doesn't
//! implement? Not part of the crate's plan; delete after use.
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use etherparse::{IcmpEchoHeader, Icmpv4Type, PacketBuilder, PacketHeaders, TransportHeader};
use proton_proxy::client::ProtonVPNClient;
use std::net::UdpSocket;
use std::time::Duration;

fn read_env_file_var(key: &str) -> String {
    let content = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".env"),
    )
    .expect("failed to read .env");
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix(&format!("{key}=")) {
            return rest.to_string();
        }
    }
    panic!("{key} not found in .env");
}

fn decode_key(b64: &str) -> [u8; 32] {
    let bytes = BASE64.decode(b64).expect("valid base64 key");
    bytes.try_into().expect("32-byte key")
}

#[tokio::main]
async fn main() {
    let email = read_env_file_var("EMAIL");
    let password = read_env_file_var("PASSWORD");

    let mut client = ProtonVPNClient::new(&email);
    println!("logging in...");
    let creds = client.login(&email, &password).await.expect("login");
    println!("login OK");

    client.fetch_servers().await.expect("fetch_servers");
    let server = client
        .server_list
        .iter()
        .find(|s| s.country_code.eq_ignore_ascii_case("US"))
        .expect("a US server");
    let physical = server.pick_physical().expect("a physical server");
    println!(
        "connecting to {} ({}) via {}",
        server.name, server.country, physical.entry_ip
    );

    let private = StaticSecret::from(decode_key(&creds.wg_private_key));
    let peer_public = PublicKey::from(decode_key(&physical.x25519_public_key));
    let mut tunn = Tunn::new(private, peer_public, None, None, 0, None);

    let sock = UdpSocket::bind("0.0.0.0:0").expect("bind udp socket");
    sock.connect((physical.entry_ip.as_str(), proton_proxy::wireguard::WG_PORT))
        .expect("connect udp socket");
    sock.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");

    // --- Handshake ---
    let mut buf = vec![0u8; 2048];
    match tunn.format_handshake_initiation(&mut buf, false) {
        TunnResult::WriteToNetwork(packet) => {
            sock.send(packet).expect("send handshake initiation");
        }
        other => panic!("unexpected format_handshake_initiation result: {other:?}"),
    }
    println!("sent handshake initiation, waiting for response...");

    let mut recv_buf = vec![0u8; 2048];
    let n = sock.recv(&mut recv_buf).expect("recv handshake response (timed out = no reply from server)");
    println!("received {n} bytes (handshake response)");

    let mut out_buf = vec![0u8; 2048];
    match tunn.decapsulate(None, &recv_buf[..n], &mut out_buf) {
        TunnResult::WriteToNetwork(packet) => {
            sock.send(packet).expect("send handshake ack");
            println!("handshake complete (sent ack)");
        }
        TunnResult::Done => println!("handshake complete (no ack needed)"),
        other => panic!("unexpected decapsulate result during handshake: {other:?}"),
    }

    // --- Send an ICMP echo request to the internal gateway through the tunnel ---
    let payload = [1u8, 2, 3, 4, 5, 6, 7, 8];
    let builder = PacketBuilder::ipv4([10, 2, 0, 2], [10, 2, 0, 1], 64)
        .icmpv4_echo_request(0xABCD, 1);
    let mut ip_packet = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut ip_packet, &payload).expect("build ICMP packet");

    let mut enc_buf = vec![0u8; ip_packet.len() + 64];
    match tunn.encapsulate(&ip_packet, &mut enc_buf) {
        TunnResult::WriteToNetwork(packet) => {
            sock.send(packet).expect("send ICMP echo request");
            println!("sent ICMP echo request to 10.2.0.1 through the tunnel, waiting for reply...");
        }
        other => panic!("unexpected encapsulate result: {other:?}"),
    }

    let n = match sock.recv(&mut recv_buf) {
        Ok(n) => n,
        Err(e) => {
            println!("NO REPLY within 5s ({e}) — tunnel handshake succeeded but no traffic came back.");
            println!("This is consistent with Proton requiring the Local Agent authorization step.");
            return;
        }
    };
    println!("received {n} bytes back through the tunnel");

    let mut out_buf2 = vec![0u8; 2048];
    match tunn.decapsulate(None, &recv_buf[..n], &mut out_buf2) {
        TunnResult::WriteToTunnelV4(packet, addr) => {
            println!("decapsulated {} bytes from {addr}", packet.len());
            match PacketHeaders::from_ip_slice(packet) {
                Ok(headers) => match headers.transport {
                    Some(TransportHeader::Icmpv4(icmp)) => match icmp.icmp_type {
                        Icmpv4Type::EchoReply(IcmpEchoHeader { id, seq }) => {
                            println!(
                                "SUCCESS: got a genuine ICMP echo reply (id={id}, seq={seq}) — traffic flows through the tunnel without any Local Agent step."
                            );
                        }
                        other => println!("got an ICMP packet but not an echo reply: {other:?}"),
                    },
                    other => println!("got a non-ICMP transport header back: {other:?}"),
                },
                Err(e) => println!("could not parse the returned packet as IP: {e}"),
            }
        }
        other => println!("unexpected decapsulate result for the ICMP reply: {other:?}"),
    }

    // --- Also confirm actual internet-bound traffic (not just a reply from the gateway
    //     itself): a DNS query through Proton's internal resolver for a real domain. ---
    let mut dns_query = vec![
        0x12, 0x34, // ID
        0x01, 0x00, // flags: standard query, recursion desired
        0x00, 0x01, // QDCOUNT = 1
        0x00, 0x00, // ANCOUNT
        0x00, 0x00, // NSCOUNT
        0x00, 0x00, // ARCOUNT
    ];
    for label in "example.com".split('.') {
        dns_query.push(label.len() as u8);
        dns_query.extend_from_slice(label.as_bytes());
    }
    dns_query.push(0); // root label
    dns_query.extend_from_slice(&[0x00, 0x01]); // QTYPE = A
    dns_query.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN

    let dns_builder = PacketBuilder::ipv4([10, 2, 0, 2], [10, 2, 0, 1], 64).udp(54321, 53);
    let mut dns_ip_packet = Vec::with_capacity(dns_builder.size(dns_query.len()));
    dns_builder
        .write(&mut dns_ip_packet, &dns_query)
        .expect("build DNS query packet");

    let mut enc_buf2 = vec![0u8; dns_ip_packet.len() + 64];
    match tunn.encapsulate(&dns_ip_packet, &mut enc_buf2) {
        TunnResult::WriteToNetwork(packet) => {
            sock.send(packet).expect("send DNS query");
            println!(
                "sent a DNS query for example.com to 10.2.0.1:53 through the tunnel, waiting for reply..."
            );
        }
        other => panic!("unexpected encapsulate result for DNS query: {other:?}"),
    }

    let n = match sock.recv(&mut recv_buf) {
        Ok(n) => n,
        Err(e) => {
            println!("NO DNS REPLY within 5s ({e}).");
            return;
        }
    };
    let mut out_buf3 = vec![0u8; 2048];
    match tunn.decapsulate(None, &recv_buf[..n], &mut out_buf3) {
        TunnResult::WriteToTunnelV4(packet, addr) => {
            println!("decapsulated {} bytes from {addr}", packet.len());
            match PacketHeaders::from_ip_slice(packet) {
                Ok(headers) => {
                    println!("transport header: {:?}", headers.transport);
                    // `payload` is already just the UDP payload (the DNS message) — etherparse
                    // separates headers from payload during parsing.
                    let payload = headers.payload.slice();
                    println!("payload first 16 bytes: {:02x?}", &payload[..payload.len().min(16)]);
                    if payload.len() >= 12 {
                        // DNS header: ANCOUNT is bytes 6..8 of the DNS message.
                        let ancount = u16::from_be_bytes([payload[6], payload[7]]);
                        println!(
                            "SUCCESS: got a DNS response for example.com through the tunnel, ANCOUNT={ancount} — real internet-bound traffic flows without any Local Agent step."
                        );
                    } else {
                        println!("DNS response payload too short: {} bytes", payload.len());
                    }
                }
                Err(e) => println!("could not parse the DNS reply packet as IP: {e}"),
            }
        }
        other => println!("unexpected decapsulate result for the DNS reply: {other:?}"),
    }
}
