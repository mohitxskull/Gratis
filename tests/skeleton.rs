#[test]
fn empty_client_has_no_fastest_server() {
    let client = proton_proxy::client::ProtonVPNClient::new("user@example.com");
    assert!(client.server_list.is_empty());
    assert!(client.get_fastest_server().is_none());
}
