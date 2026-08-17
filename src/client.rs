//! The Proton VPN API client.
//!
//! Correctness reference for endpoints/flow: <https://github.com/ProtonVPN/proton-vpn-cli>
use crate::errors::*;
use crate::models::*;
use reqwest::header;

pub struct ProtonVPNClient {
    pub username: String,
    pub client: reqwest::Client,
    pub auth_token: Option<String>,
    pub vpn_credentials: Option<VPNCredentials>,
    pub server_list: Vec<VPNServer>,
}

impl ProtonVPNClient {
    pub fn new(username: &str) -> Self {
        let client = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .default_headers({
                let mut h = header::HeaderMap::new();
                h.insert(
                    "x-pm-appversion",
                    header::HeaderValue::from_static("Linux_5.2.5_web"),
                );
                h.insert("x-pm-apiversion", header::HeaderValue::from_static("3"));
                h
            })
            .build()
            .expect("reqwest client");
        Self {
            username: username.to_string(),
            client,
            auth_token: None,
            vpn_credentials: None,
            server_list: Vec::new(),
        }
    }

    /// Authenticate via SRP-6a and load VPN credentials. Implemented in Task 02.
    pub async fn login(&mut self, _password: &str) -> Result<bool> {
        todo!("Task 02: SRP auth + /vpn/v2/account")
    }

    /// Fetch and parse the server list. Implemented in Task 02.
    pub async fn fetch_servers(&mut self) -> Result<bool> {
        todo!("Task 02: GET /vpn/v1/servers")
    }

    /// Find servers matching criteria, lowest load first. Pure (operates on `server_list`).
    pub fn find_servers(
        &self,
        country: Option<&str>,
        city: Option<&str>,
        feature: Option<&str>,
        user_tier: i32,
    ) -> Vec<VPNServer> {
        let mut results: Vec<VPNServer> = self
            .server_list
            .iter()
            .filter(|s| {
                if s.tier > user_tier {
                    return false;
                }
                if let Some(c) = country
                    && !s.country_code.eq_ignore_ascii_case(c)
                {
                    return false;
                }
                if let Some(ci) = city
                    && !s.city.as_deref().is_some_and(|x| x.eq_ignore_ascii_case(ci))
                {
                    return false;
                }
                if let Some(f) = feature
                    && !s.features.iter().any(|x| x.eq_ignore_ascii_case(f))
                {
                    return false;
                }
                true
            })
            .cloned()
            .collect();
        results.sort_by(|a, b| a.load.partial_cmp(&b.load).unwrap());
        results
    }

    /// Lowest-load server across the whole list.
    pub fn get_fastest_server(&self) -> Option<VPNServer> {
        self.server_list
            .iter()
            .min_by(|a, b| a.load.partial_cmp(&b.load).unwrap())
            .cloned()
    }
}
