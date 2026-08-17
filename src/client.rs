//! The Proton VPN API client.
//!
//! Correctness reference for endpoints/flow: <https://github.com/ProtonVPN/proton-vpn-cli>
use crate::errors::*;
use crate::models::*;
use crate::srp::prove;
use proton_srp::{SRPProofB64, SrpHashVersion};
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

    /// POST `body` as JSON to `path` (relative to `PROTON_API_URL`), returning typed JSON.
    ///
    /// On `401` -> `ProtonError::Auth`; on any other >=400 status -> `ProtonError::Api`.
    async fn post<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<T> {
        let url = format!("{PROTON_API_URL}{path}");
        let mut req = self.client.post(&url).json(body);
        if let Some(token) = &self.auth_token {
            req = req.bearer_auth(token);
        }
        let resp = req.send().await?;
        Self::into_json(resp).await
    }

    /// GET `path` (relative to `PROTON_API_URL`), returning typed JSON.
    async fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T> {
        let url = format!("{PROTON_API_URL}{path}");
        let mut req = self.client.get(&url);
        if let Some(token) = &self.auth_token {
            req = req.bearer_auth(token);
        }
        let resp = req.send().await?;
        Self::into_json(resp).await
    }

    /// Turn a response into typed JSON, mapping status errors to `ProtonError`.
    async fn into_json<T: serde::de::DeserializeOwned>(resp: reqwest::Response) -> Result<T> {
        let status = resp.status();
        if status == reqwest::StatusCode::UNAUTHORIZED {
            return Err(ProtonError::Auth);
        }
        if !status.is_success() {
            let msg = resp.text().await.unwrap_or_default();
            return Err(ProtonError::Api(msg));
        }
        Ok(resp.json::<T>().await?)
    }

    /// Authenticate via SRP-6a and load VPN credentials.
    pub async fn login(&mut self, email: &str, password: &str) -> Result<VPNCredentials> {
        // 1. Fetch SRP parameters for this user.
        let info: AuthInfo = self
            .post(
                "/auth/v4/info",
                &serde_json::json!({ "Username": email }),
            )
            .await?;

        // 2. Build the SRP proofs. `info.version` is a u32 protocol version; cast to u8 for
        //    the enum.
        let version = SrpHashVersion::try_from(info.version as u8)?;
        let (client_ephemeral, client_proof, expected_server_proof) = prove(
            Some(email),
            password,
            version,
            &info.salt,
            &info.modulus,
            &info.server_ephemeral,
        )?;

        // 3. Authenticate.
        let body = serde_json::json!({
            "Username": email,
            "ClientEphemeral": client_ephemeral,
            "ClientProof": client_proof,
            "SRPSession": info.srp_session,
            "TwoFactorCode": null,
        });
        let auth: AuthResponse = self.post("/auth/v4/authenticate", &body).await?;

        // 4. The API signals success with `ResponseCode == 1000`.
        if auth.response_code != Some(1000) {
            return Err(ProtonError::Auth);
        }

        // 5. (recommended) verify the server proof if the response carried one.
        if let Some(sp) = &auth.server_proof {
            let proof_ok = SRPProofB64 {
                client_ephemeral: client_ephemeral.clone(),
                client_proof: client_proof.clone(),
                expected_server_proof: expected_server_proof.clone(),
            }
            .compare_server_proof(sp);
            if !proof_ok {
                return Err(ProtonError::Auth);
            }
        }

        self.auth_token = auth.access_token.clone();

        // 6. Fetch the VPN account and build credentials.
        let account: AccountResponse = self.get("/vpn/v2/account").await?;
        let vpn = account.vpn;
        let creds = VPNCredentials {
            username: vpn.user_name,
            password: vpn.password,
            certificate: vpn.pub_key_credential.certificate_pem,
            wg_public_key: vpn.pub_key_credential.public_key,
            wg_private_key: vpn.pub_key_credential.private_key,
        };
        self.vpn_credentials = Some(creds.clone());
        Ok(creds)
    }

    /// Fetch and parse the server list into `self.server_list`.
    pub async fn fetch_servers(&mut self) -> Result<()> {
        let resp: ServersResponse = self.get("/vpn/v1/servers").await?;
        self.server_list = resp
            .servers
            .into_iter()
            .filter(|dto| dto.status == 1)
            .map(map_server)
            .collect();
        Ok(())
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

/// Map a raw `ServerDto` (only `Status == 1` servers reach here) into a `VPNServer`.
///
/// `country_code` comes from `EntryCountry`; `ips` from `Addresses[].IP`; the WireGuard peer
/// public key comes from `WGPublicKey` (NOT `ips[0]` — flagged gap #2).
fn map_server(dto: ServerDto) -> VPNServer {
    VPNServer {
        id: dto.id,
        name: dto.name,
        country: dto.entry_country.clone(),
        country_code: dto.entry_country,
        city: dto.city,
        tier: dto.tier,
        load: dto.load,
        features: features_to_strings(dto.features, dto.is_secure_core),
        ips: dto.addresses.into_iter().map(|a| a.ip).collect(),
        status: dto.status,
        wg_public_key: dto.wg_public_key,
    }
}
