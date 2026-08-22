//! The Proton VPN API client.
//!
//! Correctness reference for endpoints/flow: <https://github.com/ProtonVPN/proton-vpn-cli>
use crate::errors::*;
use crate::keys::ClientIdentity;
use crate::models::*;
use crate::srp::prove;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use proton_srp::{SRPProofB64, SrpHashVersion};
use reqwest::header;

pub struct ProtonVPNClient {
    pub username: String,
    pub client: reqwest::Client,
    pub auth_token: Option<String>,
    /// Session UID from the auth response. Verified against `proton.session.transports.
    /// requests.RequestsTransport`: authenticated requests must carry BOTH
    /// `Authorization: Bearer <AccessToken>` AND `x-pm-uid: <UID>` — a request with only the
    /// bearer token gets a bare 401 (this was silently broken until fetch_certificate's live
    /// 401 surfaced it; `/vpn/v1/certificate` was the first call to require session auth).
    pub uid: Option<String>,
    /// Set after `login`/`refresh` — used by `session.rs`/`gratis login` to persist a
    /// resumable session. Never sent as a request header; only the bearer/UID pair is.
    pub refresh_token: Option<String>,
    pub vpn_credentials: Option<VPNCredentials>,
    pub server_list: Vec<VPNServer>,
}

impl ProtonVPNClient {
    /// Fails only if the underlying TLS/crypto backend can't be initialized (never on these
    /// fixed, valid header values) — but that failure is real on a misconfigured system, so it
    /// propagates as `ProtonError::Http` instead of panicking the whole process (see
    /// error_handling review F3: this used to be an `expect()` that could take down a
    /// long-running daemon over a one-time client-construction failure).
    pub fn new(username: &str) -> Result<Self> {
        let client = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .default_headers({
                let mut h = header::HeaderMap::new();
                // "Linux_5.2.5_web" (the value docs/references for this flow used to cite) is
                // rejected by Proton's live API with a bare 500 (no error body) as of this
                // writing; verified live against api.protonvpn.ch that this value is accepted.
                h.insert(
                    "x-pm-appversion",
                    header::HeaderValue::from_static("linux-vpn-cli@5.0.0"),
                );
                h.insert("x-pm-apiversion", header::HeaderValue::from_static("3"));
                h
            })
            .build()?;
        Ok(Self {
            username: username.to_string(),
            client,
            auth_token: None,
            uid: None,
            refresh_token: None,
            vpn_credentials: None,
            server_list: Vec::new(),
        })
    }

    /// Attach session auth headers (`Authorization: Bearer`, `x-pm-uid`) when logged in. Both
    /// are required together — a request with only the bearer token gets a bare 401.
    fn authed(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        let mut req = req;
        if let Some(token) = &self.auth_token {
            req = req.bearer_auth(token);
        }
        if let Some(uid) = &self.uid {
            req = req.header("x-pm-uid", uid);
        }
        req
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
        let req = self.authed(self.client.post(&url).json(body));
        let resp = req.send().await?;
        Self::into_json(resp).await
    }

    /// GET `path` (relative to `PROTON_API_URL`), returning typed JSON.
    async fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T> {
        let url = format!("{PROTON_API_URL}{path}");
        let req = self.authed(self.client.get(&url));
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
            // Mirror the decode-error branch below: never embed the raw body in an error that
            // can end up logged (`main.rs` logs `ProtonError::Api` at `warn!` on several
            // paths) — some responses on this client can carry key material or tokens. Report
            // only the status and top-level field names, which is enough to diagnose a shape
            // mismatch without risking a secret leak. If the body itself can't even be read
            // (e.g. connection reset mid-body), still preserve the status rather than
            // collapsing to an empty, contentless error.
            return Err(match resp.text().await {
                Ok(body) => {
                    let keys: Vec<String> = serde_json::from_str::<serde_json::Value>(&body)
                        .ok()
                        .and_then(|v| v.as_object().map(|o| o.keys().cloned().collect()))
                        .unwrap_or_default();
                    ProtonError::Api(format!("HTTP {status}; top-level fields: {keys:?}"))
                }
                Err(_) => ProtonError::Api(format!("HTTP {status} (body unreadable)")),
            });
        }
        let text = resp.text().await?;
        serde_json::from_str(&text).map_err(|e| {
            // Never include the raw body here: some responses on this client (e.g. the
            // account endpoint) carry private key material, and this error can end up in
            // logs. Report only the top-level field names present, which is enough to
            // diagnose a shape mismatch without risking a secret leak.
            let keys: Vec<String> = serde_json::from_str::<serde_json::Value>(&text)
                .ok()
                .and_then(|v| v.as_object().map(|o| o.keys().cloned().collect()))
                .unwrap_or_default();
            ProtonError::Api(format!("decode error: {e}; top-level fields: {keys:?}"))
        })
    }

    /// Authenticate via SRP-6a and load VPN credentials.
    pub async fn login(&mut self, email: &str, password: &str) -> Result<VPNCredentials> {
        // 1. Fetch SRP parameters for this user.
        // "/auth/v4/info" (the path this flow's docs/reference used to cite) also works
        // live, but "/auth/info" is what the official proton-core client actually calls
        // (verified by reading /usr/lib/python3/dist-packages/proton/session/api.py) — use
        // the same path the reference uses rather than a v4-prefixed alias that happens to
        // also route correctly today.
        let info: AuthInfo = self
            .post("/auth/info", &serde_json::json!({ "Username": email }))
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
        // "/auth/v4/authenticate" (the path this flow's docs/reference used to cite) is a
        // bare 404 live. "/auth/v4" also works (verified: a garbage-SRP-proof probe got a
        // genuine SRP-field validation error, not a routing 404), but the official
        // proton-core client actually posts to "/auth" (no version prefix) — use that,
        // matching the reference exactly.
        let auth: AuthResponse = self.post("/auth", &body).await?;

        // 4. The API signals success with `Code == 1000`.
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
        self.uid = auth.uid.clone();
        self.refresh_token = auth.refresh_token.clone();

        // 6. If the account has 2FA enabled, `/auth` succeeds (password was correct) but
        //    scopes the session down until a TOTP/FIDO2 code is also submitted — see
        //    `needs_twofa` in the reference cited on `TwoFactorResponse`. `self.auth_token`/
        //    `self.uid` are already set at this point, so the caller can go straight to
        //    `submit_2fa` without repeating SRP.
        if needs_twofa(&auth.scopes) {
            return Err(ProtonError::TwoFactorRequired);
        }

        self.issue_credentials(email).await
    }

    /// Complete a login that returned [`ProtonError::TwoFactorRequired`]: submit the
    /// account's TOTP code and, on success, finish the same way a non-2FA `login` would
    /// (mint a client identity + certificate). Must be called on the same `ProtonVPNClient`
    /// that returned `TwoFactorRequired` — it relies on `self.auth_token`/`self.uid` already
    /// being set from that call.
    pub async fn submit_2fa(&mut self, code: &str) -> Result<VPNCredentials> {
        let email = self.username.clone();
        let resp: TwoFactorResponse = self
            .post("/auth/2fa", &serde_json::json!({ "TwoFactorCode": code }))
            .await?;
        if resp.response_code != Some(1000) {
            return Err(ProtonError::Auth);
        }
        self.issue_credentials(&email).await
    }

    /// Resume a previously stored session (see `session.rs`) instead of running SRP again —
    /// this is what makes `gratis up`/`gratis run` fast: it skips the password-derived SRP
    /// math entirely and goes straight to minting a fresh certificate off the stored
    /// `access_token`. Call `fetch_servers` first with these credentials set to confirm the
    /// token is still valid (a `401` there means it needs `refresh`, not this).
    pub async fn authenticate_with_session(
        &mut self,
        uid: &str,
        access_token: &str,
    ) -> Result<VPNCredentials> {
        self.auth_token = Some(access_token.to_string());
        self.uid = Some(uid.to_string());
        let email = self.username.clone();
        self.issue_credentials(&email).await
    }

    /// Exchange a `refresh_token` for a new `access_token`/`refresh_token` pair, without
    /// re-running SRP. Endpoint/body shape verified against
    /// `proton.session.api.Session.async_refresh` (`/usr/lib/python3/dist-packages/proton/
    /// session/api.py`): the body carries `ResponseType`/`GrantType`/`RefreshToken`/
    /// `RedirectURI` only — **no `UID` field** — the account is identified purely by the
    /// `x-pm-uid` header (see `authed`), which is why `self.uid` must already be set before
    /// calling this.
    pub async fn refresh(&mut self, uid: &str, refresh_token: &str) -> Result<AuthResponse> {
        self.uid = Some(uid.to_string());
        let body = serde_json::json!({
            "ResponseType": "token",
            "GrantType": "refresh_token",
            "RefreshToken": refresh_token,
            "RedirectURI": "http://protonmail.ch",
        });
        let auth: AuthResponse = self.post("/auth/refresh", &body).await?;
        if auth.response_code != Some(1000) {
            return Err(ProtonError::Auth);
        }
        self.auth_token = auth.access_token.clone();
        self.uid = auth.uid.clone().or_else(|| Some(uid.to_string()));
        self.refresh_token = auth.refresh_token.clone();
        Ok(auth)
    }

    /// Generate a client WireGuard/certificate identity and ask Proton to sign it. Verified
    /// against proton-vpn-api-core: the server never hands back a private key (`GET
    /// /vpn/v2/account`, this flow's old source of `VPNCredentials`, doesn't exist for this
    /// purpose at all) — the client generates its own ed25519/X25519 keypair and requests a
    /// certificate for the public half. A fresh identity is minted every time this runs
    /// (fresh SRP login or session resume alike) rather than restored from a prior one;
    /// restoring a saved identity is not implemented (matches the daemon's existing,
    /// already-documented "no unattended restore" limitation) — `self.auth_token`/`self.uid`
    /// must already be set (by `login` or `authenticate_with_session`) before calling this.
    async fn issue_credentials(&mut self, email: &str) -> Result<VPNCredentials> {
        let identity = ClientIdentity::generate();
        let cert: CertificateResponse = self
            .post(
                "/vpn/v1/certificate",
                &serde_json::json!({
                    "ClientPublicKey": identity.ed25519_public_key_pem(),
                    "Duration": "168 min",
                }),
            )
            .await?;

        let creds = VPNCredentials {
            username: email.to_string(),
            ed25519_seed_b64: BASE64.encode(identity.ed25519_seed),
            wg_private_key: identity.wg_private_key_b64(),
            wg_public_key: identity.wg_public_key_b64(),
            certificate: cert.certificate,
            certificate_expires_at: cert.expiration_time,
        };
        self.vpn_credentials = Some(creds.clone());
        Ok(creds)
    }

    /// Fetch and parse the server list into `self.server_list`.
    pub async fn fetch_servers(&mut self) -> Result<()> {
        // Verified live + against proton-vpn-api-core's `MixinEndpointV1.LOGICALS`: the real
        // endpoint is "/vpn/v1/logicals" (nested logical -> physical servers), not the flat
        // "/vpn/v1/servers" this flow's docs/reference used to cite (which 404s live).
        let resp: LogicalServersResponse = self
            .get("/vpn/v1/logicals?SecureCoreFilter=all&WithState=true")
            .await?;
        self.server_list = resp
            .logical_servers
            .into_iter()
            .filter(|dto| dto.status == 1)
            .map(map_logical)
            .collect();
        Ok(())
    }

    /// Fetch this account's plan/tier/connection-limit info. Verified live (see
    /// `VPNSettings`'s doc comment) — used by `manager.rs` to filter the server list by the
    /// account's real tier instead of assuming free, and to enforce `MaxConnect` as the
    /// default simultaneous-tunnel cap.
    pub async fn fetch_account_info(&self) -> Result<VPNSettings> {
        self.get("/vpn/v2").await
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
                    && !s
                        .city
                        .as_deref()
                        .is_some_and(|x| x.eq_ignore_ascii_case(ci))
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

/// Whether an `/auth` (or `/auth/refresh`) response's `Scopes` list means 2FA still needs to
/// be completed. Verified against `proton.session.api.Session.needs_twofa`: the *only* signal
/// is `"twofactor"` being present in `Scopes` — there is no separate boolean flag.
fn needs_twofa(scopes: &[String]) -> bool {
    scopes.iter().any(|s| s == "twofactor")
}

/// Map a raw `LogicalServerDto` (only `Status == 1` logicals reach here) into a `VPNServer`,
/// keeping each physical server's entry IP paired with ITS OWN WireGuard public key — never
/// mixing IP and key across two different physical servers (flagged gap #2's root cause).
fn map_logical(dto: LogicalServerDto) -> VPNServer {
    VPNServer {
        id: dto.id,
        name: dto.name,
        country: dto.entry_country.clone(),
        country_code: dto.entry_country,
        city: dto.city,
        tier: dto.tier,
        load: dto.load,
        features: features_to_strings(dto.features),
        status: dto.status,
        physical: dto
            .servers
            .into_iter()
            .map(|p| PhysicalServer {
                entry_ip: p.entry_ip,
                domain: p.domain,
                x25519_public_key: p.x25519_public_key,
                enabled: p.status == 1,
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn needs_twofa_true_only_when_twofactor_scope_present() {
        assert!(needs_twofa(&["twofactor".to_string()]));
        assert!(needs_twofa(&["full".to_string(), "twofactor".to_string()]));
        assert!(!needs_twofa(&["full".to_string()]));
        assert!(!needs_twofa(&[]));
    }

    #[test]
    fn refresh_response_without_uid_falls_back_to_the_requested_uid() {
        // Verified live: /auth/refresh's response omits UID entirely (see `refresh`'s doc
        // comment) — the account is identified by the x-pm-uid header, not the body. Confirm
        // AuthResponse tolerates a missing UID rather than failing to parse.
        let json = r#"{
            "AccessToken": "new-access",
            "RefreshToken": "new-refresh",
            "Code": 1000,
            "Scopes": ["full"]
        }"#;
        let auth: AuthResponse = serde_json::from_str(json).expect("must parse without UID");
        assert_eq!(auth.uid, None);
        assert_eq!(auth.access_token.as_deref(), Some("new-access"));
        assert!(!needs_twofa(&auth.scopes));
    }
}
