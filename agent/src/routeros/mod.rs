//! REST client for a RouterOS device.
//!
//! Used against the *host* router the agent runs on, reachable at the
//! container's default gateway. The binary API is better for streaming
//! commands like `bandwidth-test`, but everything discovery needs is a simple
//! read, and REST avoids implementing the binary sentence protocol.
//!
//! Self-signed certificates are the norm on RouterOS, so TLS verification is
//! optional and off by default — the connection does not leave the device.

pub mod btest;

use std::time::Duration;

use serde_json::Value;

#[derive(Debug, thiserror::Error)]
pub enum RouterOsError {
    #[error("transport error talking to RouterOS: {0}")]
    Transport(String),
    #[error("RouterOS rejected the credentials")]
    Unauthorized,
    #[error("RouterOS returned {status} for {path}: {body}")]
    Http { status: u16, path: String, body: String },
    #[error("could not parse the RouterOS response: {0}")]
    Decode(String),
}

pub struct RouterOs {
    http: reqwest::Client,
    base: String,
    user: String,
    pass: String,
}

impl RouterOs {
    pub fn new(
        host: &str,
        port: u16,
        user: &str,
        pass: &str,
        use_tls: bool,
        timeout: Duration,
    ) -> Result<Self, RouterOsError> {
        let http = reqwest::Client::builder()
            .timeout(timeout)
            // RouterOS ships a self-signed certificate by default and the
            // traffic never leaves the device, so requiring a valid chain here
            // would block the feature for almost every real deployment.
            .danger_accept_invalid_certs(use_tls)
            .build()
            .map_err(|e| RouterOsError::Transport(e.to_string()))?;

        let scheme = if use_tls { "https" } else { "http" };
        Ok(Self {
            http,
            base: format!("{scheme}://{host}:{port}"),
            user: user.to_string(),
            pass: pass.to_string(),
        })
    }

    /// GET a REST path, e.g. `/ip/arp`.
    pub async fn get(&self, path: &str) -> Result<Value, RouterOsError> {
        let url = format!("{}/rest{}", self.base, path);
        let resp = self
            .http
            .get(&url)
            .basic_auth(&self.user, Some(&self.pass))
            .send()
            .await
            .map_err(|e| RouterOsError::Transport(e.to_string()))?;
        Self::decode(resp, path).await
    }

    /// POST a RouterOS command, e.g. `/tool/traceroute`.
    pub async fn post(&self, path: &str, body: &Value) -> Result<Value, RouterOsError> {
        let url = format!("{}/rest{}", self.base, path);
        let resp = self
            .http
            .post(&url)
            .basic_auth(&self.user, Some(&self.pass))
            .json(body)
            .send()
            .await
            .map_err(|e| RouterOsError::Transport(e.to_string()))?;
        Self::decode(resp, path).await
    }

    async fn decode(resp: reqwest::Response, path: &str) -> Result<Value, RouterOsError> {
        let status = resp.status();
        if status == reqwest::StatusCode::UNAUTHORIZED {
            return Err(RouterOsError::Unauthorized);
        }
        let body = resp.text().await.map_err(|e| RouterOsError::Transport(e.to_string()))?;
        if !status.is_success() {
            // A 400 here usually means the menu does not exist on this device
            // — the legacy wireless stack on a wifi-only board, for instance —
            // which callers treat as "feature absent" rather than an error.
            return Err(RouterOsError::Http {
                status: status.as_u16(),
                path: path.to_string(),
                body: body.chars().take(200).collect(),
            });
        }
        serde_json::from_str(&body).map_err(|e| RouterOsError::Decode(e.to_string()))
    }

    /// Whether the credentials work and the REST service is reachable.
    pub async fn check(&self) -> Result<String, RouterOsError> {
        let v = self.get("/system/identity").await?;
        Ok(v.get("name").and_then(|n| n.as_str()).unwrap_or("unknown").to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_urls_for_both_schemes() {
        let plain = RouterOs::new("172.17.0.1", 80, "u", "p", false, Duration::from_secs(5)).unwrap();
        assert_eq!(plain.base, "http://172.17.0.1:80");

        let tls = RouterOs::new("172.17.0.1", 443, "u", "p", true, Duration::from_secs(5)).unwrap();
        assert_eq!(tls.base, "https://172.17.0.1:443");
    }

    #[test]
    fn a_blank_password_is_accepted() {
        // Lab and factory-default routers frequently have one, and refusing it
        // would make the tool unusable exactly where it is most needed.
        assert!(RouterOs::new("10.0.0.1", 80, "admin", "", false, Duration::from_secs(5)).is_ok());
    }
}
