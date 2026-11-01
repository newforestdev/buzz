//! APNs envelope construction, endpoint encryption, and response classification.

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use std::{sync::Mutex, time::Duration};

use async_trait::async_trait;
use reqwest::{header::CONTENT_TYPE, StatusCode};
use serde::Deserialize;
use thiserror::Error;

use crate::{config::ApnsEnvironment, model::APNS_RECONNECT_PAYLOAD};

/// Sanitized delivery outcome. Raw provider bodies never cross this boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryOutcome {
    /// APNs accepted the request (not proof of device delivery).
    Accepted,
    /// This endpoint generation is permanently invalid. APNs may provide the time it became invalid.
    InvalidEndpoint {
        /// APNs' timestamp for when the endpoint became invalid, if supplied.
        unregistered_at: Option<i64>,
    },
    /// A bounded retry is safe. A sanitized server hint may raise the delay.
    Retry {
        /// Retry-After delay in seconds, clamped by the transport.
        retry_after_seconds: Option<i64>,
    },
    /// Provider credential/profile configuration is unhealthy; do not invalidate endpoints.
    ConfigurationFault,
    /// The locally-generated request is permanently invalid.
    PermanentRequestFault,
}

/// Classify APNs status/reason without conflating provider faults with endpoints.
pub fn classify(code: u16, reason: Option<&str>, timestamp: Option<i64>) -> DeliveryOutcome {
    match (code, reason) {
        (200, _) => DeliveryOutcome::Accepted,
        (410, Some("Unregistered")) => DeliveryOutcome::InvalidEndpoint {
            unregistered_at: timestamp,
        },
        // Both reasons are ambiguous with deployment profile mistakes: APNs
        // uses BadDeviceToken for environment mismatches and
        // DeviceTokenNotForTopic for topic mismatches. Only Unregistered
        // crosses the permanent endpoint-invalidation boundary.
        (400, Some("BadDeviceToken" | "DeviceTokenNotForTopic")) => {
            DeliveryOutcome::ConfigurationFault
        }
        (403, _) | (429, Some("TooManyProviderTokenUpdates")) => {
            DeliveryOutcome::ConfigurationFault
        }
        (429 | 500 | 503, _)
        | (
            _,
            Some(
                "IdleTimeout"
                | "InternalServerError"
                | "ServiceUnavailable"
                | "Shutdown"
                | "TooManyRequests",
            ),
        ) => DeliveryOutcome::Retry {
            retry_after_seconds: None,
        },
        _ => DeliveryOutcome::PermanentRequestFault,
    }
}

/// Closed APNs transport controls. No field can be serialized into application
/// content; the concrete transport always uses `APNS_RECONNECT_PAYLOAD`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeliveryAttempt {
    pub request_id: uuid::Uuid,
    pub expires_at: i64,
}

/// APNs sender abstraction for live-validation tests.
#[async_trait]
pub trait PushTransport: Send + Sync {
    /// Send one durable job.
    async fn send(&self, attempt: DeliveryAttempt, endpoint: &str) -> DeliveryOutcome;
}

/// Direct HTTP/2 APNs transport using a client certificate or ES256 provider key.
pub struct ApnsTransport {
    client: reqwest::Client,
    topic: String,
    base_url: String,
    token_credentials: Option<TokenCredentials>,
}

struct TokenCredentials {
    signing_key: EncodingKey,
    key_id: String,
    team_id: String,
    cached: Mutex<Option<(i64, String)>>,
}

#[derive(serde::Serialize)]
struct ProviderClaims<'a> {
    iss: &'a str,
    iat: i64,
}

impl TokenCredentials {
    fn jwt(&self, now: i64) -> Result<String, ApnsError> {
        let mut cached = self.cached.lock().map_err(|_| ApnsError::Credential)?;
        if let Some((issued_at, token)) = cached.as_ref() {
            if (0..3000).contains(&(now - issued_at)) {
                return Ok(token.clone());
            }
        }
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.key_id.clone());
        let token = jsonwebtoken::encode(
            &header,
            &ProviderClaims {
                iss: &self.team_id,
                iat: now,
            },
            &self.signing_key,
        )
        .map_err(|_| ApnsError::Credential)?;
        *cached = Some((now, token.clone()));
        Ok(token)
    }
}

impl ApnsTransport {
    /// Build an HTTP/2 APNs transport from a mounted Apple ES256 provider key.
    pub fn token(
        p8: &[u8],
        key_id: &str,
        team_id: &str,
        topic: String,
        environment: ApnsEnvironment,
    ) -> Result<Self, ApnsError> {
        let signing_key = EncodingKey::from_ec_pem(p8).map_err(|_| ApnsError::Credential)?;
        let credentials = TokenCredentials {
            signing_key,
            key_id: key_id.to_owned(),
            team_id: team_id.to_owned(),
            cached: Mutex::new(None),
        };
        // Validate the key immediately, without logging its bytes or signed JWT.
        credentials.jwt(chrono::Utc::now().timestamp())?;
        let client = reqwest::Client::builder()
            .http2_keep_alive_while_idle(false)
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|_| ApnsError::Credential)?;
        let base_url = match environment {
            ApnsEnvironment::Production => "https://api.push.apple.com",
            ApnsEnvironment::Sandbox => "https://api.sandbox.push.apple.com",
        }
        .to_owned();
        Ok(Self {
            client,
            topic,
            base_url,
            token_credentials: Some(credentials),
        })
    }

    /// Build a reusable APNs client from a combined PEM private key and certificate.
    pub fn certificate(
        identity_pem: &[u8],
        topic: String,
        environment: ApnsEnvironment,
    ) -> Result<Self, ApnsError> {
        let base_url = match environment {
            ApnsEnvironment::Production => "https://api.push.apple.com",
            ApnsEnvironment::Sandbox => "https://api.sandbox.push.apple.com",
        };
        Self::certificate_with_base_url(identity_pem, topic, base_url.to_owned())
    }

    fn certificate_with_base_url(
        identity_pem: &[u8],
        topic: String,
        base_url: String,
    ) -> Result<Self, ApnsError> {
        let identity =
            reqwest::Identity::from_pem(identity_pem).map_err(|_| ApnsError::Credential)?;
        let client = reqwest::Client::builder()
            // APNs requires HTTP/2. This no-op method reference is intentionally
            // feature-gated so removing reqwest's `http2` feature fails the build.
            .http2_keep_alive_while_idle(false)
            .identity(identity)
            .timeout(Duration::from_secs(15))
            // Identity validation completes while the TLS client is built, so a
            // malformed or mismatched certificate/key pair is a credential error.
            .build()
            .map_err(|_| ApnsError::Credential)?;
        Ok(Self {
            client,
            topic,
            base_url,
            token_credentials: None,
        })
    }

    fn request(&self, attempt: DeliveryAttempt, endpoint: &str) -> reqwest::RequestBuilder {
        self.client
            .post(format!("{}/3/device/{endpoint}", self.base_url))
            .header(CONTENT_TYPE, "application/json")
            .header("apns-id", attempt.request_id.to_string())
            .header("apns-topic", &self.topic)
            .header("apns-push-type", "alert")
            .header("apns-priority", "10")
            .header("apns-expiration", attempt.expires_at.to_string())
            // This is the only APNs application body in the program. It is a
            // byte constant, not a serialization of the relay request, grant,
            // endpoint, headers, route, provider response, or any generic JSON map.
            .body(APNS_RECONNECT_PAYLOAD)
    }

    async fn send_response(
        &self,
        attempt: DeliveryAttempt,
        endpoint: &str,
    ) -> Result<reqwest::Response, ApnsError> {
        let mut request = self.request(attempt, endpoint);
        if let Some(credentials) = &self.token_credentials {
            request = request.bearer_auth(credentials.jwt(chrono::Utc::now().timestamp())?);
        }
        request.send().await.map_err(|_| ApnsError::Request)
    }
}

/// APNs transport setup failure. It intentionally carries no credential material.
#[derive(Debug, Error)]
pub enum ApnsError {
    /// Invalid client certificate identity material.
    #[error("invalid APNs credential")]
    Credential,
    /// Network failure; contains no token or request URL.
    #[error("APNs request failed")]
    Request,
}

#[derive(Deserialize)]
struct ApnsErrorBody {
    reason: Option<String>,
    timestamp: Option<i64>,
}

#[async_trait]
impl PushTransport for ApnsTransport {
    async fn send(&self, attempt: DeliveryAttempt, endpoint: &str) -> DeliveryOutcome {
        crate::metrics::record_apns_send_attempt();
        let response = self.send_response(attempt, endpoint).await;
        let response = match response {
            Ok(response) => response,
            Err(ApnsError::Credential) => return DeliveryOutcome::ConfigurationFault,
            Err(ApnsError::Request) => {
                return DeliveryOutcome::Retry {
                    retry_after_seconds: None,
                }
            }
        };
        if response.status() == StatusCode::OK {
            return DeliveryOutcome::Accepted;
        }
        let code = response.status().as_u16();
        let retry_after = response
            .headers()
            .get("retry-after")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<i64>().ok())
            .map(|seconds| seconds.clamp(1, 3600));
        let detail = response.json::<ApnsErrorBody>().await.ok();
        if code == 403
            && detail.as_ref().and_then(|d| d.reason.as_deref()) == Some("ExpiredProviderToken")
        {
            if let Some(credentials) = &self.token_credentials {
                if let Ok(mut cached) = credentials.cached.lock() {
                    *cached = None;
                }
                return DeliveryOutcome::Retry {
                    retry_after_seconds: Some(1),
                };
            }
        }
        let timestamp = detail.as_ref().and_then(|d| d.timestamp);
        let reason = detail.as_ref().and_then(|d| d.reason.as_deref());
        let outcome = match classify(code, reason, timestamp) {
            DeliveryOutcome::Retry { .. } => DeliveryOutcome::Retry {
                retry_after_seconds: retry_after,
            },
            outcome => outcome,
        };
        if outcome != DeliveryOutcome::Accepted {
            tracing::warn!(
                status = code,
                reason = sanitized_reason(reason),
                outcome = ?outcome,
                "APNs push request did not succeed"
            );
        }
        outcome
    }
}

fn sanitized_reason(reason: Option<&str>) -> &str {
    match reason {
        Some("BadDeviceToken") => "bad_device_token",
        Some("DeviceTokenNotForTopic") => "device_token_not_for_topic",
        Some("InvalidProviderToken") => "invalid_provider_token",
        Some("ExpiredProviderToken") => "expired_provider_token",
        Some("MissingProviderToken") => "missing_provider_token",
        Some("BadCertificate") => "bad_certificate",
        Some("BadCertificateEnvironment") => "bad_certificate_environment",
        Some("Forbidden") => "forbidden",
        Some("BadEnvironmentKeyIdInToken") => "bad_environment_key_id",
        Some("UnrelatedKeyIdInToken") => "unrelated_key_id",
        Some("TopicDisallowed") => "topic_disallowed",
        Some("BadTopic") => "bad_topic",
        Some("MissingTopic") => "missing_topic",
        Some("TopicMismatch") => "topic_mismatch",
        Some("TooManyProviderTokenUpdates") => "too_many_provider_token_updates",
        Some("Unregistered") => "unregistered",
        Some("TooManyRequests") => "too_many_requests",
        Some("ServiceUnavailable") => "service_unavailable",
        Some("InternalServerError") => "internal_server_error",
        // APNs uses short, single-token reason codes. Preserve an unknown code
        // only when it is bounded ASCII alphanumeric; never log a response body.
        Some(code)
            if (1..=64).contains(&code.len())
                && code.bytes().all(|byte| byte.is_ascii_alphanumeric()) =>
        {
            code
        }
        Some(_) => "unrecognized",
        None => "no_reason",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Bytes,
        extract::State,
        http::{HeaderMap, StatusCode},
        routing::post,
        Router,
    };
    use std::sync::{Arc, Mutex};

    // Self-signed test-only identity material. None of these are Apple credentials.
    const TEST_IDENTITY_PEM: &[u8] = include_bytes!("../tests/fixtures/apns-test-identity.pem");
    const TEST_CERT_ONLY_PEM: &[u8] = include_bytes!("../tests/fixtures/apns-test-cert-only.pem");
    const TEST_KEY_ONLY_PEM: &[u8] = include_bytes!("../tests/fixtures/apns-test-key-only.pem");
    const TEST_ENCRYPTED_IDENTITY_PEM: &[u8] =
        include_bytes!("../tests/fixtures/apns-test-encrypted-identity.pem");
    const TEST_MISMATCHED_IDENTITY_PEM: &[u8] =
        include_bytes!("../tests/fixtures/apns-test-mismatched-identity.pem");

    #[derive(Default)]
    struct CapturedRequest {
        headers: HeaderMap,
        body: Vec<u8>,
    }

    async fn capture_request(
        State(requests): State<Arc<Mutex<Vec<CapturedRequest>>>>,
        headers: HeaderMap,
        body: Bytes,
    ) -> StatusCode {
        requests.lock().unwrap().push(CapturedRequest {
            headers,
            body: body.to_vec(),
        });
        StatusCode::OK
    }

    // Generated test-only P-256 material, unrelated to any Apple account.
    const TEST_PROVIDER: &[u8] = include_bytes!("../tests/fixtures/apns-test-provider.p8");
    const TEST_PROVIDER_PUBLIC: &[u8] =
        include_bytes!("../tests/fixtures/apns-test-provider-public.pem");

    #[test]
    fn provider_jwt_is_signed_cached_and_renewed_before_expiry() {
        let transport = ApnsTransport::token(
            TEST_PROVIDER,
            "KEY1234567",
            "TEAM123456",
            "app.topic".into(),
            ApnsEnvironment::Sandbox,
        )
        .unwrap();
        let credentials = transport.token_credentials.as_ref().unwrap();
        let first = credentials.jwt(100).unwrap();
        assert_eq!(first, credentials.jwt(3099).unwrap());
        assert_ne!(first, credentials.jwt(3100).unwrap());
        let header = jsonwebtoken::decode_header(&first).unwrap();
        assert_eq!(header.alg, Algorithm::ES256);
        assert_eq!(header.kid.as_deref(), Some("KEY1234567"));
        let mut validation = jsonwebtoken::Validation::new(Algorithm::ES256);
        validation.required_spec_claims.clear();
        validation.validate_exp = false;
        let verified = jsonwebtoken::decode::<serde_json::Value>(
            &first,
            &jsonwebtoken::DecodingKey::from_ec_pem(TEST_PROVIDER_PUBLIC).unwrap(),
            &validation,
        )
        .unwrap();
        assert_eq!(verified.claims["iss"], "TEAM123456");
        assert_eq!(verified.claims["iat"], 100);
        assert_eq!(transport.base_url, "https://api.sandbox.push.apple.com");
    }

    #[tokio::test]
    async fn token_transport_sends_authenticated_fixed_reconnect_payload() {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let app = Router::new()
            .route("/3/device/{endpoint}", post(capture_request))
            .with_state(requests.clone());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let mut transport = ApnsTransport::token(
            TEST_PROVIDER,
            "KEY1234567",
            "TEAM123456",
            "app.topic".into(),
            ApnsEnvironment::Sandbox,
        )
        .unwrap();
        transport.base_url = base_url;
        assert_eq!(
            transport
                .send(
                    DeliveryAttempt {
                        request_id: uuid::Uuid::new_v4(),
                        expires_at: 100
                    },
                    &"00".repeat(32)
                )
                .await,
            DeliveryOutcome::Accepted
        );
        let captured = requests.lock().unwrap();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].body, APNS_RECONNECT_PAYLOAD);
        assert!(captured[0].headers[reqwest::header::AUTHORIZATION]
            .to_str()
            .unwrap()
            .starts_with("Bearer "));
        assert_eq!(captured[0].headers["apns-topic"], "app.topic");
    }

    #[tokio::test]
    async fn certificate_transport_sends_no_bearer_and_exact_body_for_every_attempt() {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let app = Router::new()
            .route("/3/device/{endpoint}", post(capture_request))
            .with_state(requests.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let transport = ApnsTransport::certificate_with_base_url(
            TEST_IDENTITY_PEM,
            "app.topic".to_owned(),
            base_url,
        )
        .unwrap();
        for (request_id, expires_at, endpoint) in [
            (uuid::Uuid::nil(), 1, "00".repeat(32)),
            (uuid::Uuid::max(), i64::MAX, "ff".repeat(32)),
        ] {
            assert_eq!(
                transport
                    .send(
                        DeliveryAttempt {
                            request_id,
                            expires_at,
                        },
                        &endpoint,
                    )
                    .await,
                DeliveryOutcome::Accepted
            );
        }
        let captured = requests.lock().unwrap();
        assert_eq!(captured.len(), 2);
        assert!(captured
            .iter()
            .all(|request| request.body.as_slice() == APNS_RECONNECT_PAYLOAD));
        assert!(captured
            .iter()
            .all(|request| !request.headers.contains_key(reqwest::header::AUTHORIZATION)));
        assert!(captured.iter().all(|request| request
            .headers
            .get("apns-topic")
            .is_some_and(|topic| topic == "app.topic")));
    }

    #[tokio::test]
    #[ignore = "requires the exported dogfood Apple Push Services PEM"]
    async fn live_sandbox_probe_reports_literal_status_and_body() {
        let cert_path = std::env::var("BUZZ_PUSH_LIVE_APNS_CERT_PATH")
            .expect("set BUZZ_PUSH_LIVE_APNS_CERT_PATH to the dogfood identity PEM");
        let topic = std::env::var("BUZZ_PUSH_LIVE_APNS_TOPIC")
            .expect("set BUZZ_PUSH_LIVE_APNS_TOPIC to the dogfood bundle id");
        let identity = std::fs::read(cert_path).unwrap();
        let transport =
            ApnsTransport::certificate(&identity, topic, ApnsEnvironment::Sandbox).unwrap();
        let response = transport
            .send_response(
                DeliveryAttempt {
                    request_id: uuid::Uuid::nil(),
                    expires_at: chrono::Utc::now().timestamp() + 60,
                },
                &"00".repeat(32),
            )
            .await
            .unwrap();
        let status = response.status();
        let body = response.text().await.unwrap();
        eprintln!("live APNs response: status={status}, body={body}");
        assert_eq!(status, reqwest::StatusCode::BAD_REQUEST);
        assert_eq!(body, r#"{"reason":"BadDeviceToken"}"#);
    }

    #[tokio::test]
    #[ignore = "requires a registered Apple APNs provider key"]
    async fn live_provider_key_authenticates_with_configured_environment() {
        let key_path = std::env::var("BUZZ_PUSH_APNS_KEY_PATH").expect("provider key path");
        let key_id = std::env::var("BUZZ_PUSH_APNS_KEY_ID").expect("provider key ID");
        let team_id = std::env::var("BUZZ_PUSH_APNS_TEAM_ID").expect("Apple team ID");
        let topic = std::env::var("BUZZ_PUSH_APNS_TOPIC").expect("APNs topic");
        let environment = match std::env::var("BUZZ_PUSH_LIVE_APNS_ENVIRONMENT")
            .as_deref()
            .unwrap_or("sandbox")
        {
            "sandbox" => ApnsEnvironment::Sandbox,
            "production" => ApnsEnvironment::Production,
            other => panic!("unsupported live APNs environment: {other}"),
        };
        let key = std::fs::read(key_path).expect("read mounted provider key");
        let transport = ApnsTransport::token(&key, &key_id, &team_id, topic, environment)
            .expect("valid provider key");
        let response = transport
            .send_response(
                DeliveryAttempt {
                    request_id: uuid::Uuid::new_v4(),
                    expires_at: chrono::Utc::now().timestamp() + 60,
                },
                &"00".repeat(32),
            )
            .await
            .expect("connect to Apple APNs");
        assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
        assert_eq!(
            response.text().await.expect("APNs response"),
            r#"{"reason":"BadDeviceToken"}"#
        );
    }

    #[tokio::test]
    #[ignore = "sends one generic alert to an explicitly selected enrolled test device"]
    async fn live_enrolled_device_accepts_generic_alert() {
        use base64::Engine as _;
        let config = crate::config::Config::from_env().expect("private gateway configuration");
        let credentials = config.profile.apns_token.expect("APNs provider key");
        let key = std::fs::read(credentials.key_path).expect("read mounted provider key");
        let transport = ApnsTransport::token(
            &key,
            &credentials.key_id,
            &credentials.team_id,
            config.profile.apns_topic,
            config.profile.apns_environment,
        )
        .expect("valid provider key");
        let ring = crate::token::TokenKeyring::new(
            config
                .token_keys
                .iter()
                .map(|k| crate::token::TokenKey::new(&k.id, &k.key).expect("token key"))
                .collect(),
        )
        .expect("token keyring");
        let encrypted = base64::engine::general_purpose::STANDARD
            .decode(
                std::env::var("BUZZ_PUSH_TEST_ENROLLED_CIPHERTEXT")
                    .expect("explicit test endpoint"),
            )
            .expect("encoded endpoint");
        let endpoint = ring.open(&encrypted).expect("decrypt registered endpoint");
        let endpoint = endpoint
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let response = transport
            .send_response(
                DeliveryAttempt {
                    request_id: uuid::Uuid::new_v4(),
                    expires_at: chrono::Utc::now().timestamp() + 60,
                },
                &endpoint,
            )
            .await
            .expect("connect to Apple APNs");
        assert_eq!(response.status(), reqwest::StatusCode::OK);
    }

    #[test]
    fn empty_certificate_identity_fails_as_a_credential_error() {
        assert_credential_error(b"");
    }

    #[test]
    fn malformed_certificate_identity_fails_as_a_credential_error() {
        assert_credential_error(b"not a PEM identity");
    }

    #[test]
    fn certificate_without_private_key_fails_as_a_credential_error() {
        assert_credential_error(TEST_CERT_ONLY_PEM);
    }

    #[test]
    fn private_key_without_certificate_fails_as_a_credential_error() {
        assert_credential_error(TEST_KEY_ONLY_PEM);
    }

    #[test]
    fn encrypted_private_key_fails_as_a_credential_error() {
        assert_credential_error(TEST_ENCRYPTED_IDENTITY_PEM);
    }

    #[test]
    fn mismatched_private_key_fails_as_a_credential_error() {
        // reqwest parses both PEM blocks, then rejects the mismatched pair while
        // building the TLS client. This locks the ClientBuilder error mapping.
        assert_credential_error(TEST_MISMATCHED_IDENTITY_PEM);
    }

    fn assert_credential_error(identity_pem: &[u8]) {
        assert!(matches!(
            ApnsTransport::certificate(
                identity_pem,
                "app.topic".to_owned(),
                ApnsEnvironment::Production,
            ),
            Err(ApnsError::Credential)
        ));
    }

    #[test]
    fn response_classes_do_not_massacre_endpoints_on_provider_faults() {
        assert_eq!(
            classify(410, Some("Unregistered"), Some(7)),
            DeliveryOutcome::InvalidEndpoint {
                unregistered_at: Some(7)
            }
        );
        for reason in ["InvalidProviderToken", "ExpiredProviderToken"] {
            assert_eq!(
                classify(403, Some(reason), None),
                DeliveryOutcome::ConfigurationFault
            );
        }
        for reason in ["BadDeviceToken", "DeviceTokenNotForTopic"] {
            assert_eq!(
                classify(400, Some(reason), None),
                DeliveryOutcome::ConfigurationFault
            );
        }
        assert_eq!(
            classify(429, Some("TooManyRequests"), None),
            DeliveryOutcome::Retry {
                retry_after_seconds: None
            }
        );
        assert_eq!(
            classify(400, Some("BadTopic"), None),
            DeliveryOutcome::PermanentRequestFault
        );
    }
}
