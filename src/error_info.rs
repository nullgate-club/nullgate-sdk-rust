use std::{any::Any, error::Error as StdError, fmt, sync::Arc};

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Optional structured service diagnostic metadata; unknown codes are retained.
#[derive(Clone, Deserialize)]
pub struct ErrorInfo {
    /// Machine-readable service code.
    pub code: String,
    /// One of client, request, service, or upstream.
    pub origin: String,
    /// Safe service explanation, available for explicit inspection.
    pub message: String,
    /// Server retry advice; this SDK never retries automatically.
    pub retryable: Option<bool>,
    /// Failed processing stage.
    pub stage: Option<String>,
    /// Server-derived target context.
    pub target: Option<ErrorTarget>,
    /// Sanitized client transport category.
    pub cause: Option<TransportCause>,
    /// Positive ID of the failed issued target HTTP command, when known.
    pub command_id: Option<i64>,
}

/// Server-derived target context without URL paths or credentials.
#[derive(Clone, Deserialize)]
pub struct ErrorTarget {
    /// Issued command role.
    pub role: String,
    /// HTTP method.
    pub method: String,
    /// Target host only.
    pub host: String,
}

/// Safe transport facts, never raw exception text.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TransportCause {
    /// timeout, dns, tls, proxy, connection, cancelled, invalid_response, or unknown.
    pub kind: String,
    /// Optional validated exception identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    /// Optional validated provider code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

impl fmt::Debug for ErrorInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ErrorInfo")
            .field("code", &self.display_code())
            .field("origin", &self.origin)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for ErrorTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ErrorTarget").finish_non_exhaustive()
    }
}

fn token(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
}

impl ErrorInfo {
    pub(crate) fn display_origin(&self) -> &str {
        match self.origin.as_str() {
            "client" | "request" | "service" | "upstream" => &self.origin,
            _ => "unknown",
        }
    }

    pub(crate) fn display_code(&self) -> &str {
        if token(&self.code, 128) {
            &self.code
        } else {
            "UNKNOWN"
        }
    }

    pub(crate) fn parse(value: Option<Value>) -> Option<Self> {
        let value = value?;
        value.get("retryable")?;
        let info: Self = serde_json::from_value(value).ok()?;
        if !matches!(
            info.origin.as_str(),
            "client" | "request" | "service" | "upstream"
        ) {
            return None;
        }
        if info.command_id.is_some_and(|id| id <= 0) {
            return None;
        }
        if let Some(cause) = &info.cause
            && (!matches!(
                cause.kind.as_str(),
                "timeout"
                    | "dns"
                    | "tls"
                    | "proxy"
                    | "connection"
                    | "cancelled"
                    | "invalid_response"
                    | "unknown"
            ) || cause.r#type.as_ref().is_some_and(|s| !token(s, 128))
                || cause.code.as_ref().is_some_and(|s| !token(s, 64)))
        {
            return None;
        }
        Some(info)
    }
}

pub(crate) type LocalSource = Arc<dyn StdError + Send + Sync>;

pub(crate) struct TargetFailure {
    pub cause: TransportCause,
    pub source: Option<LocalSource>,
}

impl TargetFailure {
    pub fn from_error<E: Send + 'static>(error: E) -> Self {
        if !(&error as &dyn Any).is::<reqwest::Error>()
            && !(&error as &dyn Any).is::<std::io::Error>()
        {
            return Self {
                cause: TransportCause {
                    kind: "unknown".to_owned(),
                    r#type: None,
                    code: None,
                },
                source: None,
            };
        }
        let mut kind = "unknown";
        let boxed: Box<dyn Any + Send> = Box::new(error);
        let source: Option<LocalSource> = match boxed.downcast::<reqwest::Error>() {
            Ok(error) => {
                kind = if error.is_timeout() {
                    "timeout"
                } else if error.is_connect() {
                    "connection"
                } else if error.is_decode() {
                    "invalid_response"
                } else {
                    "unknown"
                };
                Some(Arc::new(*error))
            }
            Err(boxed) => match boxed.downcast::<std::io::Error>() {
                Ok(error) => {
                    kind = match error.kind() {
                        std::io::ErrorKind::TimedOut => "timeout",
                        std::io::ErrorKind::ConnectionRefused
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::NotConnected
                        | std::io::ErrorKind::BrokenPipe => "connection",
                        std::io::ErrorKind::InvalidData | std::io::ErrorKind::UnexpectedEof => {
                            "invalid_response"
                        }
                        _ => "unknown",
                    };
                    Some(Arc::new(*error))
                }
                Err(_) => None,
            },
        };
        Self {
            cause: TransportCause {
                kind: kind.to_owned(),
                r#type: None,
                code: None,
            },
            source,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn reqwest_target_error_is_private_but_explicitly_inspectable() {
        let raw = reqwest::Client::new()
            .get("https://target.example/private?private-token=secret")
            .header("invalid\nheader", "private-proxy-credential")
            .build()
            .unwrap_err();
        let failure = TargetFailure::from_error(raw);
        let error = crate::Error::from(
            crate::ProfileError::service(502, Value::Null, None).with_source(failure.source),
        );
        assert!(error.target_error().unwrap().is::<reqwest::Error>());
        let mut chain: Option<&(dyn StdError + 'static)> = Some(&error);
        while let Some(source) = chain {
            assert!(!format!("{source} {source:?}").contains("private-"));
            chain = source.source();
        }
    }

    #[test]
    fn malformed_metadata_is_ignored_and_future_codes_are_preserved() {
        for value in [
            json!({"code":"CLIENT_TRANSPORT_ERROR", "origin":"client", "message":"safe"}),
            json!({"code":"CLIENT_TRANSPORT_ERROR", "origin":"client", "message":null, "retryable":null}),
            json!({"code":"CLIENT_TRANSPORT_ERROR", "origin":"client", "message":"safe", "retryable":null, "cause":{"kind":"invented"}}),
            json!({"code":"CLIENT_TRANSPORT_ERROR", "origin":"client", "message":"safe", "retryable":null, "cause":{"kind":"unknown", "type":"https://secret@proxy"}}),
            json!({"code":"CLIENT_TRANSPORT_ERROR", "origin":"client", "message":"safe", "retryable":null, "command_id":0}),
            json!({"code":"CLIENT_TRANSPORT_ERROR", "origin":"client", "message":"safe", "retryable":null, "command_id":-1}),
            json!({"code":"CLIENT_TRANSPORT_ERROR", "origin":"client", "message":"safe", "retryable":null, "command_id":1.5}),
            json!({"code":"CLIENT_TRANSPORT_ERROR", "origin":"client", "message":"safe", "retryable":null, "command_id":true}),
        ] {
            assert!(ErrorInfo::parse(Some(value)).is_none());
        }
        let info = ErrorInfo::parse(Some(json!({"code":"FUTURE_ERROR", "origin":"upstream", "message":"private body", "retryable":null, "future_field":true}))).unwrap();
        assert_eq!(info.code, "FUTURE_ERROR");
        assert!(!format!("{info:?}").contains("private body"));
    }

    #[test]
    fn only_known_typed_errors_supply_transport_categories() {
        let unknown =
            TargetFailure::from_error("timeout DNS TLS proxy private-password".to_owned());
        assert_eq!(unknown.cause.kind, "unknown");
        assert!(unknown.source.is_none());
        let failed = TargetFailure::from_error(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "private proxy",
        ));
        assert_eq!(failed.cause.kind, "timeout");
        assert!(
            failed
                .source
                .unwrap()
                .downcast_ref::<std::io::Error>()
                .is_some()
        );
    }
}
