use std::{error::Error as StdError, fmt};

use serde_json::Value;

/// A checked configuration, discovery, transport, service, or protocol failure.
pub enum Error {
    /// Invalid caller configuration or an invalid checked value.
    Configuration(&'static str),
    /// Local discovery found more than one candidate.
    AmbiguousProtections {
        /// Number of candidates retained by discovery.
        count: usize,
    },
    /// The Nullgate service returned a non-success HTTP status.
    Api(ApiError),
    /// A successful HTTP response did not satisfy the generation contract.
    Protocol(ProtocolError),
    /// The API request failed before a usable response was received.
    Transport(reqwest::Error),
}

/// Original service status, diagnostic request ID, and inspectable server detail.
///
/// Detail is deliberately absent from `Debug` and `Display`: a remote service may
/// echo caller data. Read it explicitly when deciding how to present an error.
pub struct ApiError {
    status: u16,
    detail: Value,
    request_id: Option<String>,
}

impl ApiError {
    pub(crate) fn new(status: u16, detail: Value, request_id: Option<String>) -> Self {
        Self {
            status,
            detail,
            request_id,
        }
    }

    /// Original HTTP status code.
    pub fn status(&self) -> u16 {
        self.status
    }

    /// Server `detail`, the JSON body when no detail exists, or the text body.
    pub fn detail(&self) -> &Value {
        &self.detail
    }

    /// The actual `X-Request-ID` response header, if supplied.
    pub fn request_id(&self) -> Option<&str> {
        self.request_id.as_deref()
    }
}

/// A missing or malformed successful response, without raw response contents.
#[derive(Debug)]
pub struct ProtocolError {
    message: &'static str,
    request_id: Option<String>,
}

impl ProtocolError {
    pub(crate) fn new(message: &'static str, request_id: Option<String>) -> Self {
        Self {
            message,
            request_id,
        }
    }

    /// The failed protocol requirement.
    pub fn message(&self) -> &'static str {
        self.message
    }

    /// The actual `X-Request-ID` response header, when usable.
    pub fn request_id(&self) -> Option<&str> {
        self.request_id.as_deref()
    }
}

impl fmt::Debug for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiError")
            .field("status", &self.status)
            .field("request_id", &self.request_id)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Nullgate HTTP {}", self.status)?;
        if let Some(id) = &self.request_id {
            write!(f, " (request_id={id})")?;
        }
        Ok(())
    }
}

impl StdError for ApiError {}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Nullgate protocol error: {}", self.message)?;
        if let Some(id) = &self.request_id {
            write!(f, " (request_id={id})")?;
        }
        Ok(())
    }
}

impl StdError for ProtocolError {}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration(message) => f.debug_tuple("Configuration").field(message).finish(),
            Self::AmbiguousProtections { count } => f
                .debug_struct("AmbiguousProtections")
                .field("count", count)
                .finish(),
            Self::Api(error) => fmt::Debug::fmt(error, f),
            Self::Protocol(error) => fmt::Debug::fmt(error, f),
            Self::Transport(_) => f.write_str("Transport(Nullgate request failed)"),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration(message) => write!(f, "Invalid Nullgate configuration: {message}"),
            Self::AmbiguousProtections { count } => write!(
                f,
                "Found {count} protection candidates; use FindOptions {{ panic: false }} to select explicitly"
            ),
            Self::Api(error) => fmt::Display::fmt(error, f),
            Self::Protocol(error) => fmt::Display::fmt(error, f),
            Self::Transport(_) => f.write_str("Nullgate API transport failed"),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Api(error) => Some(error),
            Self::Protocol(error) => Some(error),
            Self::Transport(error) => Some(error),
            Self::Configuration(_) | Self::AmbiguousProtections { .. } => None,
        }
    }
}

impl From<reqwest::Error> for Error {
    fn from(error: reqwest::Error) -> Self {
        Self::Transport(error.without_url())
    }
}
