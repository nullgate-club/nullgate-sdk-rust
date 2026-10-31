use std::{collections::BTreeMap, fmt, future::Future, sync::Arc};

use futures_util::future::BoxFuture;
use serde::Deserialize;

use crate::{Error, turn_transport::Route};

/// The caller's cookie policy for one target request.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Credentials {
    /// Use and update the caller's existing target cookie jar.
    Include,
    /// Neither send nor retain cookies; use a fresh per-request provider jar.
    Omit,
}

/// One target request, executed only by the caller's transport.
///
/// `body` is raw bytes. `None` and `Some(Vec::new())` remain distinct.
#[derive(Clone)]
pub struct TargetRequest {
    /// Source-owned request role, such as `tags`.
    pub role: String,
    /// Actual absolute target URL.
    pub url: String,
    /// Actual HTTP method.
    pub method: String,
    /// Source-owned headers; never includes the Nullgate API credential.
    pub headers: BTreeMap<String, String>,
    /// Unmodified request bytes, or an absent body.
    pub body: Option<Vec<u8>>,
    /// Per-request cookie policy that the callback must honor.
    pub credentials: Credentials,
}

/// Actual completed target HTTP facts, including non-success statuses.
#[derive(Clone)]
pub struct TargetResponse {
    /// Actual status; do not call the provider's `error_for_status` helper.
    pub status: u16,
    /// Actual response headers.
    pub headers: BTreeMap<String, String>,
    /// Actual response bytes, without UTF-8 decoding.
    pub body: Vec<u8>,
}

type Fetch = dyn Fn(TargetRequest) -> BoxFuture<'static, Result<TargetResponse, ()>> + Send + Sync;

/// Reusable caller-owned HTTP callback and explicit local TURN route.
///
/// The callback must use the same User-Agent, cookie jar and route as the page
/// request. For `Credentials::Omit`, override the request's cookie provider with
/// a fresh provider jar; never clear or replace the caller's shared jar. Dropping
/// the callback future must cancel its request. Callback errors are deliberately
/// discarded rather than exposing proxy credentials or request contents.
#[derive(Clone)]
pub struct Target {
    pub(crate) fetch: Arc<Fetch>,
    pub(crate) route: Route,
}

impl Target {
    /// Validate the explicit route before any paid profile is opened.
    ///
    /// `None` or `Some("")` explicitly selects direct TCP. HTTP CONNECT, HTTPS
    /// CONNECT and SOCKS5 (`socks5`) proxy URLs are supported. The proxy
    /// remains local and is never sent to Nullgate or included in error messages.
    /// TURN resolves one endpoint locally; `socks5h` is rejected rather than misrepresented.
    pub fn new<F, Fut, E>(fetch: F, proxy: Option<&str>) -> Result<Self, Error>
    where
        F: Fn(TargetRequest) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<TargetResponse, E>> + Send + 'static,
        E: Send + 'static,
    {
        let route = Route::parse(proxy)?;
        Ok(Self {
            fetch: Arc::new(move |request| {
                let future = fetch(request);
                Box::pin(async move { future.await.map_err(|_| ()) })
            }),
            route,
        })
    }
}

impl fmt::Debug for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Target").finish_non_exhaustive()
    }
}

impl fmt::Debug for TargetRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TargetRequest")
            .field("credentials", &self.credentials)
            .field("body_bytes", &self.body.as_ref().map(Vec::len))
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for TargetResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TargetResponse")
            .field("status", &self.status)
            .field("body_bytes", &self.body.len())
            .finish_non_exhaustive()
    }
}
