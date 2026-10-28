use std::{fmt, sync::Arc, time::Duration};

use reqwest::header::{AUTHORIZATION, HeaderValue, USER_AGENT};
use serde::Serialize;
use url::Url;
use uuid::Uuid;

use crate::protection::http_url;
use crate::{
    ApiError, Error, FindOptions, Page, Params, Protection, ProtocolError, Solution,
    find_protections, find_protections_with_options,
};

const BASE_URL: &str = "https://akamai.nullgate.club";
const ANALYTICS_URL: &str = "https://analytics.nullgate.club";

/// A cheaply cloned handle to one reusable Nullgate API pool.
///
/// Dropping the last client/session/solution releases the pool. No target traffic
/// or target cookie jar is owned by this handle.
#[derive(Clone)]
pub struct NullgateClient {
    inner: Arc<ClientInner>,
}

struct ClientInner {
    http: reqwest::Client,
    authorization: HeaderValue,
    base_url: Url,
    report_url: Url,
    report_timeout: Duration,
}

#[derive(Serialize)]
struct Report<'a> {
    request_id: &'a str,
}

/// Checked client construction; credentials never become transport-wide defaults.
pub struct ClientBuilder {
    api_key: String,
    base_url: String,
    analytics_url: String,
    timeout: Duration,
    report_timeout: Duration,
}

impl NullgateClient {
    /// Open the API pool with production service URLs and a 30-second timeout.
    pub fn new(api_key: impl Into<String>) -> Result<Self, Error> {
        Self::builder(api_key).build()
    }

    /// Customize endpoints/timeouts before constructing the pool.
    pub fn builder(api_key: impl Into<String>) -> ClientBuilder {
        ClientBuilder {
            api_key: api_key.into(),
            base_url: BASE_URL.to_owned(),
            analytics_url: ANALYTICS_URL.to_owned(),
            timeout: Duration::from_secs(30),
            report_timeout: Duration::from_secs(3),
        }
    }

    /// Open an independent generation state stream bound to one identity/profile.
    pub fn open(&self, options: SessionOptions) -> Result<Session, Error> {
        if options.user_agent.is_empty() {
            return Err(Error::Configuration("user agent must not be empty"));
        }
        let user_agent = HeaderValue::from_str(&options.user_agent)
            .map_err(|_| Error::Configuration("user agent must be a valid HTTP header"))?;
        Ok(Session {
            client: self.clone(),
            identity: options.identity,
            user_agent,
            timezone: options.timezone,
            state_id: None,
        })
    }

    /// Local synchronous discovery; multiple candidates return an ambiguity error.
    pub fn find_protections(&self, page: &Page) -> Result<Vec<Protection>, Error> {
        find_protections(page)
    }

    /// Local discovery with explicit ambiguity handling; no network requests occur.
    ///
    /// Use `FindOptions { panic: false }` to retain every candidate and select
    /// explicitly. This never causes a Rust panic.
    pub fn find_protections_with_options(
        &self,
        page: &Page,
        options: FindOptions,
    ) -> Result<Vec<Protection>, Error> {
        find_protections_with_options(page, options)
    }

    /// Deliver a customer report containing only its request ID.
    ///
    /// `true` means an HTTP 2xx response, not archive acceptance or a refund.
    /// Network failures/timeouts/status failures return `Ok(false)`. Dropping this
    /// future cancels it; request-construction errors remain errors.
    pub async fn report(&self, request_id: &str) -> Result<bool, Error> {
        let request = self
            .inner
            .http
            .post(self.inner.report_url.clone())
            .timeout(self.inner.report_timeout)
            .json(&Report { request_id })
            .build()?;
        match self.inner.http.execute(request).await {
            Ok(response) => Ok(response.status().is_success()),
            Err(error) if error.is_builder() => Err(error.into()),
            Err(_) => Ok(false),
        }
    }
}

impl ClientBuilder {
    /// API origin/base path. Absolute HTTP(S), without credentials/query/fragment.
    pub fn base_url(mut self, value: impl Into<String>) -> Self {
        self.base_url = value.into();
        self
    }

    /// Analytics origin/base path; `/report` is appended.
    pub fn analytics_url(mut self, value: impl Into<String>) -> Self {
        self.analytics_url = value.into();
        self
    }

    /// Finite total timeout for generation requests.
    pub fn timeout(mut self, value: Duration) -> Self {
        self.timeout = value;
        self
    }

    /// Finite report timeout; defaults to three seconds.
    pub fn report_timeout(mut self, value: Duration) -> Self {
        self.report_timeout = value;
        self
    }

    /// Validate configuration and construct a pooled transport without retries,
    /// automatic redirects, cookies, or default authentication headers.
    pub fn build(self) -> Result<NullgateClient, Error> {
        if !self.api_key.starts_with("ng_")
            || self.api_key.len() <= 3
            || !self
                .api_key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err(Error::Configuration("API key must be an ng_ credential"));
        }
        if self.timeout.is_zero() || self.report_timeout.is_zero() {
            return Err(Error::Configuration("timeouts must be greater than zero"));
        }
        let base_url = service_base(&self.base_url)?;
        let report_url = service_base(&self.analytics_url)?
            .join("report")
            .map_err(|_| Error::Configuration("invalid analytics endpoint"))?;
        let mut authorization = HeaderValue::from_str(&format!("Bearer {}", self.api_key))
            .map_err(|_| Error::Configuration("invalid API key header"))?;
        authorization.set_sensitive(true);
        let http = reqwest::Client::builder()
            .timeout(self.timeout)
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .build()?;
        Ok(NullgateClient {
            inner: Arc::new(ClientInner {
                http,
                authorization,
                base_url,
                report_url,
                report_timeout: self.report_timeout,
            }),
        })
    }
}

/// Required identity/profile configuration for one generation state stream.
pub struct SessionOptions {
    identity: Uuid,
    user_agent: String,
    timezone: Option<String>,
}

impl SessionOptions {
    /// Use an already checked UUID and the exact target transport user agent.
    pub fn new(identity: Uuid, user_agent: impl Into<String>) -> Self {
        Self {
            identity,
            user_agent: user_agent.into(),
            timezone: None,
        }
    }

    /// Set the caller's IANA timezone name; the service validates the name.
    pub fn timezone(mut self, value: impl Into<String>) -> Self {
        self.timezone = Some(value.into());
        self
    }
}

/// An isolated, sequential generation state stream.
///
/// `solve` takes `&mut self`; concurrent solves cannot accidentally share state.
/// Independent sessions share connection pools and can run in parallel.
///
/// ```compile_fail
/// use nullgate_sdk::{Params, Session};
/// async fn cannot_overlap(session: &mut Session, a: Params, b: Params) {
///     let first = session.solve(a);
///     let second = session.solve(b);
///     first.await.unwrap();
///     second.await.unwrap();
/// }
/// ```
pub struct Session {
    client: NullgateClient,
    identity: Uuid,
    user_agent: HeaderValue,
    timezone: Option<String>,
    state_id: Option<HeaderValue>,
}

impl Session {
    /// Identity to which this session is bound.
    pub fn identity(&self) -> Uuid {
        self.identity
    }

    /// Last usable service state header, retained across error responses.
    pub fn state_id(&self) -> Option<&str> {
        self.state_id.as_ref().and_then(|value| value.to_str().ok())
    }

    /// Generate one ready target POST, retaining header rotations even on errors.
    pub async fn solve(&mut self, params: Params) -> Result<Solution, Error> {
        let mut url = self
            .client
            .inner
            .base_url
            .join(&format!("v1/{}/generate", self.identity))
            .map_err(|_| Error::Configuration("invalid generation endpoint"))?;
        url.query_pairs_mut()
            .append_pair("type", params.operation());
        let mut request = self
            .client
            .inner
            .http
            .post(url)
            .header(AUTHORIZATION, self.client.inner.authorization.clone())
            .header(USER_AGENT, self.user_agent.clone())
            .json(&params.payload(self.timezone.as_deref()));
        if let Some(state_id) = &self.state_id {
            request = request.header("X-State-ID", state_id.clone());
        }
        let response = request.send().await?;
        // Apply rotations before status/body validation: errors can rotate state too.
        if let Some(value) = response.headers().get("X-State-ID") {
            self.state_id = Some(value.clone());
        }
        let request_id = response
            .headers()
            .get("X-Request-ID")
            .and_then(|value| value.to_str().ok())
            .filter(|value| !value.is_empty())
            .map(str::to_owned);
        let status = response.status();
        let body = response.bytes().await?;
        if !status.is_success() {
            let value = serde_json::from_slice::<serde_json::Value>(&body).unwrap_or_else(|_| {
                serde_json::Value::String(String::from_utf8_lossy(&body).into_owned())
            });
            let detail = match value {
                serde_json::Value::Object(mut object) => object
                    .remove("detail")
                    .unwrap_or(serde_json::Value::Object(object)),
                value => value,
            };
            return Err(Error::Api(ApiError::new(
                status.as_u16(),
                detail,
                request_id,
            )));
        }
        let request_id = request_id.ok_or_else(|| {
            Error::Protocol(ProtocolError::new(
                "missing or malformed X-Request-ID header",
                None,
            ))
        })?;
        Solution::from_response(self.client.clone(), &params, &body, request_id)
    }
}

impl fmt::Debug for NullgateClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NullgateClient").finish_non_exhaustive()
    }
}
impl fmt::Debug for ClientBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientBuilder").finish_non_exhaustive()
    }
}
impl fmt::Debug for SessionOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionOptions")
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}
impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

fn service_base(value: &str) -> Result<Url, Error> {
    let mut url = http_url(value)?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::Configuration(
            "service URL must not contain credentials, query, or fragment",
        ));
    }
    let path = format!("{}/", url.path().trim_end_matches('/'));
    url.set_path(&path);
    Ok(url)
}
