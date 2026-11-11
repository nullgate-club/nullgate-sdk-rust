use std::{fmt, sync::Arc, time::Duration};

use reqwest::header::{AUTHORIZATION, HeaderValue, USER_AGENT};
use serde::Serialize;
use url::Url;
use uuid::Uuid;

use crate::profile::{self, Connection, Profiles};
use crate::protection::http_url;
use crate::{
    ApiError, Error, FindOptions, Page, Params, Profile, Protection, ProtocolError, Solution,
    Target, ThreatMetrixParams, find_protections, find_protections_with_options,
};

const BASE_URL: &str = "https://akamai.nullgate.club";
const ANALYTICS_URL: &str = "https://analytics.nullgate.club";
const PROFILE_URL: &str = "https://threatmetrix.nullgate.club";
const AMAZON_URL: &str = "https://amazon.nullgate.club";

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
    profile_url: Url,
    amazon_url: Url,
    timeout: Duration,
    profile_tls: Arc<tokio_rustls::rustls::ClientConfig>,
    profiles: Profiles,
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
    profile_base_url: String,
    amazon_base_url: String,
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
            profile_base_url: PROFILE_URL.to_owned(),
            amazon_base_url: AMAZON_URL.to_owned(),
            timeout: Duration::from_secs(30),
            report_timeout: Duration::from_secs(3),
        }
    }

    /// Open an independent generation state stream bound to one identity/profile.
    pub fn open(&self, options: SessionOptions) -> Result<Session, Error> {
        if self.inner.profiles.cancel.is_cancelled() {
            return Err(profile::closed(None).into());
        }
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
            state_id: new_state_id(),
            amazon_state_id: new_state_id(),
            profiles: Profiles::default(),
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

    /// Close all owned active profiles without inventing page departure.
    /// The client cannot open new sessions or profiles afterward.
    pub async fn close(&self) -> Result<(), Error> {
        self.inner.profiles.close().await
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

    /// Profiling origin/base path; HTTP(S) becomes WS(S) for the profile socket.
    pub fn profile_base_url(mut self, value: impl Into<String>) -> Self {
        self.profile_base_url = value.into();
        self
    }

    /// Amazon origin/base path; independent of the existing generation endpoint.
    pub fn amazon_base_url(mut self, value: impl Into<String>) -> Self {
        self.amazon_base_url = value.into();
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
        let amazon_url = service_base(&self.amazon_base_url)?;
        let mut profile_url = service_base(&self.profile_base_url)?;
        let scheme = if profile_url.scheme() == "https" {
            "wss"
        } else {
            "ws"
        };
        profile_url
            .set_scheme(scheme)
            .map_err(|_| Error::Configuration("invalid profile endpoint"))?;
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
            .no_proxy()
            .build()?;
        Ok(NullgateClient {
            inner: Arc::new(ClientInner {
                http,
                authorization,
                base_url,
                report_url,
                profile_url,
                amazon_url,
                timeout: self.timeout,
                profile_tls: crate::turn_transport::tls_config()
                    .map_err(|_| Error::Configuration("invalid profile TLS configuration"))?,
                profiles: Profiles::default(),
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
    state_id: HeaderValue,
    amazon_state_id: HeaderValue,
    profiles: Profiles,
}

impl Session {
    /// Identity to which this session is bound.
    pub fn identity(&self) -> Uuid {
        self.identity
    }

    /// Current locally chosen or service-rotated state header, including after errors.
    pub fn state_id(&self) -> Option<&str> {
        self.state_id.to_str().ok()
    }

    /// Generate one ready target POST, retaining header rotations even on errors.
    pub async fn solve(&mut self, params: Params) -> Result<Solution, Error> {
        if self.profiles.cancel.is_cancelled() || self.client.inner.profiles.cancel.is_cancelled() {
            return Err(profile::closed(None).into());
        }
        let mut url = self
            .client
            .inner
            .base_url
            .join(&format!("v1/{}/generate", self.identity))
            .map_err(|_| Error::Configuration("invalid generation endpoint"))?;
        url.query_pairs_mut()
            .append_pair("type", params.operation());
        let (response, request_id) = generate(
            &self.client,
            &self.user_agent,
            &mut self.state_id,
            url,
            &params.payload(self.timezone.as_deref()),
        )
        .await?;
        let body = response.bytes().await?;
        Solution::from_response(self.client.clone(), &params, &body, request_id)
    }

    /// Amazon continuation, separate from Akamai/ThreatMetrix state.
    pub fn amazon_state_id(&self) -> Option<&str> {
        self.amazon_state_id.to_str().ok()
    }

    /// Generate metadata for the caller's form without sending a target request.
    /// Dropping this future cancels generation; received rotations survive errors.
    pub async fn fwcim(
        &mut self,
        params: &crate::FwcimParams,
    ) -> Result<crate::FwcimSolution, Error> {
        if self.profiles.cancel.is_cancelled() || self.client.inner.profiles.cancel.is_cancelled() {
            return Err(profile::closed(None).into());
        }
        let mut url = self
            .client
            .inner
            .amazon_url
            .join(&format!("v1/{}/generate", self.identity))
            .map_err(|_| Error::Configuration("invalid Amazon generation endpoint"))?;
        url.query_pairs_mut().append_pair("type", "fwcim");
        let (response, request_id) = generate(
            &self.client,
            &self.user_agent,
            &mut self.amazon_state_id,
            url,
            &params.payload(self.timezone.as_deref()),
        )
        .await?;
        let body = response.bytes().await?;
        crate::FwcimSolution::from_response(&body, request_id)
    }

    /// Begin profiling the original document on the caller's own target network.
    ///
    /// Returns after `ready`, not `collected`; the active handle continues to
    /// serve source requests until explicit departure or close. Dropping this
    /// future cancels startup and releases any resources already opened.
    pub async fn profile(
        &mut self,
        params: ThreatMetrixParams,
        target: Target,
    ) -> Result<Profile, Error> {
        if self.profiles.cancel.is_cancelled() || self.client.inner.profiles.cancel.is_cancelled() {
            return Err(profile::closed(None).into());
        }
        let url = self
            .client
            .inner
            .profile_url
            .join(&format!("v1/{}/profile", self.identity))
            .map_err(|_| Error::Configuration("invalid profile endpoint"))?;
        let connection = Connection {
            url,
            authorization: self.client.inner.authorization.clone(),
            user_agent: self.user_agent.clone(),
            state_id: self.state_id.clone(),
            timezone: self.timezone.clone(),
            limit: self.client.inner.timeout,
            cancel: self.client.inner.profiles.cancel.clone(),
            tls: self.client.inner.profile_tls.clone(),
        };
        let (profile, state_id, ready) = profile::begin(
            self.client.clone(),
            connection,
            params,
            target,
            self.profiles.cancel.clone(),
        )
        .await?;
        self.state_id = state_id;
        self.profiles.register(&profile);
        self.client.inner.profiles.register(&profile);
        profile.ready(ready, self.client.inner.timeout).await?;
        Ok(profile)
    }

    /// Cancel and await all this session's active profiles, without pagehide.
    pub async fn close(&self) -> Result<(), Error> {
        self.profiles.close().await
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

fn new_state_id() -> HeaderValue {
    HeaderValue::from_str(
        Uuid::new_v4()
            .hyphenated()
            .encode_lower(&mut Uuid::encode_buffer()),
    )
    .expect("UUID characters are valid in an HTTP header")
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

async fn generate(
    client: &NullgateClient,
    user_agent: &HeaderValue,
    state_id: &mut HeaderValue,
    url: Url,
    payload: &impl Serialize,
) -> Result<(reqwest::Response, String), Error> {
    let request = client
        .inner
        .http
        .post(url)
        .header(AUTHORIZATION, client.inner.authorization.clone())
        .header(USER_AGENT, user_agent.clone())
        .header("X-State-ID", state_id.clone())
        .header("X-Nullgate-Error-Format", "1")
        .json(payload)
        .build()?;
    let started = tokio::time::Instant::now();
    for attempt in 0..=2 {
        if client.inner.profiles.cancel.is_cancelled() {
            return Err(profile::closed(None).into());
        }
        let mut request = request
            .try_clone()
            .expect("JSON generation request is cloneable");
        *request.timeout_mut() = Some(client.inner.timeout.saturating_sub(started.elapsed()));
        let response = client.inner.http.execute(request).await?;
        let rotation = response.headers().get("X-State-ID").cloned();
        let request_id = response
            .headers()
            .get("X-Request-ID")
            .and_then(|value| value.to_str().ok())
            .filter(|value| !value.is_empty())
            .map(str::to_owned);
        let status = response.status();
        let retry_delay = maintenance_delay(status.as_u16(), response.headers());
        // Headers own continuation even when the response body cannot be read.
        if retry_delay.is_none()
            && let Some(value) = rotation
        {
            *state_id = value;
        }
        if status.is_success() {
            let request_id = request_id.ok_or_else(|| {
                Error::Protocol(ProtocolError::new(
                    "missing or malformed X-Request-ID header",
                    None,
                ))
            })?;
            return Ok((response, request_id));
        }
        if attempt < 2
            && let Some(delay) = retry_delay
            && delay < client.inner.timeout.saturating_sub(started.elapsed())
        {
            drop(response);
            tokio::select! {
                () = tokio::time::sleep(delay) => {}
                () = client.inner.profiles.cancel.cancelled() => {
                    return Err(profile::closed(request_id.as_deref()).into());
                }
            }
            continue;
        }
        let body = response.bytes().await?;
        let value = serde_json::from_slice::<serde_json::Value>(&body).unwrap_or_else(|_| {
            serde_json::Value::String(String::from_utf8_lossy(&body).into_owned())
        });
        let error_info = crate::ErrorInfo::parse(value.get("error").cloned());
        let detail = match value {
            serde_json::Value::Object(mut object) => object
                .remove("detail")
                .unwrap_or(serde_json::Value::Object(object)),
            value => value,
        };
        return Err(Error::Api(
            ApiError::new(status.as_u16(), detail, request_id).with_error_info(error_info),
        ));
    }
    unreachable!("the final attempt returns its response")
}

pub(crate) fn maintenance_delay(
    status: u16,
    headers: &reqwest::header::HeaderMap,
) -> Option<Duration> {
    if status != 503 {
        return None;
    }
    let mut markers = headers.get_all("X-Nullgate-Maintenance").iter();
    if markers.next()?.as_bytes() != b"1" || markers.next().is_some() {
        return None;
    }
    let mut delays = headers.get_all("Retry-After").iter();
    let delay = delays.next()?.to_str().ok()?;
    if delays.next().is_some() {
        return None;
    }
    delay
        .parse::<f64>()
        .ok()
        .filter(|value| value.is_finite() && (0.0..=5.0).contains(value))
        .map(Duration::from_secs_f64)
}
