use std::{
    collections::BTreeMap,
    fmt,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use url::Url;

use crate::protection::http_url;
use crate::{Error, NullgateClient, Params, ProtocolError};

/// A complete target POST. The SDK never sends it or owns target cookies.
#[derive(Clone)]
pub struct Solution {
    client: NullgateClient,
    url: Url,
    headers: BTreeMap<String, String>,
    body: String,
    send_at: f64,
    request_id: String,
}

#[derive(Deserialize)]
struct Generated {
    send_at: f64,
    headers: BTreeMap<String, String>,
    sensor_data: Option<String>,
    url: Option<String>,
    body: Option<String>,
}

#[derive(Serialize)]
struct SensorBody {
    sensor_data: String,
}

impl Solution {
    pub(crate) fn from_response(
        client: NullgateClient,
        params: &Params,
        bytes: &[u8],
        request_id: String,
    ) -> Result<Self, Error> {
        let protocol =
            |message| Error::Protocol(ProtocolError::new(message, Some(request_id.clone())));
        let generated: Generated = serde_json::from_slice(bytes)
            .map_err(|_| protocol("malformed generation JSON or required fields"))?;
        let duration = Duration::try_from_secs_f64(generated.send_at.max(0.0))
            .map_err(|_| protocol("send_at must be a finite representable Unix timestamp"))?;
        if !generated.send_at.is_finite() || UNIX_EPOCH.checked_add(duration).is_none() {
            return Err(protocol(
                "send_at must be a finite representable Unix timestamp",
            ));
        }
        let (url, body, content_type) = match params {
            Params::Sensor(_) => {
                let sensor = generated
                    .sensor_data
                    .ok_or_else(|| protocol("missing sensor_data string"))?;
                let body = serde_json::to_string(&SensorBody {
                    sensor_data: sensor,
                })
                .map_err(|_| protocol("sensor_data could not be serialized"))?;
                (
                    params.script_url().clone(),
                    body,
                    "text/plain;charset=UTF-8",
                )
            }
            Params::Pixel(_) | Params::Sbsd(_) => {
                let url = generated
                    .url
                    .ok_or_else(|| protocol("missing target URL string"))?;
                let url =
                    http_url(&url).map_err(|_| protocol("target URL must be absolute HTTP(S)"))?;
                let body = generated
                    .body
                    .ok_or_else(|| protocol("missing target body string"))?;
                let content_type = if matches!(params, Params::Pixel(_)) {
                    "application/x-www-form-urlencoded"
                } else {
                    "application/json"
                };
                (url, body, content_type)
            }
        };
        let mut headers = generated.headers;
        headers.retain(|name, _| !name.eq_ignore_ascii_case("content-type"));
        headers.insert("Content-Type".to_owned(), content_type.to_owned());
        for (name, value) in &headers {
            reqwest::header::HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| protocol("invalid target header name"))?;
            reqwest::header::HeaderValue::from_str(value)
                .map_err(|_| protocol("invalid target header value"))?;
        }
        Ok(Self {
            client,
            url,
            headers,
            body,
            send_at: generated.send_at,
            request_id,
        })
    }

    /// The target method is always POST.
    pub fn method(&self) -> &'static str {
        "POST"
    }

    /// Absolute target URL. Sensor uses the protection's script URL.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Target headers, including the operation's canonical Content-Type.
    pub fn headers(&self) -> &BTreeMap<String, String> {
        &self.headers
    }

    /// Exact UTF-8 target body. Send as bytes/text, never JSON-encode again.
    pub fn body(&self) -> &str {
        &self.body
    }

    /// Earliest target POST time, as absolute Unix seconds.
    pub fn send_at(&self) -> f64 {
        self.send_at
    }

    /// The actual diagnostic `X-Request-ID` from the generation response.
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    /// Wait until the absolute send deadline; an elapsed deadline returns immediately.
    /// Dropping the future cancels the wait.
    pub async fn wait(&self) -> Result<(), Error> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Configuration("system clock is before the Unix epoch"))?
            .as_secs_f64();
        let delay = self.send_at - now;
        if delay > 0.0 {
            let duration = Duration::try_from_secs_f64(delay).map_err(|_| {
                Error::Protocol(ProtocolError::new(
                    "send_at delay is not representable",
                    Some(self.request_id.clone()),
                ))
            })?;
            let deadline = tokio::time::Instant::now()
                .checked_add(duration)
                .ok_or_else(|| {
                    Error::Protocol(ProtocolError::new(
                        "send_at delay is not representable",
                        Some(self.request_id.clone()),
                    ))
                })?;
            tokio::time::sleep_until(deadline).await;
        }
        Ok(())
    }

    /// Report a target rejection through the originating client's analytics endpoint.
    /// A delivered report does not prove a generator defect or grant a refund.
    pub async fn report(&self) -> Result<bool, Error> {
        self.client.report(&self.request_id).await
    }
}

impl fmt::Debug for Solution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Solution")
            .field("method", &self.method())
            .field("send_at", &self.send_at)
            .field("request_id", &self.request_id)
            .finish_non_exhaustive()
    }
}
