use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt,
    sync::{Arc, Mutex as StdMutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{Engine, engine::general_purpose::STANDARD};
use futures_util::{SinkExt, StreamExt};
use reqwest::header::HeaderValue;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use tokio::{
    net::TcpStream,
    sync::{Mutex, mpsc, oneshot, watch},
    task::{JoinHandle, JoinSet},
    time::timeout,
};
use tokio_tungstenite::{
    Connector, MaybeTlsStream, WebSocketStream,
    tungstenite::{Error as WebSocketError, Message, client::IntoClientRequest},
};
use tokio_util::sync::CancellationToken;
use url::Url;
use uuid::Uuid;

use crate::{
    Credentials, Error, NullgateClient, ProfileError, ProfileErrorKind, Target, TargetRequest,
    ThreatMetrix,
    akamai::{PreparedInput, prepare_inputs},
    params::validate_actions,
    protection::ThreatMetrixSource,
    turn_transport::{self, IceServer},
};

type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;
type DepartureResult = oneshot::Sender<Result<(), ProfileError>>;
type Ready = oneshot::Receiver<Result<(), ProfileError>>;

/// Nominal profiling input; cannot accidentally be submitted to `solve`.
#[derive(Clone)]
pub struct ThreatMetrixParams {
    protection: ThreatMetrix,
    inputs: Option<Vec<PreparedInput>>,
    actions: Option<Vec<Map<String, Value>>>,
}

impl ThreatMetrixParams {
    /// Retain the selected tags entry or direct collector and its document observation.
    pub fn new(protection: ThreatMetrix) -> Self {
        Self {
            protection,
            inputs: None,
            actions: None,
        }
    }

    /// The actual protection being profiled.
    pub fn protection(&self) -> &ThreatMetrix {
        &self.protection
    }

    /// Hash caller-supplied input values locally using the existing SDK format.
    pub fn inputs(mut self, inputs: Vec<BTreeMap<String, String>>) -> Self {
        self.inputs = Some(prepare_inputs(&inputs));
        self
    }

    /// Retain real observations only; input/change values must be prepared summaries.
    pub fn actions(mut self, actions: Vec<Map<String, Value>>) -> Result<Self, Error> {
        validate_actions(&actions)?;
        self.actions = Some(actions);
        Ok(self)
    }
}

impl fmt::Debug for ThreatMetrixParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ThreatMetrixParams")
            .field("protection", &self.protection)
            .finish_non_exhaustive()
    }
}

/// One live profiled document, returned after startup, not collector completion.
///
/// Keep it alive through source interaction lifetimes. `pagehide` is explicit;
/// `close`, future cancellation and Drop never invent a departure. Use `close`
/// to await cleanup; Drop requests the same cleanup on its owning Tokio task.
pub struct Profile {
    client: NullgateClient,
    request_id: Arc<str>,
    control: Arc<ProfileControl>,
    departure: Mutex<()>,
}

impl Profile {
    /// Actual service diagnostic ID received in `hello`.
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    /// Whether all installed collector lifetimes have completed.
    /// This does not imply page departure or close the socket.
    pub fn collected(&self) -> bool {
        *self.control.collected.borrow()
    }

    /// Await collector completion while the background reader services requests.
    pub async fn wait_collected(&self) -> Result<(), Error> {
        let mut collected = self.control.collected.clone();
        let mut done = self.control.done.clone();
        loop {
            if *collected.borrow_and_update() {
                return Ok(());
            }
            if let Some(result) = done.borrow_and_update().clone() {
                return Err(result.err().unwrap_or_else(|| self.closed()).into());
            }
            tokio::select! {
                result = collected.changed() => if result.is_err()
                    && done.changed().await.is_err() { return Err(self.closed().into()); },
                result = done.changed() => if result.is_err() { return Err(self.closed().into()); },
            }
        }
    }

    /// Explicitly report departure. `None` samples the caller's wall clock now.
    ///
    /// `persisted=true` does not close the profile. Cancellation after sending a
    /// departure closes the profile because the wire acknowledgement has no ID.
    pub async fn pagehide(&self, at_ms: Option<u64>, persisted: bool) -> Result<(), Error> {
        let at_ms = match at_ms {
            Some(value) => value,
            None => wall_clock_ms()?,
        };
        let _serial = self.departure.lock().await;
        self.ensure_open()?;
        let (reply, receive) = oneshot::channel();
        self.control
            .commands
            .send(Departure {
                at_ms,
                persisted,
                reply,
            })
            .await
            .map_err(|_| self.closed())?;
        let mut guard = CancelDeparture {
            cancel: &self.control.cancel,
            completed: false,
        };
        let result = receive.await.unwrap_or_else(|_| Err(self.closed()));
        guard.completed = true;
        result.map_err(Into::into)
    }

    /// Cancel source work, release TURN resources and disconnect, without pagehide.
    /// Idempotent; background protocol/service failures remain inspectable.
    pub async fn close(&self) -> Result<(), Error> {
        self.control.close().await.map_err(Into::into)
    }

    /// Existing analytics report semantics; sends only this request ID.
    pub async fn report(&self) -> Result<bool, Error> {
        self.client.report(&self.request_id).await
    }

    pub(crate) fn control(&self) -> &Arc<ProfileControl> {
        &self.control
    }

    pub(crate) async fn ready(&self, ready: Ready, limit: Duration) -> Result<(), Error> {
        timeout(limit, ready)
            .await
            .map_err(|_| transport("profile startup timed out", Some(&self.request_id)))?
            .map_err(|_| {
                transport(
                    "profile reader stopped during startup",
                    Some(&self.request_id),
                )
            })?
            .map_err(Into::into)
    }

    fn closed(&self) -> ProfileError {
        closed(Some(&self.request_id))
    }

    fn ensure_open(&self) -> Result<(), Error> {
        if let Some(result) = self.control.done.borrow().clone() {
            return Err(result.err().unwrap_or_else(|| self.closed()).into());
        }
        if self.control.cancel.is_cancelled() {
            return Err(self.closed().into());
        }
        Ok(())
    }
}

impl fmt::Debug for Profile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Profile")
            .field("request_id", &self.request_id)
            .field("collected", &self.collected())
            .finish_non_exhaustive()
    }
}

impl Drop for Profile {
    fn drop(&mut self) {
        self.control.cancel.cancel();
    }
}

struct CancelDeparture<'a> {
    cancel: &'a CancellationToken,
    completed: bool,
}
impl Drop for CancelDeparture<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.cancel.cancel();
        }
    }
}

pub(crate) struct ProfileControl {
    cancel: CancellationToken,
    commands: mpsc::Sender<Departure>,
    done: watch::Receiver<Option<Result<(), ProfileError>>>,
    collected: watch::Receiver<bool>,
    task: StdMutex<Option<JoinHandle<()>>>,
}

impl ProfileControl {
    async fn close(&self) -> Result<(), ProfileError> {
        self.cancel.cancel();
        let mut done = self.done.clone();
        let result = loop {
            if let Some(result) = done.borrow_and_update().clone() {
                break result;
            }
            if done.changed().await.is_err() {
                break Err(transport("profile reader stopped", None));
            }
        };
        let task = self
            .task
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        if let Some(task) = task {
            task.await
                .map_err(|_| transport("profile reader stopped", None))?;
        }
        result
    }
}

/// Registries own worker handles until cleanup finishes, without retaining clients.
#[derive(Default)]
pub(crate) struct Profiles {
    pub cancel: CancellationToken,
    controls: StdMutex<Vec<Arc<ProfileControl>>>,
}

impl Profiles {
    pub(crate) fn register(&self, profile: &Profile) {
        let mut controls = self
            .controls
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        controls.retain(|control| control.done.borrow().is_none());
        controls.push(profile.control().clone());
        if self.cancel.is_cancelled() {
            profile.control.cancel.cancel();
        }
    }

    pub(crate) async fn close(&self) -> Result<(), Error> {
        self.cancel.cancel();
        let controls = self
            .controls
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone();
        for control in &controls {
            control.cancel.cancel();
        }
        let mut first = None;
        for control in controls {
            if let Err(error) = control.close().await {
                first.get_or_insert(error);
            }
        }
        first.map_or(Ok(()), |error| Err(error.into()))
    }
}

impl Drop for Profiles {
    fn drop(&mut self) {
        self.cancel.cancel();
        for control in self
            .controls
            .get_mut()
            .unwrap_or_else(|error| error.into_inner())
            .iter()
        {
            control.cancel.cancel();
        }
    }
}

pub(crate) struct Connection {
    pub url: Url,
    pub authorization: HeaderValue,
    pub user_agent: HeaderValue,
    pub state_id: HeaderValue,
    pub timezone: Option<String>,
    pub limit: Duration,
    pub tls: Arc<tokio_rustls::rustls::ClientConfig>,
    pub cancel: CancellationToken,
}

pub(crate) async fn begin(
    client: NullgateClient,
    connection: Connection,
    params: ThreatMetrixParams,
    target: Target,
    session_cancel: CancellationToken,
) -> Result<(Profile, HeaderValue, Ready), Error> {
    let mut request = connection
        .url
        .as_str()
        .into_client_request()
        .map_err(|_| Error::Configuration("invalid profile endpoint"))?;
    // connect_async opens its own TCP stream and does not adopt environment proxies.
    request
        .headers_mut()
        .insert("Authorization", connection.authorization);
    request
        .headers_mut()
        .insert("User-Agent", connection.user_agent);
    request
        .headers_mut()
        .insert("X-State-ID", connection.state_id);
    let observed_at_ms = wall_clock_ms()?;
    let opening = async {
        let (mut socket, _) = tokio_tungstenite::connect_async_tls_with_config(
            request,
            None,
            false,
            Some(Connector::Rustls(connection.tls)),
        )
        .await
        .map_err(handshake_error)?;
        let protection = params.protection();
        let page = protection.page();
        let mut start = json!({
            "type":"start",
            "at_ms":observed_at_ms,
            "website":{"url":page.url().as_str(), "html":page.html(), "document_id":page.document_id(), "started_at_ms":page.started_at_ms()},
            "timezone":connection.timezone,
        });
        match &protection.source {
            ThreatMetrixSource::Tags => {
                start["tags_url"] = json!(protection.script_url().as_str());
            }
            ThreatMetrixSource::Collector {
                url,
                org_id,
                session_id,
            } => {
                start["collector"] = json!({
                    "url":url,
                    "org_id":org_id,
                    "session_id":session_id,
                });
            }
        }
        if let Some(inputs) = &params.inputs {
            start["inputs"] = json!(inputs);
        }
        if let Some(actions) = &params.actions {
            start["actions"] = json!(actions);
        }
        send(&mut socket, start, connection.limit, None).await?;
        match read(&mut socket, connection.limit, None).await? {
            ServerMessage::Hello {
                state_id,
                request_id,
            } => {
                if Uuid::parse_str(&request_id).is_err() || state_id.is_empty() {
                    return Err(protocol("malformed profile hello", None));
                }
                let state = HeaderValue::from_str(&state_id)
                    .map_err(|_| protocol("malformed profile state ID", Some(&request_id)))?;
                Ok((socket, state, request_id))
            }
            ServerMessage::Failure {
                status,
                detail,
                request_id,
            } => Err(service_error(status, detail, request_id, None)?),
            _ => Err(protocol("expected profile hello", None)),
        }
    };
    let (socket, state_id, request_id) = tokio::select! {
        biased;
        _ = connection.cancel.cancelled() => return Err(closed(None).into()),
        _ = session_cancel.cancelled() => return Err(closed(None).into()),
        result = timeout(connection.limit, opening) => result.map_err(|_| transport("profile connection timed out", None))??,
    };
    let request_id: Arc<str> = request_id.into();
    let cancel = session_cancel.child_token();
    let (commands, commands_rx) = mpsc::channel(1);
    let (done_tx, done) = watch::channel(None);
    let (collected_tx, collected) = watch::channel(false);
    let (ready_tx, ready) = oneshot::channel();
    let control = Arc::new(ProfileControl {
        cancel: cancel.clone(),
        commands,
        done,
        collected,
        task: StdMutex::new(None),
    });
    let worker_id = request_id.clone();
    let task = tokio::spawn(async move {
        let result = run(
            socket,
            target,
            commands_rx,
            Worker {
                id: worker_id,
                cancel,
                client_cancel: connection.cancel,
                limit: connection.limit,
                ready: Some(ready_tx),
                collected: collected_tx,
            },
        )
        .await;
        done_tx.send_replace(Some(result));
    });
    *control
        .task
        .lock()
        .unwrap_or_else(|error| error.into_inner()) = Some(task);
    Ok((
        Profile {
            client,
            request_id,
            control,
            departure: Mutex::new(()),
        },
        state_id,
        ready,
    ))
}

struct Departure {
    at_ms: u64,
    persisted: bool,
    reply: DepartureResult,
}

struct Worker {
    id: Arc<str>,
    cancel: CancellationToken,
    client_cancel: CancellationToken,
    limit: Duration,
    ready: Option<oneshot::Sender<Result<(), ProfileError>>>,
    collected: watch::Sender<bool>,
}

#[derive(Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
enum ServerMessage {
    #[serde(rename = "hello")]
    Hello {
        state_id: String,
        request_id: String,
    },
    #[serde(rename = "http")]
    Http { id: i64, request: HttpRequest },
    #[serde(rename = "ice")]
    Ice { id: i64, server: IceServer },
    #[serde(rename = "ice.release")]
    IceRelease { id: i64 },
    #[serde(rename = "ready")]
    Ready { request_id: String },
    #[serde(rename = "collected")]
    Collected { request_id: String },
    #[serde(rename = "pagehide.done")]
    PagehideDone,
    #[serde(rename = "error")]
    Failure {
        status: u16,
        detail: Value,
        request_id: Option<String>,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpRequest {
    role: String,
    url: String,
    method: String,
    headers: BTreeMap<String, String>,
    body: Option<String>,
    credentials: Credentials,
}

impl HttpRequest {
    fn into_target(self, request_id: &str) -> Result<TargetRequest, ProfileError> {
        let malformed = || protocol("malformed target HTTP request", Some(request_id));
        let url = Url::parse(&self.url).map_err(|_| malformed())?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || self.role.is_empty()
            || reqwest::Method::from_bytes(self.method.as_bytes()).is_err()
        {
            return Err(malformed());
        }
        for (name, value) in &self.headers {
            if reqwest::header::HeaderName::from_bytes(name.as_bytes()).is_err()
                || HeaderValue::from_str(value).is_err()
                || matches!(
                    name.to_ascii_lowercase().as_str(),
                    "authorization" | "proxy-authorization" | "x-state-id"
                )
                || (self.credentials == Credentials::Omit && name.eq_ignore_ascii_case("cookie"))
            {
                return Err(malformed());
            }
        }
        let body = self
            .body
            .map(|body| STANDARD.decode(body).map_err(|_| malformed()))
            .transpose()?;
        Ok(TargetRequest {
            role: self.role,
            url: self.url,
            method: self.method,
            headers: self.headers,
            body,
            credentials: self.credentials,
        })
    }
}

async fn run(
    mut socket: Socket,
    target: Target,
    mut commands: mpsc::Receiver<Departure>,
    mut worker: Worker,
) -> Result<(), ProfileError> {
    let operations_cancel = CancellationToken::new();
    let mut operations: JoinSet<Result<(), ProfileError>> = JoinSet::new();
    let (replies, mut responses) = mpsc::unbounded_channel();
    let mut seen = HashSet::new();
    let mut releases = HashMap::new();
    let mut departure: Option<DepartureResult> = None;
    let work = async {
        loop {
            tokio::select! {
                biased;
                Some(message) = responses.recv() => send(&mut socket, message, worker.limit, Some(&worker.id)).await?,
                Some(result) = operations.join_next(), if !operations.is_empty() => {
                    result.map_err(|_| transport("target operation task stopped", Some(&worker.id)))?
                        .map_err(|error| error.with_request_id(&worker.id))?;
                }
                command = commands.recv() => {
                    let Some(command) = command else { return Ok(()); };
                    if worker.ready.is_some() || departure.is_some() {
                        return Err(protocol("overlapping or premature pagehide", Some(&worker.id)));
                    }
                    send(&mut socket, json!({"type":"pagehide", "at_ms":command.at_ms, "persisted":command.persisted}), worker.limit, Some(&worker.id)).await?;
                    departure = Some(command.reply);
                }
                message = socket.next() => {
                    let message = decode(message, Some(&worker.id))?;
                    let Some(message) = message else { continue; };
                    match message {
                        ServerMessage::Http { id, request } => {
                            check_id(&mut seen, id, &worker.id)?;
                            let request = request.into_target(&worker.id)?;
                            let fetch = target.fetch.clone();
                            let replies = replies.clone();
                            let cancel = operations_cancel.child_token();
                            let request_id = worker.id.clone();
                            operations.spawn(async move {
                                let result = tokio::select! { biased; _ = cancel.cancelled() => return Ok(()), result = fetch(request) => result };
                                let response = match result {
                                    Ok(response) => {
                                        let received_at_ms = wall_clock_ms().map_err(|_| protocol("invalid caller wall clock", Some(&request_id)))?;
                                        if !(100..=999).contains(&response.status) {
                                            return Err(protocol("invalid target HTTP status", Some(&request_id)));
                                        }
                                        for (name, value) in &response.headers {
                                            if reqwest::header::HeaderName::from_bytes(name.as_bytes()).is_err() || HeaderValue::from_str(value).is_err() {
                                                return Err(protocol("invalid target HTTP headers", Some(&request_id)));
                                            }
                                        }
                                        json!({"type":"http.result", "id":id, "response":{"status":response.status, "headers":response.headers, "body":STANDARD.encode(response.body), "received_at_ms":received_at_ms}})
                                    }
                                    Err(()) => json!({"type":"http.error", "id":id, "detail":"Target request failed"}),
                                };
                                let _ = replies.send(response);
                                Ok(())
                            });
                        }
                        ServerMessage::Ice { id, server } => {
                            check_id(&mut seen, id, &worker.id)?;
                            if !server.valid() { return Err(protocol("invalid TURN server request", Some(&worker.id))); }
                            let release = CancellationToken::new();
                            releases.insert(id, release.clone());
                            operations.spawn(turn_transport::gather(id, server, target.route.clone(), release, operations_cancel.child_token(), replies.clone(), worker.limit));
                        }
                        ServerMessage::IceRelease { id } => {
                            let release = releases.remove(&id).ok_or_else(|| protocol("unknown or duplicate ICE release", Some(&worker.id)))?;
                            release.cancel();
                        }
                        ServerMessage::Ready { request_id } => {
                            check_request_id(&request_id, &worker.id)?;
                            let ready = worker.ready.take().ok_or_else(|| protocol("duplicate ready message", Some(&worker.id)))?;
                            let _ = ready.send(Ok(()));
                        }
                        ServerMessage::Collected { request_id } => {
                            check_request_id(&request_id, &worker.id)?;
                            if worker.ready.is_some() || *worker.collected.borrow() { return Err(protocol("premature or duplicate collected message", Some(&worker.id))); }
                            worker.collected.send_replace(true);
                        }
                        ServerMessage::PagehideDone => {
                            let reply = departure.take().ok_or_else(|| protocol("unexpected pagehide acknowledgement", Some(&worker.id)))?;
                            let _ = reply.send(Ok(()));
                        }
                        ServerMessage::Failure { status, detail, request_id } => return Err(service_error(status, detail, request_id, Some(&worker.id))?),
                        ServerMessage::Hello { .. } => return Err(protocol("duplicate profile hello", Some(&worker.id))),
                    }
                }
            }
        }
    };
    let result = tokio::select! {
        biased;
        _ = worker.cancel.cancelled() => Ok(()),
        _ = worker.client_cancel.cancelled() => Ok(()),
        result = work => result,
    };
    operations_cancel.cancel();
    for release in releases.into_values() {
        release.cancel();
    }
    let mut cleanup_error = None;
    while let Some(result) = operations.join_next().await {
        let result = result
            .map_err(|_| transport("target operation task stopped", Some(&worker.id)))
            .and_then(|result| result.map_err(|error| error.with_request_id(&worker.id)));
        if let Err(error) = result {
            cleanup_error.get_or_insert(error);
        }
    }
    let close_result = timeout(Duration::from_secs(3), socket.close(None)).await;
    let result = result
        .and_then(|()| cleanup_error.map_or(Ok(()), Err))
        .and_then(|()| match close_result {
            Ok(Ok(()))
            | Ok(Err(WebSocketError::ConnectionClosed | WebSocketError::AlreadyClosed)) => Ok(()),
            _ => Err(transport("profile socket cleanup failed", Some(&worker.id))),
        });
    let pending_error = result
        .as_ref()
        .err()
        .cloned()
        .unwrap_or_else(|| closed(Some(&worker.id)));
    if let Some(ready) = worker.ready.take() {
        let _ = ready.send(Err(pending_error.clone()));
    }
    if let Some(reply) = departure {
        let _ = reply.send(Err(pending_error));
    }
    result
}

fn check_id(seen: &mut HashSet<i64>, id: i64, request_id: &str) -> Result<(), ProfileError> {
    if !seen.insert(id) {
        return Err(protocol("duplicate correlation ID", Some(request_id)));
    }
    Ok(())
}

fn check_request_id(value: &str, expected: &str) -> Result<(), ProfileError> {
    if value != expected {
        return Err(protocol("mismatched profile request ID", Some(expected)));
    }
    Ok(())
}

async fn read(
    socket: &mut Socket,
    limit: Duration,
    id: Option<&str>,
) -> Result<ServerMessage, ProfileError> {
    loop {
        let message = timeout(limit, socket.next())
            .await
            .map_err(|_| transport("profile read timed out", id))?;
        if let Some(message) = decode(message, id)? {
            return Ok(message);
        }
    }
}

fn decode(
    message: Option<Result<Message, WebSocketError>>,
    id: Option<&str>,
) -> Result<Option<ServerMessage>, ProfileError> {
    match message {
        Some(Ok(Message::Text(text))) => serde_json::from_str(&text)
            .map(Some)
            .map_err(|_| protocol("unknown or malformed profile message", id)),
        Some(Ok(Message::Ping(_) | Message::Pong(_))) => Ok(None),
        Some(Ok(Message::Close(_))) | None => Err(transport("profile connection closed", id)),
        Some(Ok(_)) => Err(protocol("profile message must be JSON text", id)),
        Some(Err(_)) => Err(transport("profile connection failed", id)),
    }
}

async fn send(
    socket: &mut Socket,
    value: Value,
    limit: Duration,
    id: Option<&str>,
) -> Result<(), ProfileError> {
    timeout(limit, socket.send(Message::text(value.to_string())))
        .await
        .map_err(|_| transport("profile write timed out", id))?
        .map_err(|_| transport("profile write failed", id))
}

fn handshake_error(error: WebSocketError) -> ProfileError {
    if let WebSocketError::Http(response) = error {
        let request_id = response
            .headers()
            .get("X-Request-ID")
            .and_then(|value| value.to_str().ok())
            .filter(|value| Uuid::parse_str(value).is_ok())
            .map(str::to_owned);
        let detail = response
            .body()
            .as_deref()
            .map(|body| {
                serde_json::from_slice(body)
                    .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(body).into_owned()))
            })
            .unwrap_or(Value::Null);
        ProfileError::service(response.status().as_u16(), detail, request_id)
    } else {
        transport("profile connection failed", None)
    }
}

fn service_error(
    status: u16,
    detail: Value,
    request_id: Option<String>,
    expected: Option<&str>,
) -> Result<ProfileError, ProfileError> {
    if !(400..=599).contains(&status)
        || request_id
            .as_ref()
            .is_some_and(|value| Uuid::parse_str(value).is_err())
    {
        return Err(protocol("malformed profile service error", expected));
    }
    if let (Some(actual), Some(expected)) = (request_id.as_deref(), expected) {
        check_request_id(actual, expected)?;
    }
    Ok(ProfileError::service(
        status,
        detail,
        request_id.or_else(|| expected.map(str::to_owned)),
    ))
}

pub(crate) fn wall_clock_ms() -> Result<u64, Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Configuration("system clock is before the Unix epoch"))?
        .as_millis()
        .try_into()
        .map_err(|_| Error::Configuration("timestamp exceeds u64 milliseconds"))
}

pub(crate) fn closed(id: Option<&str>) -> ProfileError {
    ProfileError::new(
        ProfileErrorKind::Closed,
        "profile, session or client is closed",
        id.map(str::to_owned),
    )
}

fn protocol(message: &'static str, id: Option<&str>) -> ProfileError {
    ProfileError::new(ProfileErrorKind::Protocol, message, id.map(str::to_owned))
}

fn transport(message: &'static str, id: Option<&str>) -> ProfileError {
    ProfileError::new(ProfileErrorKind::Transport, message, id.map(str::to_owned))
}
