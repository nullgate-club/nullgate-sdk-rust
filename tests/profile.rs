use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{Engine, engine::general_purpose::STANDARD};
use futures_util::{SinkExt, StreamExt};
use nullgate_sdk::{
    Credentials, Error, NullgateClient, Page, ProfileErrorKind, SessionOptions, Target,
    TargetRequest, TargetResponse, ThreatMetrix, ThreatMetrixParams,
};
use serde_json::{Value, json};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Barrier, Notify},
    time::timeout,
};
use tokio_tungstenite::{WebSocketStream, accept_async, tungstenite::Message};
use uuid::Uuid;

type Socket = WebSocketStream<TcpStream>;
const REQUEST_ID: &str = "11111111-2222-4333-8444-555555555555";

async fn receive(socket: &mut Socket) -> Value {
    loop {
        let message = timeout(Duration::from_secs(3), socket.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        match message {
            Message::Text(text) => return serde_json::from_str(&text).unwrap(),
            Message::Ping(_) | Message::Pong(_) => {}
            other => panic!("unexpected message: {other:?}"),
        }
    }
}

async fn send(socket: &mut Socket, value: Value) {
    socket.send(Message::text(value.to_string())).await.unwrap();
}

async fn hello(socket: &mut Socket) {
    let start = receive(socket).await;
    assert_eq!(
        start["tags_url"],
        "https://signals.example/fp/tags.js?org_id=org&session_id=session"
    );
    assert!(start.get("collector").is_none());
    send(
        socket,
        json!({"type":"hello", "state_id":"continued-tmx-state", "request_id":REQUEST_ID}),
    )
    .await;
}

async fn expect_close_without_departure(socket: &mut Socket) {
    loop {
        let response = timeout(Duration::from_secs(3), socket.next())
            .await
            .unwrap();
        match response {
            Some(Ok(Message::Text(text))) => {
                let value: Value = serde_json::from_str(&text).unwrap();
                assert_eq!(value["type"], "close");
            }
            Some(Ok(Message::Close(_))) => {
                socket.flush().await.unwrap();
                return;
            }
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
            None => return,
            other => panic!("unexpected shutdown message: {other:?}"),
        }
    }
}

fn client(base: &str) -> NullgateClient {
    NullgateClient::builder("ng_synthetic_test_key_not_a_real_credential")
        .profile_base_url(base)
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap()
}

fn session(client: &NullgateClient) -> nullgate_sdk::Session {
    client
        .open(SessionOptions::new(Uuid::new_v4(), "target user agent"))
        .unwrap()
}

fn params() -> ThreatMetrixParams {
    let page = Page::new("https://target.example/login", "<html></html>").unwrap();
    ThreatMetrixParams::new(
        ThreatMetrix::new(
            page,
            "https://signals.example/fp/tags.js?org_id=org&session_id=session",
        )
        .unwrap(),
    )
}

#[tokio::test]
async fn direct_collector_preserves_explicit_facts_and_parent_document() {
    const URL: &str = "HTTPS://Signals.Example:443/opaque%2Fcollector?org_id=url-org&session_id=url-session&wenkse=caller%2Fgenerated+value&x=1&x=2";
    let page = Page::new(
        "https://target.example/login",
        "<input type='hidden' name='tmxSessionId' value='site-session/one'>",
    )
    .unwrap();
    let website = json!({
        "url":page.url().as_str(),
        "html":page.html(),
        "document_id":page.document_id(),
        "started_at_ms":page.started_at_ms(),
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let service = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = accept_async(stream).await.unwrap();
        let start = receive(&mut socket).await;
        assert_eq!(start["website"], website);
        assert!(start.get("tags_url").is_none());
        assert_eq!(
            start["collector"],
            json!({
                "url":URL,
                "org_id":"explicit-org",
                "session_id":"site-session/one",
            })
        );
        send(
            &mut socket,
            json!({"type":"hello", "state_id":"continued-tmx-state", "request_id":REQUEST_ID}),
        )
        .await;
        send(
            &mut socket,
            json!({"type":"ready", "request_id":REQUEST_ID}),
        )
        .await;
        send(
            &mut socket,
            json!({"type":"collected", "request_id":REQUEST_ID}),
        )
        .await;
        expect_close_without_departure(&mut socket).await;
    });
    let sdk = client(&base);
    let mut session = session(&sdk);
    let target = Target::new(|_| async { Err::<TargetResponse, _>(()) }, None).unwrap();
    let collector = ThreatMetrix::collector(page, URL, "explicit-org", "site-session/one").unwrap();
    assert!(collector.tags_url().is_none());
    let profile = session
        .profile(ThreatMetrixParams::new(collector), target)
        .await
        .unwrap();
    profile.wait_collected().await.unwrap();
    profile.close().await.unwrap();
    session.close().await.unwrap();
    sdk.close().await.unwrap();
    service.await.unwrap();
}

#[test]
fn direct_collector_rejects_invalid_facts_before_profile_transport() {
    let page = Page::new("https://target.example/login", "").unwrap();
    for url in [
        "",
        "/relative",
        "https:signals.example/collector",
        "https:///signals.example/collector",
        "ftp://signals.example/collector",
        "https://",
        "https://signals.example:/collector",
        "https://signals.example:bad/collector",
        "https://signals.example:65536/collector",
        "https://@signals.example/collector",
        "https://private-user:private-password@signals.example/collector",
        "https://signals.example/collector#",
        "https://signals.example/collector#fragment",
        " https://signals.example/collector",
        "https://signals.example/collector ",
        "https://signals.example/collect\nor",
        "https://signals.example/collect\tor",
        "https://signals.example\\collector",
    ] {
        let error = ThreatMetrix::collector(page.clone(), url, "org", "session").unwrap_err();
        assert!(matches!(error, Error::Configuration(_)), "{url:?}");
        assert!(!format!("{error:?} {error}").contains("private-password"));
    }
    for (org_id, session_id) in [
        ("", "session"),
        ("org", ""),
        (" \t", "session"),
        ("org", "\u{2003}"),
        ("private-org\rvalue", "session"),
        ("org", "private-session\nvalue"),
    ] {
        let error = ThreatMetrix::collector(
            page.clone(),
            "https://signals.example/collector",
            org_id,
            session_id,
        )
        .unwrap_err();
        assert!(matches!(error, Error::Configuration(_)));
        assert!(!format!("{error:?} {error}").contains("private-"));
    }
}

fn http(id: i64, role: &str, body: Value, credentials: &str) -> Value {
    json!({"type":"http", "id":id, "request":{
        "role":role, "url":"https://target.example/resource", "method":"POST",
        "headers":{}, "body":body, "credentials":credentials,
    }})
}

#[tokio::test]
async fn concurrent_http_preserves_bytes_and_departure_does_not_stop_reader() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let barrier = Arc::new(Barrier::new(3));
    let collected = Arc::new(Notify::new());
    let service_barrier = barrier.clone();
    let service_collected = collected.clone();
    let earliest = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let service = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = accept_async(stream).await.unwrap();
        hello(&mut socket).await;
        send(&mut socket, http(1, "empty", json!(""), "include")).await;
        send(&mut socket, http(2, "absent", Value::Null, "omit")).await;
        timeout(Duration::from_secs(3), service_barrier.wait())
            .await
            .unwrap();
        let mut results = vec![receive(&mut socket).await, receive(&mut socket).await];
        results.sort_by_key(|value| value["id"].as_i64().unwrap());
        assert_eq!(results[0]["response"]["status"], 418);
        assert_eq!(
            STANDARD
                .decode(results[0]["response"]["body"].as_str().unwrap())
                .unwrap(),
            [255, 0, 195]
        );
        assert_eq!(results[1]["response"]["status"], 503);
        assert_eq!(results[1]["response"]["body"], "");
        let latest = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        for result in results {
            assert!(
                (earliest..=latest)
                    .contains(&result["response"]["received_at_ms"].as_u64().unwrap())
            );
        }
        send(
            &mut socket,
            json!({"type":"ready", "request_id":REQUEST_ID}),
        )
        .await;
        service_collected.notified().await;
        send(
            &mut socket,
            json!({"type":"collected", "request_id":REQUEST_ID}),
        )
        .await;
        let departure = receive(&mut socket).await;
        assert_eq!(
            departure,
            json!({"type":"pagehide", "at_ms":1700, "persisted":true})
        );
        send(
            &mut socket,
            http(3, "departure", json!(STANDARD.encode([0, 255])), "omit"),
        )
        .await;
        assert_eq!(receive(&mut socket).await["response"]["status"], 204);
        send(&mut socket, json!({"type":"pagehide.done"})).await;
        expect_close_without_departure(&mut socket).await;
    });
    let target = Target::new(
        move |request: TargetRequest| {
            let barrier = barrier.clone();
            async move {
                let (status, body) = match request.role.as_str() {
                    "empty" => {
                        assert_eq!(request.body, Some(Vec::new()));
                        assert_eq!(request.credentials, Credentials::Include);
                        barrier.wait().await;
                        (418, vec![255, 0, 195])
                    }
                    "absent" => {
                        assert_eq!(request.body, None);
                        assert_eq!(request.credentials, Credentials::Omit);
                        barrier.wait().await;
                        (503, Vec::new())
                    }
                    "departure" => {
                        assert_eq!(request.body, Some(vec![0, 255]));
                        assert_eq!(request.credentials, Credentials::Omit);
                        (204, Vec::new())
                    }
                    _ => panic!("unexpected HTTP role"),
                };
                Ok::<_, ()>(TargetResponse {
                    status,
                    headers: BTreeMap::new(),
                    body,
                })
            }
        },
        None,
    )
    .unwrap();
    let sdk = client(&base);
    let mut session = session(&sdk);
    let profile = session.profile(params(), target).await.unwrap();
    assert!(!profile.collected());
    collected.notify_one();
    timeout(Duration::from_secs(3), profile.wait_collected())
        .await
        .unwrap()
        .unwrap();
    assert!(profile.collected());
    profile.pagehide(Some(1700), true).await.unwrap();
    profile.close().await.unwrap();
    session.close().await.unwrap();
    sdk.close().await.unwrap();
    service.await.unwrap();
}

#[tokio::test]
async fn service_failure_after_ready_keeps_status_request_id_and_continuation() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let fail = Arc::new(Notify::new());
    let service_fail = fail.clone();
    let service = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = accept_async(stream).await.unwrap();
        hello(&mut socket).await;
        send(
            &mut socket,
            json!({"type":"ready", "request_id":REQUEST_ID}),
        )
        .await;
        service_fail.notified().await;
        send(&mut socket, json!({"type":"error", "status":402, "detail":"private detail", "request_id":REQUEST_ID})).await;
        socket.close(None).await.unwrap();
    });
    let target = Target::new(|_| async { Err::<TargetResponse, _>(()) }, None).unwrap();
    let sdk = client(&base);
    let mut session = session(&sdk);
    let profile = session.profile(params(), target).await.unwrap();
    assert_eq!(session.state_id(), Some("continued-tmx-state"));
    fail.notify_one();
    let error = timeout(Duration::from_secs(3), profile.wait_collected())
        .await
        .unwrap()
        .unwrap_err();
    let Error::Profile(error) = error else {
        panic!("expected typed profiling failure");
    };
    assert_eq!(error.kind(), ProfileErrorKind::Service);
    assert_eq!(error.status(), Some(402));
    assert_eq!(error.request_id(), Some(REQUEST_ID));
    assert!(!format!("{error:?} {error}").contains("private detail"));
    assert!(profile.close().await.is_err());
    assert!(sdk.close().await.is_err());
    service.await.unwrap();
}

struct Dropped(Arc<AtomicBool>);
impl Drop for Dropped {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn cancelling_startup_drops_inflight_http_and_does_not_invent_pagehide() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let service = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut socket = accept_async(stream).await.unwrap();
        hello(&mut socket).await;
        send(&mut socket, http(1, "blocked", Value::Null, "include")).await;
        expect_close_without_departure(&mut socket).await;
    });
    let entered = Arc::new(Notify::new());
    let dropped = Arc::new(AtomicBool::new(false));
    let request_entered = entered.clone();
    let request_dropped = dropped.clone();
    let target = Target::new(
        move |_| {
            let entered = request_entered.clone();
            let dropped = request_dropped.clone();
            async move {
                let _guard = Dropped(dropped);
                entered.notify_one();
                std::future::pending::<Result<TargetResponse, ()>>().await
            }
        },
        None,
    )
    .unwrap();
    let sdk = client(&base);
    let mut session = session(&sdk);
    let opening = tokio::spawn(async move { session.profile(params(), target).await });
    timeout(Duration::from_secs(3), entered.notified())
        .await
        .unwrap();
    opening.abort();
    assert!(opening.await.unwrap_err().is_cancelled());
    sdk.close().await.unwrap();
    assert!(dropped.load(Ordering::SeqCst));
    service.await.unwrap();
}

#[tokio::test]
async fn duplicate_and_malformed_correlations_are_protocol_failures() {
    for malformed in [
        http(1, "duplicate", Value::Null, "include"),
        json!({"type":"http", "id":true, "request":{}}),
        json!({"type":"unknown"}),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let service = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = accept_async(stream).await.unwrap();
            hello(&mut socket).await;
            send(&mut socket, http(1, "first", Value::Null, "include")).await;
            assert_eq!(receive(&mut socket).await["type"], "http.result");
            send(&mut socket, malformed).await;
            socket.close(None).await.unwrap();
        });
        let target = Target::new(
            |_| async {
                Ok::<_, ()>(TargetResponse {
                    status: 200,
                    headers: BTreeMap::new(),
                    body: Vec::new(),
                })
            },
            None,
        )
        .unwrap();
        let sdk = client(&base);
        let mut session = session(&sdk);
        let error = session.profile(params(), target).await.unwrap_err();
        let Error::Profile(error) = error else {
            panic!("expected typed protocol failure");
        };
        assert_eq!(error.kind(), ProfileErrorKind::Protocol);
        assert_eq!(error.request_id(), Some(REQUEST_ID));
        assert!(sdk.close().await.is_err());
        service.await.unwrap();
    }
}

#[tokio::test]
async fn profiling_observations_hash_raw_values_and_keep_absent_distinct_from_clear() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let service = tokio::spawn(async move {
        for case in 0..3 {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = accept_async(stream).await.unwrap();
            let start = receive(&mut socket).await;
            match case {
                0 => {
                    assert!(start.get("inputs").is_none());
                    assert!(start.get("actions").is_none());
                }
                1 => {
                    assert!(!start.to_string().contains("A_9"));
                    assert_eq!(
                        start["inputs"][0]["value"]["hash"],
                        "552f5768ce4326ff5fd4e0ce8d1d3a8e76c17a04542eb14f91f64e5a09550510"
                    );
                    assert_eq!(start["inputs"][0]["value"]["length"], 8);
                    assert_eq!(start["inputs"][0]["value"]["hash31"], -902_761_640_i32);
                }
                2 => {
                    assert_eq!(start["inputs"], json!([]));
                    assert_eq!(start["actions"], json!([]));
                }
                _ => unreachable!(),
            }
            send(
                &mut socket,
                json!({"type":"hello", "state_id":"continued-tmx-state", "request_id":REQUEST_ID}),
            )
            .await;
            send(
                &mut socket,
                json!({"type":"ready", "request_id":REQUEST_ID}),
            )
            .await;
            expect_close_without_departure(&mut socket).await;
        }
    });
    let field = BTreeMap::from([
        ("type".to_owned(), "password".to_owned()),
        ("value".to_owned(), "A_9 😀İ\u{a0}".to_owned()),
    ]);
    let input = json!({"type":"input","value":{
        "length":8, "hash":"552f5768ce4326ff5fd4e0ce8d1d3a8e76c17a04542eb14f91f64e5a09550510",
        "counts":[8,3,2,1],
    }});
    let supplied = params()
        .inputs(vec![field])
        .actions(vec![input.as_object().unwrap().clone()])
        .unwrap();
    let empty = params().inputs(vec![]).actions(vec![]).unwrap();
    let target = Target::new(|_| async { Err::<TargetResponse, _>(()) }, None).unwrap();
    let sdk = client(&base);
    let mut session = session(&sdk);
    for params in [params(), supplied, empty] {
        let profile = session.profile(params, target.clone()).await.unwrap();
        profile.close().await.unwrap();
    }
    session.close().await.unwrap();
    sdk.close().await.unwrap();
    service.await.unwrap();
}

#[test]
fn profiling_raw_input_actions_fail_before_opening_a_paid_profile() {
    for kind in ["input", "change"] {
        let action = json!({"type":kind, "target":0, "value":"private-password"});
        let error = params()
            .actions(vec![action.as_object().unwrap().clone()])
            .unwrap_err();
        assert!(matches!(error, Error::Configuration(_)));
        assert!(!format!("{error:?} {error}").contains("private-password"));
    }
}

#[tokio::test]
async fn error_negotiation_distinguishes_target_502_from_transport_failure() {
    use std::error::Error as _;
    use tokio_tungstenite::tungstenite::handshake::server::{
        Callback, ErrorResponse, Request as HandshakeRequest, Response as HandshakeResponse,
    };

    struct CheckErrorFormat;
    impl Callback for CheckErrorFormat {
        fn on_request(
            self,
            request: &HandshakeRequest,
            response: HandshakeResponse,
        ) -> Result<HandshakeResponse, ErrorResponse> {
            assert_eq!(request.headers()["X-Nullgate-Error-Format"], "1");
            Ok(response)
        }
    }
    for negotiated in [false, true] {
        for failed in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            let service = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut socket = tokio_tungstenite::accept_hdr_async(stream, CheckErrorFormat)
                    .await
                    .unwrap();
                receive(&mut socket).await;
                let mut greeting =
                    json!({"type":"hello", "state_id":"continued", "request_id":REQUEST_ID});
                if negotiated {
                    greeting["error_format"] = json!(1);
                }
                send(&mut socket, greeting).await;
                send(&mut socket, json!({"type":"http", "id":1, "request":{
                    "role":"tags", "url":"https://target.example/private?secret=1", "method":"GET",
                    "headers":{}, "body":null, "credentials":"include"
                }})).await;
                let reply = receive(&mut socket).await;
                assert!(!reply.to_string().contains("private-local"));
                if failed {
                    assert_eq!(reply["type"], "http.error");
                    if negotiated {
                        assert_eq!(reply["error"]["kind"], "connection");
                    } else {
                        assert_eq!(reply.as_object().unwrap().len(), 3);
                    }
                } else {
                    assert_eq!(reply["type"], "http.result");
                    assert_eq!(reply["response"]["status"], 502);
                }
                let mut failure = json!({"type":"error", "status":502, "detail":"private-detail", "request_id":REQUEST_ID});
                if negotiated && failed {
                    failure["error"] = json!({"code":"CLIENT_TRANSPORT_ERROR", "origin":"client",
                        "message":"Target request failed", "retryable":null, "stage":"target_http", "command_id":1,
                        "target":{"role":"tags", "method":"GET", "host":"target.example"},
                        "cause":{"kind":"connection"}});
                }
                send(&mut socket, failure).await;
                expect_close_without_departure(&mut socket).await;
            });
            let sdk = client(&base);
            let mut session = session(&sdk);
            let target = Target::new(
                move |_| async move {
                    if failed {
                        Err(std::io::Error::new(
                            std::io::ErrorKind::ConnectionRefused,
                            "private-local https://user:private-password@proxy.example/path?private-token=secret",
                        ))
                    } else {
                        Ok(TargetResponse {
                            status: 502,
                            headers: BTreeMap::new(),
                            body: vec![],
                        })
                    }
                },
                None,
            )
            .unwrap();
            let error = session.profile(params(), target).await.unwrap_err();
            let Error::Profile(failure) = &error else {
                panic!("lost service category");
            };
            assert_eq!(failure.status(), Some(502));
            if negotiated && failed {
                let info = failure.error_info().unwrap();
                assert_eq!(info.code, "CLIENT_TRANSPORT_ERROR");
                assert_eq!(info.target.as_ref().unwrap().host, "target.example");
                assert!(
                    error
                        .to_string()
                        .starts_with("Nullgate CLIENT_TRANSPORT_ERROR origin=client")
                );
            } else {
                assert!(failure.error_info().is_none());
            }
            assert_eq!(failure.source().is_some(), negotiated && failed);
            assert!(!format!("{error} {error:?}").contains("private-"));
            let mut chain: Option<&(dyn std::error::Error + 'static)> = Some(&error);
            while let Some(source) = chain {
                assert!(!format!("{source} {source:?}").contains("private-"));
                chain = source.source();
            }
            if negotiated && failed {
                assert_eq!(
                    failure
                        .target_error()
                        .unwrap()
                        .downcast_ref::<std::io::Error>()
                        .unwrap()
                        .kind(),
                    std::io::ErrorKind::ConnectionRefused
                );
                assert!(error.target_error().unwrap().is::<std::io::Error>());
            } else {
                assert!(error.target_error().is_none());
            }
            session.close().await.unwrap_err();
            sdk.close().await.unwrap_err();
            service.await.unwrap();
        }
    }
}

#[tokio::test]
async fn target_cause_requires_explicit_matching_command() {
    for (code, origin, command_id, second_fails, expected) in [
        (
            "CLIENT_TRANSPORT_ERROR",
            "client",
            Some(1),
            true,
            Some(std::io::ErrorKind::TimedOut),
        ),
        (
            "CLIENT_TRANSPORT_ERROR",
            "client",
            Some(2),
            true,
            Some(std::io::ErrorKind::ConnectionRefused),
        ),
        ("CLIENT_TRANSPORT_ERROR", "client", Some(2), false, None),
        ("CLIENT_TRANSPORT_ERROR", "service", Some(1), true, None),
        ("UPSTREAM_ERROR", "client", Some(1), true, None),
        ("CLIENT_TRANSPORT_ERROR", "client", None, true, None),
        ("CLIENT_TRANSPORT_ERROR", "client", Some(3), true, None),
        ("CLIENT_TRANSPORT_ERROR", "client", Some(0), true, None),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let service = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            receive(&mut socket).await;
            send(&mut socket, json!({"type":"hello", "state_id":"continued", "request_id":REQUEST_ID, "error_format":1})).await;
            for id in 1..=2 {
                send(
                    &mut socket,
                    json!({"type":"http", "id":id, "request":{
                        "role":"tags", "url":format!("https://target.example/{id}"), "method":"GET",
                        "headers":{}, "body":null, "credentials":"include"
                    }}),
                )
                .await;
            }
            for _ in 0..2 {
                let reply = receive(&mut socket).await;
                if reply["id"] == 2 && !second_fails {
                    assert_eq!(reply["type"], "http.result");
                    assert_eq!(reply["response"]["status"], 502);
                } else {
                    assert_eq!(reply["type"], "http.error");
                }
            }
            let mut info =
                json!({"code":code, "origin":origin, "message":"safe", "retryable":null});
            if let Some(id) = command_id {
                info["command_id"] = json!(id);
            }
            send(&mut socket, json!({"type":"error", "status":502, "detail":"safe", "request_id":REQUEST_ID, "error":info})).await;
            expect_close_without_departure(&mut socket).await;
        });
        let sdk = client(&base);
        let mut session = session(&sdk);
        let target = Target::new(
            move |request| async move {
                if request.url.ends_with("/1") {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "private-first",
                    ));
                }
                if second_fails {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionRefused,
                        "private-second",
                    ));
                }
                Ok(TargetResponse {
                    status: 502,
                    headers: BTreeMap::new(),
                    body: vec![],
                })
            },
            None,
        )
        .unwrap();
        let error = session.profile(params(), target).await.unwrap_err();
        assert!(matches!(error, Error::Profile(_)));
        assert_eq!(
            error
                .target_error()
                .map(|source| source.downcast_ref::<std::io::Error>().unwrap().kind()),
            expected
        );
        let mut chain: Option<&(dyn std::error::Error + 'static)> = Some(&error);
        while let Some(source) = chain {
            assert!(!format!("{source} {source:?}").contains("private-"));
            chain = source.source();
        }
        session.close().await.unwrap_err();
        sdk.close().await.unwrap_err();
        service.await.unwrap();
    }
}

async fn deny_opening(
    stream: &mut TcpStream,
    detail: &str,
    marker: Option<&str>,
    retry_after: Option<&str>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut request = Vec::new();
    loop {
        let mut buffer = [0_u8; 1024];
        let read = stream.read(&mut buffer).await.unwrap();
        assert_ne!(read, 0);
        request.extend_from_slice(&buffer[..read]);
        if request.windows(4).any(|part| part == b"\r\n\r\n") {
            break;
        }
    }
    let body = json!({"detail":detail}).to_string();
    let retry_after = retry_after
        .map(|value| format!("Retry-After: {value}\r\n"))
        .unwrap_or_default();
    let marker = marker
        .map(|value| format!("X-Nullgate-Maintenance: {value}\r\n"))
        .unwrap_or_default();
    stream.write_all(format!(
        "HTTP/1.1 503 Service Unavailable\r\nContent-Length: {}\r\nConnection: close\r\nX-State-ID: must-not-rotate\r\n{marker}{retry_after}\r\n{body}",
        body.len(),
    ).as_bytes()).await.unwrap();
}

#[tokio::test]
async fn handshake_retries_only_exact_prework_maintenance_and_is_bounded() {
    for (detail, marker, delay, attempts) in [
        (
            "Service updating; retry after a short delay",
            Some("1"),
            Some("0"),
            3,
        ),
        ("busy", Some("1"), Some("0"), 3),
        (
            "Service updating; retry after a short delay",
            None,
            Some("0"),
            1,
        ),
        (
            "Service updating; retry after a short delay",
            Some("0"),
            Some("0"),
            1,
        ),
        (
            "Service updating; retry after a short delay",
            Some("1"),
            None,
            1,
        ),
        (
            "Service updating; retry after a short delay",
            Some("1"),
            Some("6"),
            1,
        ),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let sdk = client(&format!("http://{}", listener.local_addr().unwrap()));
        let service = tokio::spawn(async move {
            for _ in 0..attempts {
                let (mut stream, _) = listener.accept().await.unwrap();
                deny_opening(&mut stream, detail, marker, delay).await;
            }
            assert!(
                timeout(Duration::from_millis(50), listener.accept())
                    .await
                    .is_err()
            );
        });
        let mut session = session(&sdk);
        let state = session.state_id().unwrap().to_owned();
        let target = Target::new(|_| async { Err::<TargetResponse, _>(()) }, None).unwrap();
        assert!(matches!(
            session.profile(params(), target).await,
            Err(Error::Profile(_))
        ));
        assert_eq!(session.state_id(), Some(state.as_str()));
        service.await.unwrap();
    }
}

#[tokio::test]
async fn client_close_cancels_handshake_maintenance_wait() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let sdk = client(&format!("http://{}", listener.local_addr().unwrap()));
    let (denied, denial) = tokio::sync::oneshot::channel();
    let service = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        deny_opening(
            &mut stream,
            "Service updating; retry after a short delay",
            Some("1"),
            Some("5"),
        )
        .await;
        denied.send(()).unwrap();
        assert!(
            timeout(Duration::from_millis(50), listener.accept())
                .await
                .is_err()
        );
    });
    let mut session = session(&sdk);
    let target = Target::new(|_| async { Err::<TargetResponse, _>(()) }, None).unwrap();
    let close = async {
        denial.await.unwrap();
        sdk.close().await.unwrap();
    };
    let (result, ()) = tokio::join!(session.profile(params(), target), close);
    assert!(matches!(result, Err(Error::Profile(_))));
    service.await.unwrap();
}
