mod common;

use std::{
    collections::BTreeMap,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use common::{Reply, serve};
use nullgate_sdk::{
    Error, FindOptions, NullgateClient, Page, Params, Pixel, PixelParams, Protection, Sbsd,
    SbsdParams, Sensor, SensorParams, SessionOptions,
};
use serde_json::{Value, json};
use uuid::Uuid;

const KEY: &str = "ng_synthetic_test_key_not_a_real_credential";
const ID: Uuid = Uuid::from_u128(1);

fn sensor() -> Params {
    let page = Page::new("https://target.example/login", "<html>private html</html>").unwrap();
    Params::Sensor(
        SensorParams::new(
            Sensor::new(page, "https://target.example/collect?raw=%2f+v").unwrap(),
            "private source",
        )
        .unwrap(),
    )
}

fn generated() -> Value {
    json!({"sensor_data":"raw sensor 😀", "send_at":-1, "headers":{"Accept-Language":"en-US"}})
}

fn success(id: &str, state: Option<&str>) -> Reply {
    let reply = Reply::json(200, generated()).header("X-Request-ID", id);
    match state {
        Some(state) => reply.header("X-State-ID", state),
        None => reply,
    }
}

#[tokio::test]
async fn normalizes_all_three_operations_without_reencoding_target_bodies() {
    let mut server = serve(vec![
        Reply::json(200, json!({"sensor_data":"raw sensor 😀", "send_at":-1, "headers":{"Accept-Language":"en", "content-type":"wrong", "CONTENT-TYPE":"also wrong"}})).header("X-Request-ID", "sensor-request"),
        Reply::json(200, json!({"url":"https://target.example/pixel?keep=%2f+q", "body":"a=1%2F2&b=+", "send_at":0, "headers":{"Accept-Language":"en"}})).header("X-Request-ID", "pixel-request"),
        Reply::json(200, json!({"url":"https://target.example/sbsd", "body":"{\"already\":\"serialized\"}", "send_at":0, "headers":{"Accept-Language":"en"}})).header("X-Request-ID", "sbsd-request"),
    ]).await;
    let client = NullgateClient::builder(KEY)
        .base_url(&server.url)
        .build()
        .unwrap();
    let mut session = client
        .open(SessionOptions::new(ID, "target-user-agent").timezone("Europe/Berlin"))
        .unwrap();
    let sensor = session.solve(sensor()).await.unwrap();
    assert_eq!(sensor.method(), "POST");
    assert_eq!(
        sensor.url().as_str(),
        "https://target.example/collect?raw=%2f+v"
    );
    assert_eq!(sensor.body(), "{\"sensor_data\":\"raw sensor 😀\"}");
    assert_eq!(
        sensor.headers().get("Content-Type").unwrap(),
        "text/plain;charset=UTF-8"
    );
    assert_eq!(sensor.headers().get("Accept-Language").unwrap(), "en");
    assert_eq!(
        sensor
            .headers()
            .keys()
            .filter(|name| name.eq_ignore_ascii_case("content-type"))
            .count(),
        1
    );
    assert_eq!(sensor.request_id(), "sensor-request");
    sensor.wait().await.unwrap();

    let page = Page::new("https://target.example/", "original html").unwrap();
    let pixel = Pixel::new(page.clone(), "https://target.example/akam/13/abc", "0012").unwrap();
    let pixel = session
        .solve(Params::Pixel(
            PixelParams::new(pixel, "pixel source").unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(pixel.body(), "a=1%2F2&b=+");
    assert_eq!(
        pixel.url().as_str(),
        "https://target.example/pixel?keep=%2f+q"
    );
    assert_eq!(
        pixel.headers().get("Content-Type").unwrap(),
        "application/x-www-form-urlencoded"
    );
    let sbsd = Sbsd::new(
        page,
        "https://target.example/challenge?v=11111111-2222-4333-8444-555555555555&t=",
    )
    .unwrap();
    let sbsd = session
        .solve(Params::Sbsd(SbsdParams::new(sbsd, "sbsd source").unwrap()))
        .await
        .unwrap();
    assert_eq!(sbsd.body(), "{\"already\":\"serialized\"}");
    assert_eq!(
        sbsd.headers().get("Content-Type").unwrap(),
        "application/json"
    );
    let first = server.requests.recv().await.unwrap();
    assert_eq!(first.target, format!("/v1/{ID}/generate?type=akamai"));
    assert_eq!(first.headers["authorization"], format!("Bearer {KEY}"));
    assert_eq!(first.headers["user-agent"], "target-user-agent");
    assert_eq!(first.body["timezone"], "Europe/Berlin");
    let second = server.requests.recv().await.unwrap();
    assert_eq!(second.target, format!("/v1/{ID}/generate?type=pixel"));
    assert_eq!(second.body["challenge"], "0012");
    let third = server.requests.recv().await.unwrap();
    assert_eq!(third.target, format!("/v1/{ID}/generate?type=sbsd"));
}

#[tokio::test]
async fn document_observations_change_without_replacing_session_or_profile() {
    let target_post = json!({
        "url":"https://target.example/post", "body":"ready", "send_at":0, "headers":{}
    });
    let mut server = serve(vec![
        Reply::json(200, target_post.clone()).header("X-Request-ID", "pixel"),
        success("sensor", None),
        Reply::json(200, target_post).header("X-Request-ID", "sbsd"),
        success("new-document", None),
        success("same-document", None),
        success("original-document", None),
    ])
    .await;
    let client = NullgateClient::builder(KEY)
        .base_url(&server.url)
        .build()
        .unwrap();
    let mut session = client
        .open(SessionOptions::new(ID, "profile").timezone("Europe/Berlin"))
        .unwrap();
    let initial_state = session.state_id().unwrap().to_owned();
    let before = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let html = format!(
        "<script>bazadebezolkohpepadr='12'</script>\
         <script src='/akam/13/abc'></script>\
         <script src='/collector'></script>\
         <script src='/challenge?v={ID}'></script>"
    );
    let html_pointer = html.as_ptr();
    let page = Page::new("https://target.example/", html).unwrap();
    let after = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    assert!((before..=after).contains(&u128::from(page.started_at_ms())));
    assert_eq!(page.html().as_ptr(), html_pointer);
    let found = client
        .find_protections_with_options(&page.clone(), FindOptions { panic: false })
        .unwrap();
    let mut original_sensor = None;
    for protection in found {
        assert_eq!(protection.page().html().as_ptr(), html_pointer);
        let params = match protection {
            Protection::Pixel(pixel) => Params::Pixel(PixelParams::new(pixel, "source").unwrap()),
            Protection::Sensor(sensor) => {
                let params = Params::Sensor(SensorParams::new(sensor, "source").unwrap());
                original_sensor = Some(params.clone());
                params
            }
            Protection::Sbsd(sbsd) => Params::Sbsd(SbsdParams::new(sbsd, "source").unwrap()),
            Protection::ThreatMetrix(_) => unreachable!("fixture contains only Akamai scripts"),
        };
        session.solve(params).await.unwrap();
        assert_eq!(session.state_id(), Some(initial_state.as_str()));
    }
    let next_page = Page::new(page.url().as_str(), page.html()).unwrap();
    assert_ne!(next_page.document_id(), page.document_id());
    let next_sensor = Params::Sensor(
        SensorParams::new(
            Sensor::new(next_page.clone(), "https://target.example/collector").unwrap(),
            "source",
        )
        .unwrap(),
    );
    session.solve(next_sensor.clone()).await.unwrap();
    session.solve(next_sensor).await.unwrap();
    assert_eq!(session.state_id(), Some(initial_state.as_str()));
    session.solve(original_sensor.unwrap()).await.unwrap();
    assert_eq!(session.state_id(), Some(initial_state.as_str()));
    assert_eq!(session.identity(), ID);
    for index in 0..6 {
        let request = server.requests.recv().await.unwrap();
        let observed = if matches!(index, 3..=4) {
            &next_page
        } else {
            &page
        };
        let website = &request.body["website"];
        assert_eq!(
            Uuid::parse_str(website["document_id"].as_str().unwrap()).unwrap(),
            observed.document_id()
        );
        assert_eq!(website["started_at_ms"], observed.started_at_ms());
        assert_eq!(request.headers["x-state-id"], initial_state);
        assert_eq!(request.headers["user-agent"], "profile");
        assert_eq!(request.body["timezone"], "Europe/Berlin");
        assert!(request.target.starts_with(&format!("/v1/{ID}/generate?")));
    }
}

#[tokio::test]
async fn state_is_per_session_and_rotates_on_api_and_protocol_errors() {
    let mut server = serve(vec![
        success("a-first", Some("state-a")),
        Reply::json(
            422,
            json!({"detail":{"reason":"private html and private source"}}),
        )
        .header("X-Request-ID", "b-error")
        .header("X-State-ID", "state-b"),
        Reply::json(200, json!({"headers":{}, "send_at":0}))
            .header("X-Request-ID", "a-malformed")
            .header("X-State-ID", "state-a-next"),
        success("b-next", None),
        success("a-next", None),
    ])
    .await;
    let client = NullgateClient::builder(KEY)
        .base_url(&server.url)
        .build()
        .unwrap();
    let mut a = client.open(SessionOptions::new(ID, "profile-a")).unwrap();
    let mut b = client
        .open(SessionOptions::new(Uuid::from_u128(2), "profile-b"))
        .unwrap();
    let initial_a = a.state_id().unwrap().to_owned();
    let initial_b = b.state_id().unwrap().to_owned();
    assert_ne!(initial_a, initial_b);
    let a_params = sensor();
    let b_params = sensor();
    a.solve(a_params.clone()).await.unwrap();
    let error = b.solve(b_params.clone()).await.unwrap_err();
    let Error::Api(api) = &error else {
        panic!("wrong failure category: {error:?}");
    };
    assert_eq!(api.status(), 422);
    assert_eq!(api.request_id(), Some("b-error"));
    assert_eq!(
        api.detail(),
        &json!({"reason":"private html and private source"})
    );
    assert!(!format!("{error:?} {error}").contains("private"));
    let malformed = a.solve(a_params.clone()).await.unwrap_err();
    let Error::Protocol(protocol) = malformed else {
        panic!("expected protocol failure");
    };
    assert_eq!(protocol.request_id(), Some("a-malformed"));
    assert_eq!(a.state_id(), Some("state-a-next"));
    assert_eq!(b.state_id(), Some("state-b"));
    b.solve(b_params).await.unwrap();
    a.solve(a_params).await.unwrap();
    let mut requests = Vec::new();
    for _ in 0..5 {
        requests.push(server.requests.recv().await.unwrap());
    }
    assert_eq!(requests[0].headers["x-state-id"], initial_a);
    assert_eq!(requests[1].headers["x-state-id"], initial_b);
    assert_eq!(requests[2].headers["x-state-id"], "state-a");
    assert_eq!(requests[3].headers["x-state-id"], "state-b");
    assert_eq!(requests[4].headers["x-state-id"], "state-a-next");
    assert_eq!(a.state_id(), Some("state-a-next"));
    assert_eq!(b.state_id(), Some("state-b"));
}

#[tokio::test]
async fn independent_sessions_can_generate_concurrently_without_shared_headers() {
    let mut server = serve(vec![
        success("first", Some("state-first")),
        success("second", Some("state-second")),
        success("third", None),
        success("fourth", None),
    ])
    .await;
    let client = NullgateClient::builder(KEY)
        .base_url(&server.url)
        .build()
        .unwrap();
    let mut a = client.open(SessionOptions::new(ID, "profile-a")).unwrap();
    let mut b = client.open(SessionOptions::new(ID, "profile-b")).unwrap();
    let initial_a = a.state_id().unwrap().to_owned();
    let initial_b = b.state_id().unwrap().to_owned();
    assert_ne!(initial_a, initial_b);
    let params = sensor();
    let (first, second) = tokio::join!(a.solve(params.clone()), b.solve(params.clone()));
    first.unwrap();
    second.unwrap();
    let state_a = a.state_id().unwrap().to_owned();
    let state_b = b.state_id().unwrap().to_owned();
    assert_ne!(state_a, state_b);
    let (third, fourth) = tokio::join!(a.solve(params.clone()), b.solve(params));
    third.unwrap();
    fourth.unwrap();
    for _ in 0..2 {
        let request = server.requests.recv().await.unwrap();
        let expected = if request.headers["user-agent"] == "profile-a" {
            &initial_a
        } else {
            &initial_b
        };
        assert_eq!(&request.headers["x-state-id"], expected);
    }
    for _ in 0..2 {
        let request = server.requests.recv().await.unwrap();
        let expected = if request.headers["user-agent"] == "profile-a" {
            &state_a
        } else {
            &state_b
        };
        assert_eq!(&request.headers["x-state-id"], expected);
    }
}

#[tokio::test]
async fn input_values_are_summarized_and_empty_activity_is_not_absent() {
    let mut server = serve(vec![success("filled", None), success("cleared", None)]).await;
    let client = NullgateClient::builder(KEY)
        .base_url(&server.url)
        .build()
        .unwrap();
    let mut session = client.open(SessionOptions::new(ID, "profile")).unwrap();
    let page = Page::new("https://target.example/", "").unwrap();
    let protection = Sensor::new(page, "https://target.example/collector").unwrap();
    let field = BTreeMap::from([
        ("type".to_owned(), "password".to_owned()),
        ("value".to_owned(), "A_9 😀İ\u{a0}".to_owned()),
    ]);
    let actions = [
        json!({"type":"focus"}),
        json!({"type":"input","value":{"length":8,"hash":"552f5768ce4326ff5fd4e0ce8d1d3a8e76c17a04542eb14f91f64e5a09550510","counts":[8,3,2,1]}}),
        json!({"type":"change","value":{"length":8,"hash":"552f5768ce4326ff5fd4e0ce8d1d3a8e76c17a04542eb14f91f64e5a09550510","counts":[8,3,2,1]}}),
        json!({"type":"input","value":null}),
        json!({"type":"change"}),
        json!({"type":"keypress","value":"Enter"}),
    ];
    let filled = SensorParams::new(protection.clone(), "source")
        .unwrap()
        .inputs(vec![field])
        .actions(
            actions
                .iter()
                .map(|action| action.as_object().unwrap().clone())
                .collect(),
        )
        .unwrap();
    session.solve(Params::Sensor(filled)).await.unwrap();
    session
        .solve(Params::Sensor(
            SensorParams::new(protection, "source")
                .unwrap()
                .inputs(vec![])
                .actions(vec![])
                .unwrap(),
        ))
        .await
        .unwrap();
    let request = server.requests.recv().await.unwrap();
    assert!(!request.body.to_string().contains("A_9"));
    let summary = &request.body["inputs"][0]["value"];
    assert_eq!(summary["hash31"], -902_761_640);
    assert_eq!(summary["trimmed_hash31"], 386_520_648);
    assert_eq!(summary["trimmed_length"], 7);
    let cleared = server.requests.recv().await.unwrap();
    assert_eq!(cleared.body["inputs"], json!([]));
    assert_eq!(cleared.body["actions"], json!([]));
}

#[test]
fn raw_input_and_change_actions_are_rejected_during_construction() {
    let page = Page::new("https://target.example/", "").unwrap();
    let protection = Sensor::new(page, "https://target.example/collector").unwrap();
    for kind in ["input", "change"] {
        for raw in ["private-password", ""] {
            let action = json!({"type":kind,"target":0,"value":raw});
            let error = SensorParams::new(protection.clone(), "source")
                .unwrap()
                .actions(vec![action.as_object().unwrap().clone()])
                .unwrap_err();
            assert!(matches!(error, Error::Configuration(_)));
            assert!(!format!("{error:?} {error}").contains("private-password"));
        }
    }
}

#[tokio::test]
async fn malformed_success_is_a_checked_protocol_error_not_a_default_solution() {
    let bad = [
        json!({"send_at":0,"headers":{}}),
        json!({"sensor_data":13,"send_at":0,"headers":{}}),
        json!({"sensor_data":"x","send_at":"later","headers":{}}),
        json!({"sensor_data":"x","send_at":0,"headers":{"Bad\nName":"value"}}),
    ];
    let mut replies = bad
        .into_iter()
        .map(|body| Reply::json(200, body).header("X-Request-ID", "malformed"))
        .collect::<Vec<_>>();
    replies.push(Reply::json(200, generated()));
    let server = serve(replies).await;
    let client = NullgateClient::builder(KEY)
        .base_url(&server.url)
        .build()
        .unwrap();
    let mut session = client.open(SessionOptions::new(ID, "profile")).unwrap();
    for _ in 0..5 {
        assert!(matches!(
            session.solve(sensor()).await,
            Err(Error::Protocol(_))
        ));
    }
}

#[tokio::test]
async fn reports_never_send_auth_state_or_cookies_and_survive_client_drop() {
    let mut server = serve(vec![
        success("generation-id", Some("private-state"))
            .header("Set-Cookie", "private=cookie; Path=/"),
        Reply::json(200, json!({"ok":true})),
        Reply::json(503, json!({"detail":"unavailable"})),
    ])
    .await;
    let client = NullgateClient::builder(KEY)
        .base_url(&server.url)
        .analytics_url(&server.url)
        .build()
        .unwrap();
    let mut session = client
        .open(SessionOptions::new(ID, "private-user-agent"))
        .unwrap();
    let solution = session.solve(sensor()).await.unwrap();
    drop(session);
    drop(client);
    assert!(solution.report().await.unwrap());
    assert!(!solution.report().await.unwrap());
    let _ = server.requests.recv().await.unwrap();
    for _ in 0..2 {
        let request = server.requests.recv().await.unwrap();
        assert_eq!(request.target, "/report");
        assert_eq!(request.body, json!({"request_id":"generation-id"}));
        for secret_header in ["authorization", "x-state-id", "cookie", "user-agent"] {
            assert!(
                !request.headers.contains_key(secret_header),
                "leaked {secret_header}"
            );
        }
        assert!(!format!("{solution:?}").contains(KEY));
    }
}

#[tokio::test]
async fn report_timeout_redirect_and_cancellation_do_not_become_success() {
    let mut slow = serve(vec![
        Reply::json(200, json!({"ok":true})).delay(Duration::from_secs(30)),
    ])
    .await;
    let client = NullgateClient::builder(KEY)
        .analytics_url(&slow.url)
        .report_timeout(Duration::from_millis(20))
        .build()
        .unwrap();
    assert!(!client.report("slow").await.unwrap());
    assert_eq!(
        slow.requests.recv().await.unwrap().body,
        json!({"request_id":"slow"})
    );

    let mut redirected = serve(vec![
        Reply::json(302, json!({})).header("Location", "https://target.example/never-send"),
    ])
    .await;
    let client = NullgateClient::builder(KEY)
        .analytics_url(&redirected.url)
        .build()
        .unwrap();
    assert!(!client.report("redirect").await.unwrap());
    assert_eq!(redirected.requests.recv().await.unwrap().target, "/report");
    assert!(redirected.requests.recv().await.is_none());

    let mut cancelled = serve(vec![
        Reply::json(200, json!({})).delay(Duration::from_secs(30)),
    ])
    .await;
    let client = NullgateClient::builder(KEY)
        .analytics_url(&cancelled.url)
        .build()
        .unwrap();
    let task = tokio::spawn(async move { client.report("cancelled").await });
    let _ = cancelled.requests.recv().await.unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
}

#[tokio::test]
async fn wait_obeys_absolute_deadline_and_can_be_cancelled() {
    let future = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs_f64()
        + 60.0;
    let server = serve(vec![
        Reply::json(
            200,
            json!({"sensor_data":"x","send_at":future,"headers":{}}),
        )
        .header("X-Request-ID", "future"),
    ])
    .await;
    let client = NullgateClient::builder(KEY)
        .base_url(&server.url)
        .build()
        .unwrap();
    let mut session = client.open(SessionOptions::new(ID, "profile")).unwrap();
    let solution = session.solve(sensor()).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(10), solution.wait())
            .await
            .is_err()
    );
}

#[test]
fn checked_values_fail_without_echoing_secrets() {
    let error = NullgateClient::new("this-is-a-private-secret").unwrap_err();
    assert!(!format!("{error:?} {error}").contains("this-is-a-private-secret"));
    assert!(
        NullgateClient::builder(KEY)
            .analytics_url("https://user:secret@analytics.example/")
            .build()
            .is_err()
    );
    assert!(
        NullgateClient::builder(KEY)
            .report_timeout(Duration::ZERO)
            .build()
            .is_err()
    );
    assert!(Page::new("file:///private/html", "secret").is_err());
    fn send_sync<T: Send + Sync>() {}
    send_sync::<NullgateClient>();
    send_sync::<nullgate_sdk::Session>();
    send_sync::<nullgate_sdk::Solution>();
}
