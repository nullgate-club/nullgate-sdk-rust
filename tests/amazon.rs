mod common;

use common::{Reply, serve};
use nullgate_sdk::{
    Error, FwcimGeometry, FwcimInput, FwcimParams, NullgateClient, Page, Params, Sensor,
    SensorParams, SessionOptions,
};
use serde_json::json;
use std::{collections::BTreeMap, time::Duration};
use uuid::Uuid;

const KEY: &str = "ng_synthetic_test_key_not_a_real_credential";
const ID: Uuid = Uuid::from_u128(1);

fn page(html: &str) -> Page {
    Page::new("https://target.example/signin", html).unwrap()
}
fn params(page: &Page) -> FwcimParams {
    FwcimParams::new(
        page.clone(),
        BTreeMap::from([("navigationStart".into(), page.started_at_ms())]),
    )
    .unwrap()
}
fn generated() -> Reply {
    Reply::json(200, json!({"metadata1":"sensitive+/%=metadata", "send_at":0, "headers":{"Accept-Language":"en"}})).header("X-Request-ID", "fwcim-request")
}
fn maintenance(delay: &str) -> Reply {
    Reply::json(
        503,
        json!({"detail":"Service updating; retry after a short delay"}),
    )
    .header("Retry-After", delay)
    .header("X-Nullgate-Maintenance", "1")
    .header("X-State-ID", "must-not-rotate")
}

#[test]
fn template_content_is_not_a_document_descendant() {
    let document = page(
        "<form id=f><template><input id=inert></template><input id=active></form>\
         <template><form id=hidden></form></template>",
    );
    for (attributes, selector) in [
        (BTreeMap::from([("id".into(), "inert".into())]), None),
        (BTreeMap::new(), Some("#inert")),
    ] {
        assert!(FwcimInput::new(&document, attributes, selector, "safe", false).is_err());
    }
    let active =
        FwcimInput::new(&document, BTreeMap::new(), Some("#active"), "safe", false).unwrap();
    assert!(
        params(&document)
            .form_selector("#f")
            .unwrap()
            .inputs(vec![active])
            .is_ok()
    );
    assert!(params(&document).form_selector("#hidden").is_err());
    for html in [
        "<template><input type=password value='' value=private></template>",
        "<template><textarea autocomplete=current-password>private</textarea></template>",
    ] {
        let unsafe_document = page(html);
        assert!(
            FwcimParams::new(
                unsafe_document.clone(),
                BTreeMap::from([("navigationStart".into(), unsafe_document.started_at_ms())]),
            )
            .is_err()
        );
    }
}

#[test]
fn rejects_password_html_and_selected_passwords_without_echo() {
    for html in [
        "<input TYPE=PASSWORD value=secret>",
        "<input type=password value='&#115;ecret'>",
        "<input type=' PaSsWoRd ' value=secret>",
        "<input autocomplete='section-login CURRENT-password' value=secret>",
        "<input autocomplete='new-password' value=secret>",
        "<input id=' AP_PASSWORD ' value=secret>",
        "<input name=' PASSWORD ' value=secret>",
        "<textarea autocomplete='current-password'>secret</textarea>",
        "<input type=password value='' value=secret>",
        "<input type=password value=secret value=''>",
        "<input type=password value='' value='&#115;ecret' value=''>",
    ] {
        let page = page(html);
        let error = FwcimParams::new(
            page.clone(),
            BTreeMap::from([("navigationStart".into(), page.started_at_ms())]),
        )
        .unwrap_err();
        assert!(!format!("{error:?} {error}").contains("secret"));
    }
    let page = page("<input id=user><input id=pass type=' PaSsWoRd '>");
    assert!(FwcimInput::new(&page, BTreeMap::new(), Some("#pass"), "secret", true).is_err());
    assert!(
        FwcimInput::new(
            &page,
            BTreeMap::from([("type".into(), "text".into())]),
            Some("#pass"),
            "secret",
            false
        )
        .is_err()
    );
    assert!(
        FwcimInput::new(
            &page,
            BTreeMap::from([("id".into(), "user".into())]),
            Some("#pass"),
            "secret",
            false
        )
        .is_err()
    );
}

#[test]
fn rejects_sensitive_observations_but_allows_nonpassword_text() {
    for attribute in [
        "type=' PASSWORD '",
        "autocomplete='section-login CURRENT-password'",
        "autocomplete='new-password'",
        "id=' AP_PASSWORD '",
        "name=' PASSWORD '",
    ] {
        let page = page(&format!("<input {attribute}>"));
        for canvas_text in [false, true] {
            let error =
                FwcimInput::new(&page, BTreeMap::new(), Some("input"), "secret", canvas_text)
                    .unwrap_err();
            assert!(!format!("{error:?} {error}").contains("secret"));
        }
    }
    let page = page("<input id=email value='ordinary text'><textarea>ordinary text</textarea>");
    let input = FwcimInput::new(
        &page,
        BTreeMap::new(),
        Some("#email"),
        "ordinary text",
        true,
    )
    .unwrap();
    assert_eq!(
        serde_json::to_value(&input).unwrap()["text"],
        "ordinary text"
    );
    assert!(params(&page).inputs(vec![input]).is_ok());
}

#[test]
fn form_membership_uses_descendant_identity_not_html_form_ownership() {
    let page = page(
        "<form id=selected><input id=inside form=other></form>\
         <form id=other></form><input id=external form=selected>\
         <form id=duplicate><input id=first></form>\
         <form id=duplicate class=second><input id=second></form>",
    );
    for (control, form, expected) in [
        ("#inside", "#selected", true),
        ("#inside", "#other", false),
        ("#external", "#selected", false),
        ("#first", ".second", false),
        ("#second", ".second", true),
    ] {
        let input = FwcimInput::new(&page, BTreeMap::new(), Some(control), "text", false).unwrap();
        assert_eq!(
            params(&page)
                .form_selector(form)
                .unwrap()
                .inputs(vec![input.clone()])
                .is_ok(),
            expected,
        );
        assert_eq!(
            params(&page)
                .inputs(vec![input])
                .unwrap()
                .form_selector(form)
                .is_ok(),
            expected,
        );
    }
}

#[test]
fn input_page_binding_includes_navigation_start_in_both_builder_orders() {
    let page = page("<form id=signin><input id=email></form>").with_document_context(ID, 123);
    let input = FwcimInput::new(&page, BTreeMap::new(), Some("#email"), "text", false).unwrap();
    let other = page.clone().with_document_context(ID, 124);
    assert!(
        params(&other)
            .form_selector("#signin")
            .unwrap()
            .inputs(vec![input.clone()])
            .is_err()
    );
    assert!(
        params(&other)
            .inputs(vec![input])
            .and_then(|params| params.form_selector("#signin"))
            .is_err()
    );
}

#[test]
fn selectors_confirm_controls_and_preserve_document_binding() {
    let page = page(
        "<form id=a><input name=email></form><form id=b><input name=email></form><textarea id=notes></textarea>",
    );
    let attrs = BTreeMap::from([("name".into(), "email".into())]);
    assert!(FwcimInput::new(&page, attrs.clone(), None, "a", false).is_err());
    assert!(FwcimInput::new(&page, attrs.clone(), Some("input"), "a", false).is_err());
    assert!(FwcimInput::new(&page, attrs.clone(), Some("#a"), "a", false).is_err());
    let input =
        FwcimInput::new(&page, attrs, Some("#b > input[name='email']"), "a", false).unwrap();
    assert!(params(&page).inputs(vec![input.clone()]).is_ok());
    assert!(
        params(&page)
            .form_selector("#a")
            .unwrap()
            .inputs(vec![input.clone()])
            .is_err()
    );
    assert!(
        params(&page)
            .inputs(vec![input.clone()])
            .unwrap()
            .form_selector("#a")
            .is_err()
    );
    assert!(
        params(&page)
            .form_selector("#b")
            .unwrap()
            .inputs(vec![input.clone()])
            .is_ok()
    );
    for selector in ["form", "#missing", "#notes", "["] {
        assert!(params(&page).form_selector(selector).is_err());
    }
    let other = Page::new("https://target.example/", "<input name=email>").unwrap();
    assert!(params(&other).inputs(vec![input]).is_err());
    assert!(FwcimInput::new(&page, BTreeMap::new(), Some("#notes"), "notes", false).is_ok());
}

#[tokio::test]
async fn sends_redacted_wire_model_and_independent_state() {
    let mut server = serve(vec![
        generated().header("X-State-ID", "amazon-rotated"),
        generated(),
        Reply::json(
            200,
            json!({"sensor_data":"sensor", "send_at":0, "headers":{}}),
        )
        .header("X-Request-ID", "sensor"),
    ])
    .await;
    let client = NullgateClient::builder(KEY)
        .base_url(&server.url)
        .amazon_base_url(&server.url)
        .build()
        .unwrap();
    let mut session = client
        .open(SessionOptions::new(ID, "exact-UA").timezone("Europe/Berlin"))
        .unwrap();
    let original = session.state_id().unwrap().to_owned();
    let amazon_original = session.amazon_state_id().unwrap().to_owned();
    assert_ne!(original, amazon_original);
    let page = page("<form id=signin><input id=email><input id=password type=password></form>");
    let input = FwcimInput::new(
        &page,
        BTreeMap::from([("id".into(), "email".into())]),
        None,
        "😀",
        false,
    )
    .unwrap()
    .geometry(FwcimGeometry {
        left: 1.0,
        top: 2.0,
        width: 3.0,
        height: 4.0,
    })
    .unwrap();
    let observation = params(&page)
        .inputs(vec![input])
        .unwrap()
        .form_selector("#signin")
        .unwrap()
        .history_length(2)
        .unwrap()
        .referrer("https://target.example/");
    let solution = session.fwcim(&observation).await.unwrap();
    assert_eq!(solution.metadata1(), "sensitive+/%=metadata");
    assert_eq!(solution.request_id(), "fwcim-request");
    assert_eq!(solution.headers()["Accept-Language"], "en");
    assert!(!format!("{solution:?}").contains("sensitive"));
    solution.wait().await.unwrap();
    assert_eq!(session.state_id(), Some(original.as_str()));
    assert_eq!(session.amazon_state_id(), Some("amazon-rotated"));
    session
        .fwcim(
            &params(&page)
                .inputs(vec![])
                .unwrap()
                .actions(vec![])
                .unwrap(),
        )
        .await
        .unwrap();
    session
        .solve(Params::Sensor(
            SensorParams::new(
                Sensor::new(page.clone(), "https://target.example/collect").unwrap(),
                "source",
            )
            .unwrap(),
        ))
        .await
        .unwrap();
    let request = server.requests.recv().await.unwrap();
    assert_eq!(request.target, format!("/v1/{ID}/generate?type=fwcim"));
    assert_eq!(request.headers["authorization"], format!("Bearer {KEY}"));
    assert_eq!(request.headers["user-agent"], "exact-UA");
    assert_eq!(request.headers["x-nullgate-error-format"], "1");
    assert_eq!(request.headers["x-state-id"], amazon_original);
    assert_eq!(
        request.body["website"]["document_id"],
        page.document_id().to_string()
    );
    assert_eq!(
        request.body["performance_timing"]["navigationStart"],
        page.started_at_ms()
    );
    assert_eq!(request.body["timezone"], "Europe/Berlin");
    assert_eq!(request.body["submitted"], true);
    assert_eq!(request.body["inputs"][0]["checksum"], 0xe4b9444d_u32);
    assert_eq!(request.body["inputs"][0]["value"]["length"], 2);
    assert!(request.body["inputs"][0]["value"].get("checksum").is_none());
    assert!(request.body["inputs"][0].get("text").is_none());
    assert!(request.body.get("script").is_none());
    assert!(request.body.get("actions").is_none());
    let request = server.requests.recv().await.unwrap();
    assert_eq!(request.headers["x-state-id"], "amazon-rotated");
    assert_eq!(request.body["inputs"], json!([]));
    assert_eq!(request.body["actions"], json!([]));
    let request = server.requests.recv().await.unwrap();
    assert_eq!(request.headers["x-state-id"], original);
}

#[test]
fn validates_timings_geometry_and_action_privacy() {
    let page = page("<input id=email>");
    assert!(FwcimParams::new(page.clone(), BTreeMap::new()).is_err());
    assert!(
        FwcimParams::new(
            page.clone(),
            BTreeMap::from([("navigationStart".into(), 0)])
        )
        .is_err()
    );
    let zero_page = page.clone().with_document_context(ID, 0);
    assert!(FwcimParams::new(zero_page, BTreeMap::from([("navigationStart".into(), 0)])).is_err());
    for event_time in [0, page.started_at_ms(), page.started_at_ms() - 1] {
        assert_eq!(
            FwcimParams::new(
                page.clone(),
                BTreeMap::from([
                    ("navigationStart".into(), page.started_at_ms()),
                    ("domComplete".into(), event_time),
                ])
            )
            .is_ok(),
            event_time == 0 || event_time >= page.started_at_ms(),
        );
    }
    for action in [
        json!({"type":"input", "value":"secret"}),
        json!({"type":"input", "input_summary":"secret"}),
        json!({"type":"input", "input_summary":{"length":6,"hash":"secret"}}),
        json!({"type":"input", "input_summary":{"length":6,"hash":"a".repeat(64),"text":"secret"}}),
        json!({"type": {"value":"secret"}}),
        json!({"target_path": ["secret"]}),
        json!({"pointer_type": {"value":"secret"}}),
        json!({"target": true}),
        json!({"trusted": 1}),
        json!({"x": "secret"}),
        json!({"touches": {"value":"secret"}}),
        json!({"touches": ["secret"]}),
        json!({"touches": [{"x":"secret"}]}),
        json!({"touches": [{}]}),
        json!({"touches": [{"x":1}]}),
        json!({"touches": [{"x":null,"y":1}]}),
        json!({"touches": [{"x":1,"y":null}]}),
        json!({"touches": [{"x":1,"y":2,"identifier":null}]}),
        json!({"touches": [{"x":1,"y":2,"identifier":1.5}]}),
        json!({"touches": [{"x":1,"value":"secret"}]}),
        json!({"acceleration": {"x":true}}),
        json!({"acceleration_with_gravity": {"value":"secret"}}),
        json!({"rotation_rate": {"x":1}}),
        json!({"input_summary": [1,[1,2,3,"secret"]]}),
    ] {
        assert!(
            params(&page)
                .actions(vec![action.as_object().unwrap().clone()])
                .is_err()
        );
    }
    for action in [
        json!({"type":"input","input_summary":[6,[6,0,6,0]]}),
        json!({"type":"input","input_summary":[0,null]}),
        json!({"touches": []}),
        json!({"touches": [{"x":-1.5,"y":-2,"identifier":-1}]}),
        json!({"touches": [{"x":1,"y":2}]}),
        json!({"type":"pointermove","target":null,"target_path":"#field","pointer_type":"mouse",
            "trusted":true,"x":1.5,"y":null,"touches":[{"x":1,"y":2,"identifier":0}],
            "acceleration":[null,0,1],"acceleration_with_gravity":[0,1,2],"rotation_rate":[0,0,0]}),
    ] {
        assert!(
            params(&page)
                .actions(vec![action.as_object().unwrap().clone()])
                .is_ok()
        );
    }
    for field in ["acceleration", "acceleration_with_gravity", "rotation_rate"] {
        for vector in [json!(null), json!([null, 1.5, -2])] {
            assert!(
                params(&page)
                    .actions(vec![serde_json::Map::from_iter([(field.into(), vector)])])
                    .is_ok()
            );
        }
        for vector in [
            json!({"x": 1, "y": 2, "z": 3}),
            json!({"alpha": 1, "beta": 2, "gamma": 3}),
            json!([]),
            json!([1, 2]),
            json!([1, 2, 3, 4]),
            json!([1, true, 3]),
            json!([1, "secret", 3]),
            json!([1, {"value": "secret"}, 3]),
        ] {
            assert!(
                params(&page)
                    .actions(vec![serde_json::Map::from_iter([(field.into(), vector)])])
                    .is_err()
            );
        }
    }
    let input = FwcimInput::new(&page, BTreeMap::new(), Some("#email"), "é", true).unwrap();
    let value = serde_json::to_value(&input).unwrap();
    assert_eq!(value["checksum"], 0x0e048d3e_u32);
    assert_eq!(value["text"], "é");
    assert!(
        input
            .geometry(FwcimGeometry {
                left: 0.0,
                top: 0.0,
                width: f64::NAN,
                height: 1.0
            })
            .is_err()
    );
    let observed = page.clone().with_document_context(Uuid::from_u128(12), 123);
    assert_eq!(observed.started_at_ms(), 123);
    assert_eq!(observed.clone().document_id(), Uuid::from_u128(12));
    assert_ne!(page.document_id(), observed.document_id());
}

#[tokio::test]
async fn retains_error_rotations_and_rejects_malformed_solutions() {
    let mut server = serve(vec![
        Reply::json(400, json!({"detail":"invalid"})).header("X-State-ID", "error-rotation"),
        Reply::json(
            200,
            json!({"metadata1":"sensitive", "send_at":0, "headers":{"Bad Header":"x"}}),
        )
        .header("X-Request-ID", "bad-header"),
        Reply::json(
            200,
            json!({"metadata1":"sensitive", "send_at":1e100, "headers":{}}),
        )
        .header("X-Request-ID", "bad-time"),
        Reply::json(200, json!({"send_at":0,"headers":{}})).header("X-Request-ID", "bad-body"),
        Reply::json(
            200,
            json!({"metadata1":"sensitive", "send_at":0,"headers":{}}),
        ),
    ])
    .await;
    let client = NullgateClient::builder(KEY)
        .amazon_base_url(&server.url)
        .build()
        .unwrap();
    let mut session = client.open(SessionOptions::new(ID, "UA")).unwrap();
    let params = params(&page("<form></form>"));
    assert!(matches!(session.fwcim(&params).await, Err(Error::Api(_))));
    assert_eq!(session.amazon_state_id(), Some("error-rotation"));
    for _ in 0..4 {
        assert!(matches!(
            session.fwcim(&params).await,
            Err(Error::Protocol(_))
        ));
    }
    for _ in 0..5 {
        server.requests.recv().await.unwrap();
    }
}

#[tokio::test]
async fn retries_only_definitive_prework_maintenance_and_keeps_state() {
    let mut server = serve(vec![
        maintenance("0"),
        Reply::json(503, json!({"detail":"unrelated body"}))
            .header("X-Nullgate-Maintenance", "1")
            .header("Retry-After", "0")
            .header("X-State-ID", "must-not-rotate"),
        generated(),
        maintenance("0"),
        maintenance("0"),
        maintenance("0"),
    ])
    .await;
    let client = NullgateClient::builder(KEY)
        .amazon_base_url(&server.url)
        .build()
        .unwrap();
    let mut session = client.open(SessionOptions::new(ID, "UA")).unwrap();
    let original = session.amazon_state_id().unwrap().to_owned();
    let params = params(&page("<form></form>"));
    session.fwcim(&params).await.unwrap();
    assert!(matches!(session.fwcim(&params).await, Err(Error::Api(_))));
    for _ in 0..6 {
        assert_eq!(
            server.requests.recv().await.unwrap().headers["x-state-id"],
            original
        );
    }
    assert_eq!(session.amazon_state_id(), Some(original.as_str()));
}

#[tokio::test]
async fn does_not_retry_generic_statuses_or_invalid_delays() {
    for reply in [
        Reply::json(503, json!({"detail":"busy"})).header("Retry-After", "0"),
        Reply::json(
            502,
            json!({"detail":"Service updating; retry after a short delay"}),
        )
        .header("Retry-After", "0"),
        Reply::json(
            503,
            json!({"detail":"Service updating; retry after a short delay"}),
        )
        .header("Retry-After", "0"),
        Reply::json(503, json!({"detail":"SERVICE_UPDATING"}))
            .header("X-Nullgate-Maintenance", "0")
            .header("Retry-After", "0"),
        maintenance("6"),
        maintenance("0").header("X-Nullgate-Maintenance", "0"),
        maintenance("0").header("Retry-After", "1"),
        maintenance("NaN"),
        maintenance("-1"),
        Reply::json(
            503,
            json!({"detail":"Service updating; retry after a short delay"}),
        ),
    ] {
        let mut server = serve(vec![reply]).await;
        let client = NullgateClient::builder(KEY)
            .amazon_base_url(&server.url)
            .build()
            .unwrap();
        let mut session = client.open(SessionOptions::new(ID, "UA")).unwrap();
        assert!(matches!(
            session.fwcim(&params(&page("<form></form>"))).await,
            Err(Error::Api(_))
        ));
        server.requests.recv().await.unwrap();
        assert!(server.requests.try_recv().is_err());
    }
}

#[tokio::test]
async fn client_close_cancels_maintenance_wait() {
    let mut server = serve(vec![maintenance("5")]).await;
    let client = NullgateClient::builder(KEY)
        .amazon_base_url(&server.url)
        .build()
        .unwrap();
    let mut session = client.open(SessionOptions::new(ID, "UA")).unwrap();
    let closer = client.clone();
    let params = params(&page("<form></form>"));
    let close = async {
        server.requests.recv().await.unwrap();
        closer.close().await.unwrap();
    };
    let (result, ()) = tokio::join!(session.fwcim(&params), close);
    assert!(matches!(result, Err(Error::Profile(_))));
    assert!(server.requests.try_recv().is_err());
    assert!(
        tokio::time::timeout(Duration::from_millis(10), session.fwcim(&params))
            .await
            .unwrap()
            .is_err()
    );
}

#[tokio::test]
async fn dropping_generation_future_does_not_retry_or_rotate() {
    let mut server = serve(vec![
        maintenance("0").delay(Duration::from_millis(50)),
        generated(),
    ])
    .await;
    let client = NullgateClient::builder(KEY)
        .amazon_base_url(&server.url)
        .build()
        .unwrap();
    let mut session = client.open(SessionOptions::new(ID, "UA")).unwrap();
    let original = session.amazon_state_id().unwrap().to_owned();
    let params = params(&page("<form></form>"));
    assert!(
        tokio::time::timeout(Duration::from_millis(10), session.fwcim(&params))
            .await
            .is_err()
    );
    assert_eq!(session.amazon_state_id(), Some(original.as_str()));
    session.fwcim(&params).await.unwrap();
    for _ in 0..2 {
        assert_eq!(
            server.requests.recv().await.unwrap().headers["x-state-id"],
            original
        );
    }
    assert!(server.requests.try_recv().is_err());
}

#[tokio::test]
async fn existing_generation_uses_same_narrow_maintenance_policy() {
    let mut server = serve(vec![
        maintenance("0"),
        Reply::json(
            200,
            json!({"sensor_data":"sensor", "send_at":0, "headers":{}}),
        )
        .header("X-Request-ID", "sensor"),
    ])
    .await;
    let client = NullgateClient::builder(KEY)
        .base_url(&server.url)
        .build()
        .unwrap();
    let mut session = client.open(SessionOptions::new(ID, "UA")).unwrap();
    let original = session.state_id().unwrap().to_owned();
    let page = page("<form></form>");
    session
        .solve(Params::Sensor(
            SensorParams::new(
                Sensor::new(page, "https://target.example/collect").unwrap(),
                "source",
            )
            .unwrap(),
        ))
        .await
        .unwrap();
    for _ in 0..2 {
        assert_eq!(
            server.requests.recv().await.unwrap().headers["x-state-id"],
            original
        );
    }
    assert_eq!(session.state_id(), Some(original.as_str()));
}

#[tokio::test]
async fn retains_nonmaintenance_rotation_before_body_failure_or_cancellation() {
    for (truncated, cancelled) in [(true, false), (false, false), (false, true)] {
        let mut reply =
            Reply::json(503, json!({"detail":"busy"})).header("X-State-ID", "early-rotation");
        if truncated {
            reply.body_length = Some(reply.body.len() + 10);
        } else {
            reply.body_delay = Duration::from_millis(100);
        }
        let mut server = serve(vec![reply, generated()]).await;
        let client = NullgateClient::builder(KEY)
            .amazon_base_url(&server.url)
            .timeout(Duration::from_millis(50))
            .build()
            .unwrap();
        let mut session = client.open(SessionOptions::new(ID, "UA")).unwrap();
        let params = params(&page("<form></form>"));
        if cancelled {
            assert!(
                tokio::time::timeout(Duration::from_millis(20), session.fwcim(&params))
                    .await
                    .is_err()
            );
        } else {
            assert!(session.fwcim(&params).await.is_err());
        }
        assert_eq!(session.amazon_state_id(), Some("early-rotation"));
        server.requests.recv().await.unwrap();
        // Let the delayed server finish its first response before the next call.
        tokio::time::sleep(Duration::from_millis(110)).await;
        session.fwcim(&params).await.unwrap();
        assert_eq!(
            server.requests.recv().await.unwrap().headers["x-state-id"],
            "early-rotation"
        );
    }
}

#[tokio::test]
async fn retries_marked_maintenance_without_waiting_for_its_body() {
    let mut reply = maintenance("0");
    reply.body_length = Some(reply.body.len() + 10);
    let mut server = serve(vec![reply, generated()]).await;
    let client = NullgateClient::builder(KEY)
        .amazon_base_url(&server.url)
        .build()
        .unwrap();
    let mut session = client.open(SessionOptions::new(ID, "UA")).unwrap();
    session
        .fwcim(&params(&page("<form></form>")))
        .await
        .unwrap();
    server.requests.recv().await.unwrap();
    server.requests.recv().await.unwrap();
}
