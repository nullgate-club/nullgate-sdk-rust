use std::collections::BTreeMap;

use nullgate_sdk::{
    Page, Protection, Sbsd,
    akamai::{abck_counters, is_enough, prepare_inputs},
    find_protections,
};

const VERSION: &str = "11111111-2222-4333-8444-555555555555";

#[test]
fn discovery_preserves_occurrences_queries_bases_and_ambiguous_challenges() {
    let html = format!(
        "<base href='/assets/'>\n<script>bazadebezolkohpepadr='0012';bazadebezolkohpepadr=\"34\";</script>\n<script src='/akam/13/aB09?x=a%2Fb+z&amp;x=two#ignored'></script>\n<script src='opaque?v={VERSION}&amp;t='></script>\n<script src='collector?raw=%2f&amp;second=+value'></script>\n<script src='collector?raw=%2f&amp;second=+value'></script>"
    );
    let page = Page::new("https://target.example/login/index", html).unwrap();
    let found = find_protections(&page);
    let pixels = found
        .iter()
        .filter_map(|p| match p {
            Protection::Pixel(p) => Some(p),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        pixels.iter().map(|p| p.challenge()).collect::<Vec<_>>(),
        ["0012", "34"]
    );
    assert_eq!(
        pixels[0].script_url().as_str(),
        "https://target.example/akam/13/aB09?x=a%2Fb+z&x=two"
    );
    let reference = pixels[0].provenance().unwrap();
    assert_eq!(
        reference.raw_source,
        "/akam/13/aB09?x=a%2Fb+z&x=two#ignored"
    );
    assert_eq!(
        (reference.tag_index, reference.line, reference.column),
        (1, 3, 0)
    );
    assert!(
        page.html()[pixels[0].challenge_offset().unwrap()..].starts_with("bazadebezolkohpepadr")
    );
    let sbsd = found
        .iter()
        .find_map(|p| match p {
            Protection::Sbsd(p) => Some(p),
            _ => None,
        })
        .unwrap();
    assert!(sbsd.blocking());
    assert_eq!(
        sbsd.script_url().as_str(),
        format!("https://target.example/assets/opaque?v={VERSION}&t=")
    );
    let sensors = found
        .iter()
        .filter_map(|p| match p {
            Protection::Sensor(p) => Some(p),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        sensors
            .iter()
            .map(|p| p.script_url().as_str())
            .collect::<Vec<_>>(),
        [
            "https://target.example/assets/collector?raw=%2f&second=+value",
            "https://target.example/assets/collector?raw=%2f&second=+value"
        ]
    );
    assert_ne!(sensors[0].provenance(), sensors[1].provenance());
}

#[test]
fn discovery_only_considers_active_same_origin_classic_scripts() {
    let html = "<!-- <script src='/comment'></script> -->\
        <template><script src='/template'></script></template>\
        <noscript><script src='/noscript'></script></noscript>\
        <script type='module' src='/module'></script>\
        <script nomodule src='/legacy'></script>\
        <script type='application/json'>bazadebezolkohpepadr='789';</script>\
        <script src='https://other.example/cross'></script>\
        <script src='http://target.example/insecure'></script>\
        <script src='https://target.example:8443/port'></script>\
        <script src='http://['></script><script src='javascript:ignored'></script>\
        <script src=''></script><SCRIPT TYPE='text/javascript' SRC='collector' src='https://other.example/duplicate'></SCRIPT>";
    for (base, expected) in [
        ("", Some("https://target.example/login/collector")),
        (
            "<base href='/resources/'>",
            Some("https://target.example/resources/collector"),
        ),
        (
            "<base href='http://['>",
            Some("https://target.example/login/collector"),
        ),
        (
            "<base href='javascript:ignored'>",
            Some("https://target.example/login/collector"),
        ),
        ("<base href='https://other.example/'>", None),
    ] {
        let found = find_protections(
            &Page::new("https://target.example/login/page", format!("{base}{html}")).unwrap(),
        );
        assert_eq!(
            found
                .iter()
                .map(|p| p.script_url().as_str())
                .collect::<Vec<_>>(),
            expected.into_iter().collect::<Vec<_>>()
        );
    }
}

#[test]
fn assets_and_ambiguous_sbsd_are_not_relabelled_as_sensors() {
    let page = Page::new("https://target.example/", format!("<script src='/app.js'></script><script src='/app.JS?x=2'></script><script src='/app.mjs'></script><script src='/app.cjs'></script><script src='/app%2Ejs'></script><script src='/duplicate?v={VERSION}&amp;v={VERSION}'></script><script src='/tokens?v={VERSION}&amp;t=one&amp;t=two'></script><script src='/akam/13/abc'></script>")).unwrap();
    assert!(find_protections(&page).is_empty());
}

#[test]
fn sbsd_uses_raw_query_presence_even_when_t_is_empty() {
    let page = Page::new("https://target.example/", "").unwrap();
    for suffix in ["t", "t=", "t=opaque%2Ftoken+part"] {
        assert!(
            Sbsd::new(
                page.clone(),
                &format!("https://target.example/s?v={VERSION}&{suffix}")
            )
            .unwrap()
            .blocking()
        );
    }
    for suffix in ["other=t", "%74=value", "T=value"] {
        assert!(
            !Sbsd::new(
                page.clone(),
                &format!("https://target.example/s?v={VERSION}&{suffix}")
            )
            .unwrap()
            .blocking()
        );
    }
}

#[test]
fn input_summaries_follow_javascript_utf16_and_whitespace_categories() {
    let prepared = prepare_inputs(&[
        BTreeMap::from([
            ("name".to_owned(), "password".to_owned()),
            ("value".to_owned(), "A_9 😀İ\u{a0}".to_owned()),
        ]),
        BTreeMap::from([("value".to_owned(), "\u{85}\u{feff}".to_owned())]),
        BTreeMap::from([("id".to_owned(), "empty".to_owned())]),
    ]);
    assert_eq!(
        prepared[0].attributes,
        BTreeMap::from([("name".to_owned(), "password".to_owned())])
    );
    assert_eq!(prepared[0].value.counts, [8, 3, 2, 1]);
    assert_eq!(
        prepared[0].value.hash,
        "552f5768ce4326ff5fd4e0ce8d1d3a8e76c17a04542eb14f91f64e5a09550510"
    );
    assert_eq!(prepared[1].value.counts, [2, 1, 0, 0]);
    assert_eq!(prepared[2].value.length, 0);
    assert_eq!(
        prepared[2].value.hash,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn cookie_gate_decodes_strictly_and_counts_responses_not_acceptance() {
    assert_eq!(
        abck_counters(Some("hash%7E%203tail%7Ex%7E%2B7more")),
        (3.0, 7.0)
    );
    assert!(!is_enough(Some("hash~3~x~7"), 2));
    assert!(is_enough(Some("hash~3~x~7"), 3));
    for value in [
        None,
        Some("broken"),
        Some("hash~3~x~7%"),
        Some("hash~3~x~7%FF"),
    ] {
        assert_eq!(abck_counters(value), (-1.0, -1.0));
        assert!(!is_enough(value, 100));
    }
    assert_eq!(
        abck_counters(Some("hash~9007199254740993~x~-2junk")),
        (9007199254740992.0, -2.0)
    );
    assert_eq!(abck_counters(Some("hash~not-a-limit~x~2")), (-1.0, 2.0));
    assert!(is_enough(Some("hash~0~x~2"), 0));
}
