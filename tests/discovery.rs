use std::collections::BTreeMap;

use nullgate_sdk::{
    Error, FindOptions, Page, Protection, Sbsd,
    akamai::{abck_counters, is_enough, prepare_inputs},
    find_protections, find_protections_with_options,
};

const VERSION: &str = "11111111-2222-4333-8444-555555555555";

#[test]
fn discovery_preserves_occurrences_queries_bases_and_ambiguous_challenges() {
    let html = format!(
        "<base href='/assets/'>\n<script>bazadebezolkohpepadr='0012';bazadebezolkohpepadr=\"34\";</script>\n<script src='/akam/13/aB09?x=a%2Fb+z&amp;x=two#ignored'></script>\n<script src='opaque?v={VERSION}&amp;t='></script>\n<script src='collector?raw=%2f&amp;second=+value'></script>\n<script src='collector?raw=%2f&amp;second=+value'></script>"
    );
    let page = Page::new("https://target.example/login/index", html).unwrap();
    let found = find_protections_with_options(&page, FindOptions { panic: false }).unwrap();
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
        )
        .unwrap();
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
    assert!(find_protections(&page).unwrap().is_empty());
}

#[test]
fn discovery_rejects_multiple_candidates_without_selecting_or_deduplicating() {
    for html in [
        "<script src='/same'></script><script src='/same'></script>".to_owned(),
        "<script src='/one'></script><script src='/two'></script>".to_owned(),
        format!("<script src='/sensor'></script><script src='/sbsd?v={VERSION}'></script>"),
        "<script>bazadebezolkohpepadr='12';bazadebezolkohpepadr='34';</script>\
         <script src='/akam/13/abc'></script>"
            .to_owned(),
    ] {
        let page = Page::new("https://target.example/", html).unwrap();
        assert!(matches!(
            find_protections(&page),
            Err(Error::AmbiguousProtections { count: 2 })
        ));
        assert!(matches!(
            find_protections_with_options(&page, FindOptions::default()),
            Err(Error::AmbiguousProtections { count: 2 })
        ));
    }
}

#[test]
fn threatmetrix_cross_origin_detection_preserves_document_and_provider_ambiguity() {
    let page = Page::new(
        "https://target.example/login",
        "<script src='https://signals.example/fp/tags.js?org_id=org&amp;session_id=session%2Fone'></script>\
         <script src='/collector'></script>",
    ).unwrap();
    assert!(matches!(
        find_protections(&page),
        Err(Error::AmbiguousProtections { count: 2 })
    ));
    let found = find_protections_with_options(&page, FindOptions { panic: false }).unwrap();
    let Protection::ThreatMetrix(protection) = &found[0] else {
        panic!("expected TMX protection");
    };
    assert_eq!(protection.page().document_id(), page.document_id());
    assert_eq!(protection.page().started_at_ms(), page.started_at_ms());
    assert_eq!(
        protection.tags_url().unwrap().as_str(),
        "https://signals.example/fp/tags.js?org_id=org&session_id=session%2Fone"
    );
    assert_eq!(protection.provenance().unwrap().tag_index, 0);
    assert!(matches!(found[1], Protection::Sensor(_)));
}

#[test]
fn threatmetrix_requires_single_nonempty_source_ids_without_site_allowlist() {
    for query in [
        "org_id=org",
        "session_id=session",
        "org_id=&session_id=session",
        "org_id=org&session_id=",
        "org_id=org&org_id=other&session_id=session",
        "org_id=org&session_id=session&session_id=other",
    ] {
        let page = Page::new(
            "https://target.example/",
            format!("<script src='https://any.example/tags.js?{query}'></script>"),
        )
        .unwrap();
        assert!(find_protections(&page).unwrap().is_empty(), "{query}");
    }
    let page = Page::new(
        "https://target.example/",
        "<script src='//any.example/tags.js?org_id=org&amp;session_id=session'></script>",
    )
    .unwrap();
    assert!(matches!(
        find_protections(&page).unwrap().as_slice(),
        [Protection::ThreatMetrix(_)]
    ));
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
fn input_hash_facts_match_ecmascript_trim_and_utf16() {
    // Expected facts come from native String.trim, charCodeAt and Math.imul.
    let cases = [
        ("", 0, 0, 0),
        ("A_9 😀İ\u{a0}", -902_761_640, 386_520_648, 7),
        ("\u{85}\u{feff}", 69_402, 133, 1),
        (
            "\u{feff}\u{a0}😀 \u{85}\tX\u{3000}\u{feff}",
            -2_113_306_057,
            927_999_095,
            6,
        ),
        (
            concat!(
                "\t\n\u{b}\u{c}\r \u{a0}\u{1680}\u{2000}\u{2001}\u{2002}",
                "\u{2003}\u{2004}\u{2005}\u{2006}\u{2007}\u{2008}\u{2009}",
                "\u{200a}\u{2028}\u{2029}\u{202f}\u{205f}\u{3000}\u{feff}",
            ),
            -1_202_517_248,
            0,
            0,
        ),
        (" \0 ", 30_784, 0, 1),
        ("\u{180e}x\u{200b}", 5_929_761, 5_929_761, 3),
        (
            "abcdefghijklmnopqrstuvwxyz😀",
            1_546_828_752,
            1_546_828_752,
            28,
        ),
        ("\u{85} x \u{85}", 123_898_050, 123_898_050, 5),
    ];
    for (index, (value, hash31, trimmed_hash31, trimmed_length)) in cases.into_iter().enumerate() {
        let prepared = prepare_inputs(&[BTreeMap::from([("value".to_owned(), value.to_owned())])]);
        let summary = &prepared[0].value;
        assert_eq!(
            (
                summary.hash31,
                summary.trimmed_hash31,
                summary.trimmed_length
            ),
            (Some(hash31), Some(trimmed_hash31), Some(trimmed_length)),
            "JavaScript case {index}"
        );
    }
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
