use std::sync::LazyLock;

use html5gum::{DefaultEmitter, Token, Tokenizer, naive_next_state};
use percent_encoding::percent_decode_str;
use regex::Regex;
use uuid::Uuid;

use crate::protection::{Script, ThreatMetrixSource, is_threatmetrix_url};
use crate::{Error, Page, Pixel, Protection, Sbsd, ScriptReference, Sensor, ThreatMetrix};

static CHALLENGE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\bbazadebezolkohpepadr\s*=\s*(?:'([0-9]+)'|"([0-9]+)")"#)
        .expect("constant challenge pattern")
});
static PIXEL_PATH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^/akam/13/[0-9a-fA-F]+$").expect("constant pixel path pattern"));

/// Options for local protection discovery.
#[derive(Clone, Copy, Debug)]
pub struct FindOptions {
    /// Return an ambiguity error when more than one candidate is found.
    ///
    /// Defaults to `true`. This never causes a Rust panic.
    pub panic: bool,
}

impl Default for FindOptions {
    fn default() -> Self {
        Self { panic: true }
    }
}

/// Discover active classic scripts without fetching or executing code.
///
/// Returns an empty list for no match and a single-element list for one match.
/// More than one candidate returns [`Error::AmbiguousProtections`]. A sensor is
/// the extensionless-script heuristic, not a claim about source contents.
pub fn find_protections(page: &Page) -> Result<Vec<Protection>, Error> {
    find_protections_with_options(page, FindOptions::default())
}

/// Discover protections with explicit ambiguity handling.
///
/// With `FindOptions { panic: false }`, every source occurrence and distinct
/// pixel challenge pairing is retained, in document order, with its provenance.
/// Select the intended candidate using ordinary iterator operations.
pub fn find_protections_with_options(
    page: &Page,
    options: FindOptions,
) -> Result<Vec<Protection>, Error> {
    let found = collect_protections(page);
    if options.panic && found.len() > 1 {
        return Err(Error::AmbiguousProtections { count: found.len() });
    }
    Ok(found)
}

fn collect_protections(page: &Page) -> Vec<Protection> {
    let html = page.html();
    let mut line_offsets = vec![0];
    line_offsets.extend(html.match_indices('\n').map(|(offset, _)| offset + 1));
    let emitter = DefaultEmitter::<usize>::new_with_span();
    let mut tokens = Tokenizer::new_with_emitter(html, emitter);
    let mut sources = Vec::new();
    let mut challenges = Vec::new();
    let mut inert = Vec::new();
    let mut base = None;
    let mut inline_start = None;
    let mut script_index = 0;

    while let Some(Ok(token)) = tokens.next() {
        match token {
            Token::StartTag(tag) => {
                let name: &[u8] = &tag.name;
                let index = script_index;
                if name == b"script" {
                    script_index += 1;
                }
                // Match the finite Python discovery parser: noscript is inert, but
                // its contained tags still contribute to source occurrence indices.
                if !tag.self_closing
                    && name != b"noscript"
                    && let Some(state) = naive_next_state(name)
                {
                    tokens.set_state(state);
                }
                if !tag.self_closing && (name == b"template" || name == b"noscript") {
                    inert.push(tag.name.clone());
                }
                if !inert.is_empty() {
                    continue;
                }
                if name == b"base"
                    && base.is_none()
                    && let Some(href) = tag.attributes.get(b"href".as_slice())
                {
                    base = Some(String::from_utf8_lossy(&href.value).trim().to_owned());
                }
                if name != b"script" {
                    continue;
                }
                let script_type = tag
                    .attributes
                    .get(b"type".as_slice())
                    .map(|v| {
                        String::from_utf8_lossy(&v.value)
                            .trim()
                            .to_ascii_lowercase()
                    })
                    .unwrap_or_default();
                let classic = !tag.attributes.contains_key(b"nomodule".as_slice())
                    && matches!(
                        script_type.as_str(),
                        "" | "text/javascript" | "application/javascript"
                    );
                inline_start = if classic
                    && !tag.self_closing
                    && !tag.attributes.contains_key(b"src".as_slice())
                {
                    Some(tag.span.end)
                } else {
                    None
                };
                if !classic {
                    continue;
                }
                if let Some(source) = tag.attributes.get(b"src".as_slice()) {
                    let raw_source = String::from_utf8_lossy(&source.value).trim().to_owned();
                    if raw_source.is_empty() {
                        continue;
                    }
                    let line = line_offsets.partition_point(|offset| *offset <= tag.span.start);
                    let column = html[line_offsets[line - 1]..tag.span.start].chars().count();
                    sources.push(ScriptReference {
                        raw_source,
                        tag_index: index,
                        line,
                        column,
                    });
                }
            }
            Token::EndTag(tag) => {
                if tag.name.as_ref() == b"script"
                    && let Some(start) = inline_start.take()
                {
                    collect_challenges(html, start, tag.span.start, &mut challenges);
                }
                if inert.last().is_some_and(|name| name == &tag.name) {
                    inert.pop();
                }
            }
            _ => {}
        }
    }
    if let Some(start) = inline_start {
        collect_challenges(html, start, html.len(), &mut challenges);
    }

    let base = base
        .as_deref()
        .and_then(|value| page.url().join(value).ok())
        .filter(|url| matches!(url.scheme(), "http" | "https"))
        .unwrap_or_else(|| page.url().clone());
    let mut found = Vec::new();
    for reference in sources {
        let Ok(mut url) = base.join(&reference.raw_source) else {
            continue;
        };
        url.set_fragment(None);
        if is_threatmetrix_url(&url) {
            found.push(Protection::ThreatMetrix(ThreatMetrix {
                script: Script {
                    page: page.clone(),
                    url,
                    provenance: Some(reference),
                },
                source: ThreatMetrixSource::Tags,
            }));
            continue;
        }
        if url.origin() != page.url().origin() {
            continue;
        }
        let path = percent_decode_str(url.path()).decode_utf8_lossy();
        let pixel = PIXEL_PATH.is_match(&path);
        let sensor = !path.is_empty()
            && ![".js", ".mjs", ".cjs"].iter().any(|suffix| {
                path.get(path.len().saturating_sub(suffix.len())..)
                    .is_some_and(|ending| ending.eq_ignore_ascii_case(suffix))
            });
        let mut version_count = 0;
        let mut token_count = 0;
        let mut has_version = false;
        for part in url.query().unwrap_or("").split('&') {
            let (name, value) = part.split_once('=').unwrap_or((part, ""));
            if name == "v" {
                version_count += 1;
                has_version |= value.len() == 36 && Uuid::parse_str(value).is_ok();
            } else if name == "t" {
                token_count += 1;
            }
        }
        let unambiguous = version_count == 1 && token_count <= 1;
        let script = Script {
            page: page.clone(),
            url,
            provenance: Some(reference),
        };
        if pixel {
            for (challenge, offset) in &challenges {
                found.push(Protection::Pixel(Pixel {
                    script: script.clone(),
                    challenge: challenge.clone(),
                    challenge_offset: Some(*offset),
                }));
            }
        } else if has_version {
            if unambiguous {
                found.push(Protection::Sbsd(Sbsd { script }));
            }
        } else if sensor {
            found.push(Protection::Sensor(Sensor { script }));
        }
    }
    found
}

fn collect_challenges(html: &str, start: usize, end: usize, found: &mut Vec<(String, usize)>) {
    for captures in CHALLENGE.captures_iter(&html[start..end]) {
        let value = captures
            .get(1)
            .or_else(|| captures.get(2))
            .expect("one challenge capture")
            .as_str();
        if !found.iter().any(|(existing, _)| existing == value) {
            found.push((
                value.to_owned(),
                start + captures.get(0).expect("full match").start(),
            ));
        }
    }
}
