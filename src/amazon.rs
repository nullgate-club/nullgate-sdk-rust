use std::{
    collections::BTreeMap,
    fmt,
    time::{Duration, UNIX_EPOCH},
};

use html5gum::{
    Span, Tokenizer,
    emitters::callback::{CallbackEmitter, CallbackEvent},
};
use scraper::{ElementRef, Html, Selector};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::{
    Error, Page, ProtocolError,
    akamai::{InputValue, summarize_input},
};

/// Actual caller-observed field bounds. No geometry is synthesized.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct FwcimGeometry {
    /// Left coordinate in CSS pixels.
    pub left: f64,
    /// Top coordinate in CSS pixels.
    pub top: f64,
    /// Nonnegative observed width.
    pub width: f64,
    /// Nonnegative observed height.
    pub height: f64,
}

/// A locally checked nonpassword observation; raw text is opt-in only.
#[derive(Clone, Serialize)]
pub struct FwcimInput {
    attributes: BTreeMap<String, String>,
    value: InputValue,
    checksum: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    selector: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    geometry: Option<FwcimGeometry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<String>,
    #[serde(skip)]
    page: Page,
}

impl FwcimInput {
    /// Match exactly one input/textarea in `page`, confirming any id/name.
    /// Password controls are rejected without retaining or echoing `value`.
    /// `canvas_text` explicitly opts into transmitting this nonpassword text.
    pub fn new(
        page: &Page,
        attributes: BTreeMap<String, String>,
        selector: Option<&str>,
        value: &str,
        canvas_text: bool,
    ) -> Result<Self, Error> {
        if attributes
            .keys()
            .any(|key| !matches!(key.as_str(), "id" | "name"))
        {
            return Err(Error::Configuration(
                "Amazon input attributes support only id/name",
            ));
        }
        let html = checked_html(page)?;
        let selector_query = Selector::parse(selector.unwrap_or("input, textarea"))
            .map_err(|_| Error::Configuration("invalid Amazon input selector"))?;
        let mut matches = html
            .select(&selector_query)
            .filter(active_element)
            .filter(|node| {
                matches!(node.value().name(), "input" | "textarea")
                    && attributes.iter().all(|(name, value)| {
                        node.value().attr(name.as_str()) == Some(value.as_str())
                    })
            });
        // A selector must be unambiguous on its own, before id/name confirmation.
        if selector.is_some() && html.select(&selector_query).filter(active_element).count() != 1 {
            return Err(Error::Configuration(
                "Amazon input selector must match exactly one control",
            ));
        }
        let node = matches.next().ok_or(Error::Configuration(
            "Amazon input does not match a control",
        ))?;
        if matches.next().is_some() || (selector.is_none() && attributes.is_empty()) {
            return Err(Error::Configuration("Amazon input identity is ambiguous"));
        }
        if sensitive_control(node) {
            return Err(Error::Configuration(
                "password input observations are not accepted",
            ));
        }
        let summary = summarize_input(value);
        Ok(Self {
            attributes,
            value: summary,
            checksum: crc32_cesu8(value),
            selector: selector.map(str::to_owned),
            geometry: None,
            text: canvas_text.then(|| value.to_owned()),
            page: page.clone(),
        })
    }

    /// Attach finite, actual field bounds; negative sizes are rejected.
    pub fn geometry(mut self, geometry: FwcimGeometry) -> Result<Self, Error> {
        if ![geometry.left, geometry.top, geometry.width, geometry.height]
            .into_iter()
            .all(f64::is_finite)
            || geometry.width < 0.0
            || geometry.height < 0.0
        {
            return Err(Error::Configuration(
                "Amazon geometry must be finite with nonnegative sizes",
            ));
        }
        self.geometry = Some(geometry);
        Ok(self)
    }
}

impl fmt::Debug for FwcimInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FwcimInput").finish_non_exhaustive()
    }
}

/// FWCIM observations for one caller-owned document. No script is accepted.
#[derive(Clone)]
pub struct FwcimParams {
    page: Page,
    cookies: Option<BTreeMap<String, String>>,
    form_selector: Option<String>,
    inputs: Option<Vec<FwcimInput>>,
    actions: Option<Vec<Map<String, Value>>>,
    submitted: bool,
    referrer: String,
    history_length: Option<u64>,
    performance_timing: BTreeMap<String, u64>,
}

impl FwcimParams {
    /// Require observed navigation timings, aligned with the Page start timestamp.
    /// Unknown timing fields are left to the service's validation.
    pub fn new(page: Page, performance_timing: BTreeMap<String, u64>) -> Result<Self, Error> {
        checked_html(&page)?;
        if page.started_at_ms() == 0
            || performance_timing.get("navigationStart") != Some(&page.started_at_ms())
        {
            return Err(Error::Configuration(
                "performance_timing.navigationStart must match Page start",
            ));
        }
        if performance_timing
            .values()
            .any(|&value| value != 0 && value < page.started_at_ms())
        {
            return Err(Error::Configuration(
                "nonzero performance timings must not precede navigationStart",
            ));
        }
        Ok(Self {
            page,
            performance_timing,
            cookies: None,
            form_selector: None,
            inputs: None,
            actions: None,
            submitted: true,
            referrer: String::new(),
            history_length: None,
        })
    }

    /// Supply the current caller-owned target cookie snapshot.
    pub fn cookies(mut self, value: BTreeMap<String, String>) -> Self {
        self.cookies = Some(value);
        self
    }

    /// Identify the actual form using a CSS selector.
    pub fn form_selector(mut self, value: impl Into<String>) -> Result<Self, Error> {
        let value = value.into();
        check_form(&self.page, &value, self.inputs.as_deref())?;
        self.form_selector = Some(value);
        Ok(self)
    }

    /// Preserve absence versus an explicitly empty observation list.
    pub fn inputs(mut self, value: Vec<FwcimInput>) -> Result<Self, Error> {
        if value.iter().any(|input| {
            input.page.document_id() != self.page.document_id()
                || input.page.html() != self.page.html()
                || input.page.url() != self.page.url()
                || input.page.started_at_ms() != self.page.started_at_ms()
        }) {
            return Err(Error::Configuration(
                "Amazon input belongs to a different Page",
            ));
        }
        if let Some(selector) = &self.form_selector {
            check_form(&self.page, selector, Some(&value))?;
        }
        self.inputs = Some(value);
        Ok(self)
    }

    /// Accept caller activity only; raw values and unsupported action fields are rejected.
    pub fn actions(mut self, value: Vec<Map<String, Value>>) -> Result<Self, Error> {
        if value.iter().any(|action| !valid_action(action)) {
            return Err(Error::Configuration(
                "Amazon actions contain invalid fields or raw input text",
            ));
        }
        self.actions = Some(value);
        Ok(self)
    }

    /// Whether the caller is submitting the form; defaults to true.
    pub fn submitted(mut self, value: bool) -> Self {
        self.submitted = value;
        self
    }
    /// Actual document referrer; no navigation is inferred.
    pub fn referrer(mut self, value: impl Into<String>) -> Self {
        self.referrer = value.into();
        self
    }
    /// Actual browser history length, at least one.
    pub fn history_length(mut self, value: u64) -> Result<Self, Error> {
        if value == 0 {
            return Err(Error::Configuration("history length must be at least one"));
        }
        self.history_length = Some(value);
        Ok(self)
    }

    pub(crate) fn payload<'a>(&'a self, timezone: Option<&'a str>) -> Payload<'a> {
        Payload {
            website: Website {
                url: self.page.url().as_str(),
                html: self.page.html(),
                document_id: self.page.document_id(),
                started_at_ms: self.page.started_at_ms(),
                referrer: &self.referrer,
                history_length: self.history_length,
            },
            timezone,
            cookies: self.cookies.as_ref(),
            form_selector: self.form_selector.as_deref(),
            inputs: self.inputs.as_deref(),
            actions: self.actions.as_deref(),
            submitted: self.submitted,
            performance_timing: &self.performance_timing,
        }
    }
}

impl fmt::Debug for FwcimParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FwcimParams")
            .field("page", &self.page)
            .finish_non_exhaustive()
    }
}

#[derive(Serialize)]
pub(crate) struct Payload<'a> {
    website: Website<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    timezone: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cookies: Option<&'a BTreeMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    form_selector: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    inputs: Option<&'a [FwcimInput]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    actions: Option<&'a [Map<String, Value>]>,
    submitted: bool,
    performance_timing: &'a BTreeMap<String, u64>,
}

#[derive(Serialize)]
struct Website<'a> {
    url: &'a str,
    html: &'a str,
    document_id: Uuid,
    started_at_ms: u64,
    referrer: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    history_length: Option<u64>,
}

fn valid_action(action: &Map<String, Value>) -> bool {
    action.iter().all(|(key, value)| match key.as_str() {
        "type" | "target_path" | "pointer_type" => value.is_string(),
        "target" => value.is_null() || value.is_i64() || value.is_u64(),
        "trusted" | "shift" | "ctrl" | "alt" | "meta" | "absolute" => {
            value.is_null() || value.is_boolean()
        }
        "time" | "x" | "y" | "button" | "which" | "pointer_id" | "key_code" | "char_code"
        | "alpha" | "beta" | "gamma" | "interval" => nullable_number(value),
        "touches" => value
            .as_array()
            .is_some_and(|points| points.iter().all(valid_touch)),
        "acceleration" | "acceleration_with_gravity" | "rotation_rate" => {
            value.is_null()
                || value
                    .as_array()
                    .is_some_and(|vector| vector.len() == 3 && vector.iter().all(nullable_number))
        }
        "input_summary" => value.as_array().is_some_and(|summary| {
            summary.len() == 2
                && summary[0].is_u64()
                && (summary[1].is_null()
                    || summary[1].as_array().is_some_and(|counts| {
                        counts.len() == 4 && counts.iter().all(Value::is_u64)
                    }))
        }),
        _ => false,
    })
}

fn nullable_number(value: &Value) -> bool {
    value.is_null() || value.as_f64().is_some_and(f64::is_finite)
}

fn valid_touch(value: &Value) -> bool {
    value.as_object().is_some_and(|point| {
        ["x", "y"].iter().all(|key| {
            point
                .get(*key)
                .is_some_and(|value| value.as_f64().is_some_and(f64::is_finite))
        }) && point.iter().all(|(key, value)| match key.as_str() {
            "x" | "y" => true,
            "identifier" => value.is_i64() || value.is_u64(),
            _ => false,
        })
    })
}

fn active_element(node: &ElementRef<'_>) -> bool {
    // Native selectors cannot traverse a template's separate content fragment.
    !node
        .ancestors()
        .filter_map(ElementRef::wrap)
        .any(|parent| parent.value().name() == "template")
}

fn check_form(page: &Page, selector: &str, inputs: Option<&[FwcimInput]>) -> Result<(), Error> {
    let html = checked_html(page)?;
    let selector = Selector::parse(selector)
        .map_err(|_| Error::Configuration("invalid Amazon form selector"))?;
    let mut forms = html.select(&selector).filter(active_element);
    let form = forms.next().ok_or(Error::Configuration(
        "Amazon form selector must select exactly one FORM",
    ))?;
    if form.value().name() != "form" || forms.next().is_some() {
        return Err(Error::Configuration(
            "Amazon form selector must select exactly one FORM",
        ));
    }
    for input in inputs.unwrap_or_default() {
        let selector = Selector::parse(input.selector.as_deref().unwrap_or("input, textarea"))
            .map_err(|_| Error::Configuration("invalid Amazon input selector"))?;
        let node = html.select(&selector).filter(active_element).find(|node| {
            matches!(node.value().name(), "input" | "textarea")
                && input
                    .attributes
                    .iter()
                    .all(|(name, value)| node.value().attr(name.as_str()) == Some(value.as_str()))
        });
        if !node.is_some_and(|node| node.ancestors().any(|parent| parent.id() == form.id())) {
            return Err(Error::Configuration(
                "Amazon input does not belong to the selected form",
            ));
        }
    }
    Ok(())
}

fn sensitive_control(node: ElementRef<'_>) -> bool {
    let element = node.value();
    element
        .attr("type")
        .is_some_and(|kind| kind.trim().eq_ignore_ascii_case("password"))
        || element.attr("autocomplete").is_some_and(|value| {
            value.split_ascii_whitespace().any(|token| {
                token.eq_ignore_ascii_case("current-password")
                    || token.eq_ignore_ascii_case("new-password")
            })
        })
        || ["id", "name"].iter().any(|key| {
            element.attr(key).is_some_and(|value| {
                let value = value.trim();
                value.eq_ignore_ascii_case("password") || value.eq_ignore_ascii_case("ap_password")
            })
        })
}

fn raw_password_value(html: &str) -> bool {
    let mut control = false;
    let mut textarea = false;
    let mut attribute = 0_u8;
    let mut sensitive = false;
    let mut populated = false;
    let mut emitter = CallbackEmitter::new(|event: CallbackEvent<'_>, _: Span<()>| -> Option<()> {
        match event {
            CallbackEvent::OpenStartTag { name } => {
                control = name == b"input" || name == b"textarea";
                textarea = name == b"textarea";
                sensitive = false;
                populated = false;
            }
            CallbackEvent::AttributeName { name } => {
                attribute = match name {
                    b"value" => 1,
                    b"type" => 2,
                    b"autocomplete" => 3,
                    b"id" | b"name" => 4,
                    _ => 0,
                };
            }
            CallbackEvent::AttributeValue { value } if control => {
                let text = std::str::from_utf8(value).unwrap_or("").trim();
                match attribute {
                    1 => populated |= !value.is_empty(),
                    2 => sensitive |= text.eq_ignore_ascii_case("password"),
                    3 => {
                        sensitive |= text.split_ascii_whitespace().any(|token| {
                            token.eq_ignore_ascii_case("current-password")
                                || token.eq_ignore_ascii_case("new-password")
                        });
                    }
                    4 => {
                        sensitive |= text.eq_ignore_ascii_case("password")
                            || text.eq_ignore_ascii_case("ap_password");
                    }
                    _ => {}
                }
            }
            CallbackEvent::CloseStartTag { .. } if control && sensitive && populated => {
                return Some(());
            }
            CallbackEvent::String { value } if textarea && sensitive && !value.is_empty() => {
                return Some(());
            }
            CallbackEvent::EndTag { .. } => {
                control = false;
                textarea = false;
            }
            _ => {}
        }
        None
    });
    // Attribute callbacks retain duplicate values that DOM parsers discard.
    emitter.naively_switch_states(true);
    Tokenizer::new_with_emitter(html, emitter).any(|event| event.is_ok())
}

fn checked_html(page: &Page) -> Result<Html, Error> {
    if raw_password_value(page.html()) {
        return Err(Error::Configuration(
            "Page HTML must not contain password values",
        ));
    }
    let html = Html::parse_document(page.html());
    let controls = Selector::parse("input, textarea").expect("constant selector");
    if html.select(&controls).any(|node| {
        sensitive_control(node)
            && (node
                .value()
                .attr("value")
                .is_some_and(|value| !value.is_empty())
                || (node.value().name() == "textarea" && node.text().any(|text| !text.is_empty())))
    }) {
        return Err(Error::Configuration(
            "Page HTML must not contain password values",
        ));
    }
    Ok(html)
}

// Standard CRC32 over CESU-8: supplementary characters are two UTF-16 units.
fn crc32_cesu8(value: &str) -> u32 {
    let mut crc = !0_u32;
    for unit in value.encode_utf16() {
        let mut bytes = [0_u8; 3];
        let count = if unit < 0x80 {
            bytes[0] = unit as u8;
            1
        } else if unit < 0x800 {
            bytes[0] = 0xc0 | (unit >> 6) as u8;
            bytes[1] = 0x80 | (unit & 63) as u8;
            2
        } else {
            bytes[0] = 0xe0 | (unit >> 12) as u8;
            bytes[1] = 0x80 | ((unit >> 6) & 63) as u8;
            bytes[2] = 0x80 | (unit & 63) as u8;
            3
        };
        for byte in &bytes[..count] {
            crc ^= u32::from(*byte);
            for _ in 0..8 {
                crc = (crc >> 1) ^ (0xedb8_8320 & 0_u32.wrapping_sub(crc & 1));
            }
        }
    }
    !crc
}

/// Sensitive metadata to insert into the caller's form, not a complete login POST.
#[derive(Clone)]
pub struct FwcimSolution {
    metadata1: String,
    send_at: f64,
    headers: BTreeMap<String, String>,
    request_id: String,
}

#[derive(Deserialize)]
struct Generated {
    metadata1: String,
    send_at: f64,
    headers: BTreeMap<String, String>,
}

impl FwcimSolution {
    pub(crate) fn from_response(bytes: &[u8], request_id: String) -> Result<Self, Error> {
        let protocol =
            |message| Error::Protocol(ProtocolError::new(message, Some(request_id.clone())));
        let generated: Generated = serde_json::from_slice(bytes)
            .map_err(|_| protocol("malformed FWCIM JSON or required fields"))?;
        let duration = Duration::try_from_secs_f64(generated.send_at.max(0.0))
            .map_err(|_| protocol("send_at must be a finite representable Unix timestamp"))?;
        if !generated.send_at.is_finite() || UNIX_EPOCH.checked_add(duration).is_none() {
            return Err(protocol(
                "send_at must be a finite representable Unix timestamp",
            ));
        }
        for (name, value) in &generated.headers {
            reqwest::header::HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| protocol("invalid target header name"))?;
            reqwest::header::HeaderValue::from_str(value)
                .map_err(|_| protocol("invalid target header value"))?;
        }
        Ok(Self {
            metadata1: generated.metadata1,
            send_at: generated.send_at,
            headers: generated.headers,
            request_id,
        })
    }
    /// Raw field value. Insert it and URL-encode the whole form exactly once.
    pub fn metadata1(&self) -> &str {
        &self.metadata1
    }
    /// Earliest form submission time in Unix seconds.
    pub fn send_at(&self) -> f64 {
        self.send_at
    }
    /// Service-supplied target headers.
    pub fn headers(&self) -> &BTreeMap<String, String> {
        &self.headers
    }
    /// Actual generation response request ID.
    pub fn request_id(&self) -> &str {
        &self.request_id
    }
    /// Wait until send_at; dropping the future cancels the wait.
    pub async fn wait(&self) -> Result<(), Error> {
        crate::solution::wait_until(self.send_at, &self.request_id).await
    }
}

impl fmt::Debug for FwcimSolution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FwcimSolution")
            .field("send_at", &self.send_at)
            .field("request_id", &self.request_id)
            .finish_non_exhaustive()
    }
}
