use std::{collections::BTreeMap, fmt, sync::Arc};

use serde::Serialize;
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::{
    Error, Page, Pixel, Sbsd, Sensor,
    akamai::{PreparedInput, prepare_inputs},
};

/// Pixel source paired only with a pixel protection.
///
/// The compiler rejects a different concrete protection:
///
/// ```compile_fail
/// fn cannot_mix(sensor: nullgate_sdk::Sensor) {
///     let _ = nullgate_sdk::PixelParams::new(sensor, "script source");
/// }
/// ```
#[derive(Clone)]
pub struct PixelParams {
    pub(crate) protection: Pixel,
    script: Arc<str>,
}

impl PixelParams {
    /// Retain the raw script text; its URL and challenge belong to the protection.
    pub fn new(protection: Pixel, script: impl Into<Arc<str>>) -> Result<Self, Error> {
        Ok(Self {
            protection,
            script: script_text(script)?,
        })
    }
}

/// Sensor source, current target cookies, and explicitly supplied activity.
#[derive(Clone)]
pub struct SensorParams {
    pub(crate) protection: Sensor,
    script: Arc<str>,
    cookies: BTreeMap<String, String>,
    inputs: Option<Vec<PreparedInput>>,
    actions: Option<Vec<Map<String, Value>>>,
}

impl SensorParams {
    /// Construct with empty cookies and absent inputs/actions (service continuation).
    pub fn new(protection: Sensor, script: impl Into<Arc<str>>) -> Result<Self, Error> {
        Ok(Self {
            protection,
            script: script_text(script)?,
            cookies: BTreeMap::new(),
            inputs: None,
            actions: None,
        })
    }

    /// Set the caller's current target cookie snapshot, not a browser cookie store.
    pub fn cookies(mut self, cookies: BTreeMap<String, String>) -> Self {
        self.cookies = cookies;
        self
    }

    /// Summarize raw values locally now. An empty list explicitly clears inputs.
    pub fn inputs(mut self, inputs: Vec<BTreeMap<String, String>>) -> Self {
        self.inputs = Some(prepare_inputs(&inputs));
        self
    }

    /// Set actual caller-supplied actions. Empty and absent remain distinct.
    ///
    /// Input/change values must be prepared summaries, not raw strings.
    pub fn actions(mut self, actions: Vec<Map<String, Value>>) -> Result<Self, Error> {
        validate_actions(&actions)?;
        self.actions = Some(actions);
        Ok(self)
    }
}

pub(crate) fn validate_actions(actions: &[Map<String, Value>]) -> Result<(), Error> {
    for action in actions {
        if matches!(
            action.get("type").and_then(Value::as_str),
            Some("input" | "change")
        ) && action.get("value").is_some_and(Value::is_string)
        {
            return Err(Error::Configuration(
                "input/change action values must be prepared summaries, not raw strings",
            ));
        }
    }
    Ok(())
}

/// SBSD source paired only with an SBSD protection.
#[derive(Clone)]
pub struct SbsdParams {
    pub(crate) protection: Sbsd,
    script: Arc<str>,
    cookies: BTreeMap<String, String>,
}

impl SbsdParams {
    /// Retain the raw script text and the concrete SBSD protection.
    pub fn new(protection: Sbsd, script: impl Into<Arc<str>>) -> Result<Self, Error> {
        Ok(Self {
            protection,
            script: script_text(script)?,
            cookies: BTreeMap::new(),
        })
    }

    /// Set current target cookies.
    pub fn cookies(mut self, cookies: BTreeMap<String, String>) -> Self {
        self.cookies = cookies;
        self
    }
}

/// Typed dispatch for the three actually supported generation operations.
///
/// Concrete constructors prevent pairing sensor parameters with a pixel:
///
/// ```compile_fail
/// use nullgate_sdk::{Page, Pixel, SensorParams};
/// let page = Page::new("https://target.example/", "").unwrap();
/// let pixel = Pixel::new(page, "https://target.example/akam/13/abc", "123").unwrap();
/// let wrong = SensorParams::new(pixel, "source");
/// ```
#[derive(Clone, Debug)]
pub enum Params {
    /// Pixel generation (`type=pixel`).
    Pixel(PixelParams),
    /// Sensor generation (`type=akamai`).
    Sensor(SensorParams),
    /// SBSD generation (`type=sbsd`).
    Sbsd(SbsdParams),
}

impl fmt::Debug for PixelParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PixelParams")
            .field("protection", &self.protection)
            .finish_non_exhaustive()
    }
}
impl fmt::Debug for SensorParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SensorParams")
            .field("protection", &self.protection)
            .finish_non_exhaustive()
    }
}
impl fmt::Debug for SbsdParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SbsdParams")
            .field("protection", &self.protection)
            .finish_non_exhaustive()
    }
}

#[derive(Serialize)]
pub(crate) struct Payload<'a> {
    website: Website<'a>,
    script: Script<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    timezone: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    challenge: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cookies: Option<&'a BTreeMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    inputs: Option<&'a [PreparedInput]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    actions: Option<&'a [Map<String, Value>]>,
}

#[derive(Serialize)]
struct Website<'a> {
    url: &'a str,
    html: &'a str,
    document_id: Uuid,
    started_at_ms: u64,
}
#[derive(Serialize)]
struct Script<'a> {
    source: &'a str,
    text: &'a str,
}

impl Params {
    pub(crate) fn operation(&self) -> &'static str {
        match self {
            Self::Pixel(_) => "pixel",
            Self::Sensor(_) => "akamai",
            Self::Sbsd(_) => "sbsd",
        }
    }

    pub(crate) fn page(&self) -> &Page {
        match self {
            Self::Pixel(p) => p.protection.page(),
            Self::Sensor(p) => p.protection.page(),
            Self::Sbsd(p) => p.protection.page(),
        }
    }

    pub(crate) fn script_url(&self) -> &url::Url {
        match self {
            Self::Pixel(p) => p.protection.script_url(),
            Self::Sensor(p) => p.protection.script_url(),
            Self::Sbsd(p) => p.protection.script_url(),
        }
    }

    pub(crate) fn payload<'a>(&'a self, timezone: Option<&'a str>) -> Payload<'a> {
        let (script, challenge, cookies, inputs, actions) = match self {
            Self::Pixel(p) => (&p.script, Some(p.protection.challenge()), None, None, None),
            Self::Sensor(p) => (
                &p.script,
                None,
                Some(&p.cookies),
                p.inputs.as_deref(),
                p.actions.as_deref(),
            ),
            Self::Sbsd(p) => (&p.script, None, Some(&p.cookies), None, None),
        };
        Payload {
            website: Website {
                url: self.page().url().as_str(),
                html: self.page().html(),
                document_id: self.page().document_id(),
                started_at_ms: self.page().started_at_ms(),
            },
            script: Script {
                source: self.script_url().as_str(),
                text: script,
            },
            timezone,
            challenge,
            cookies,
            inputs,
            actions,
        }
    }
}

fn script_text(value: impl Into<Arc<str>>) -> Result<Arc<str>, Error> {
    let value = value.into();
    if value.is_empty() {
        return Err(Error::Configuration("script text must not be empty"));
    }
    Ok(value)
}
