use std::{
    fmt,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use url::Url;
use uuid::Uuid;

use crate::Error;

/// Caller-owned page content, shared cheaply among discovery candidates.
#[derive(Clone)]
pub struct Page(Arc<PageData>);

struct PageData {
    url: Url,
    html: String,
    document_id: Uuid,
    started_at_ms: u64,
}

impl Page {
    /// Observe a new absolute HTTP(S) document. No network request is made.
    pub fn new(url: &str, html: impl Into<String>) -> Result<Self, Error> {
        Ok(Self(Arc::new(PageData {
            url: http_url(url)?,
            html: html.into(),
            document_id: Uuid::new_v4(),
            started_at_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| Error::Configuration("system clock is before the Unix epoch"))?
                .as_millis()
                .try_into()
                .map_err(|_| Error::Configuration("document timestamp exceeds u64 milliseconds"))?,
        })))
    }

    /// Parsed, absolute page URL.
    pub fn url(&self) -> &Url {
        &self.0.url
    }

    /// Original caller-provided HTML.
    pub fn html(&self) -> &str {
        &self.0.html
    }

    /// Identity of this document observation, preserved by clones and discovery.
    pub fn document_id(&self) -> Uuid {
        self.0.document_id
    }

    /// Acquisition time in UTC Unix milliseconds, preserved with the document.
    pub fn started_at_ms(&self) -> u64 {
        self.0.started_at_ms
    }
}

impl fmt::Debug for Page {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Page")
            .field("html_bytes", &self.0.html.len())
            .finish_non_exhaustive()
    }
}

/// Location of an active classic script tag in the supplied HTML.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScriptReference {
    /// Original HTML-decoded source attribute, retaining query and fragment.
    pub raw_source: String,
    /// Zero-based index among all script start tags, including inactive ones.
    pub tag_index: usize,
    /// One-based source line.
    pub line: usize,
    /// Zero-based Unicode character column.
    pub column: usize,
}

#[derive(Clone)]
pub(crate) struct Script {
    pub page: Page,
    pub url: Url,
    pub provenance: Option<ScriptReference>,
}

impl Script {
    fn new(page: Page, script_url: &str) -> Result<Self, Error> {
        Ok(Self {
            page,
            url: http_url(script_url)?,
            provenance: None,
        })
    }
}

impl fmt::Debug for Script {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Script")
            .field("page", &self.page)
            .field("tag_index", &self.provenance.as_ref().map(|p| p.tag_index))
            .finish_non_exhaustive()
    }
}

/// An Akamai pixel script paired with one discovered challenge.
#[derive(Clone, Debug)]
pub struct Pixel {
    pub(crate) script: Script,
    pub(crate) challenge: String,
    pub(crate) challenge_offset: Option<usize>,
}

impl Pixel {
    /// Construct a caller-identified pixel with its decimal challenge.
    pub fn new(page: Page, script_url: &str, challenge: impl Into<String>) -> Result<Self, Error> {
        let challenge = challenge.into();
        if challenge.is_empty() || !challenge.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Error::Configuration(
                "pixel challenge must contain decimal digits",
            ));
        }
        Ok(Self {
            script: Script::new(page, script_url)?,
            challenge,
            challenge_offset: None,
        })
    }

    /// Decimal challenge, preserving leading zeros.
    pub fn challenge(&self) -> &str {
        &self.challenge
    }

    /// UTF-8 byte offset of the challenge assignment in the original HTML.
    pub fn challenge_offset(&self) -> Option<usize> {
        self.challenge_offset
    }

    /// Original page.
    pub fn page(&self) -> &Page {
        &self.script.page
    }

    /// Resolved script URL, including its original query string.
    pub fn script_url(&self) -> &Url {
        &self.script.url
    }

    /// Discovery provenance; absent for manually constructed protections.
    pub fn provenance(&self) -> Option<&ScriptReference> {
        self.script.provenance.as_ref()
    }
}

/// An extensionless classic-script candidate, or caller-identified sensor.
#[derive(Clone, Debug)]
pub struct Sensor {
    pub(crate) script: Script,
}

impl Sensor {
    /// Construct a caller-identified sensor. The service validates its source.
    pub fn new(page: Page, script_url: &str) -> Result<Self, Error> {
        Ok(Self {
            script: Script::new(page, script_url)?,
        })
    }

    /// Original page.
    pub fn page(&self) -> &Page {
        &self.script.page
    }

    /// Resolved script URL.
    pub fn script_url(&self) -> &Url {
        &self.script.url
    }

    /// Discovery provenance.
    pub fn provenance(&self) -> Option<&ScriptReference> {
        self.script.provenance.as_ref()
    }
}

/// An Akamai SBSD script; query presence distinguishes blocking challenges.
#[derive(Clone, Debug)]
pub struct Sbsd {
    pub(crate) script: Script,
}

impl Sbsd {
    /// Construct a caller-identified SBSD protection.
    pub fn new(page: Page, script_url: &str) -> Result<Self, Error> {
        Ok(Self {
            script: Script::new(page, script_url)?,
        })
    }

    /// Whether the raw query contains `t`, including `t` or `t=`.
    pub fn blocking(&self) -> bool {
        self.script
            .url
            .query()
            .unwrap_or("")
            .split('&')
            .any(|part| part.split_once('=').map_or(part, |(name, _)| name) == "t")
    }

    /// Original page.
    pub fn page(&self) -> &Page {
        &self.script.page
    }

    /// Resolved script URL.
    pub fn script_url(&self) -> &Url {
        &self.script.url
    }

    /// Discovery provenance.
    pub fn provenance(&self) -> Option<&ScriptReference> {
        self.script.provenance.as_ref()
    }
}

/// A validated ThreatMetrix tags entry or explicitly identified direct collector.
#[derive(Clone)]
pub struct ThreatMetrix {
    pub(crate) script: Script,
    pub(crate) source: ThreatMetrixSource,
}

#[derive(Clone)]
pub(crate) enum ThreatMetrixSource {
    Tags,
    Collector {
        url: String,
        org_id: String,
        session_id: String,
    },
}

impl ThreatMetrix {
    /// Resolve the actual tags URL against this document and validate its parameters.
    pub fn new(page: Page, tags_url: &str) -> Result<Self, Error> {
        let mut url = page
            .url()
            .join(tags_url)
            .map_err(|_| Error::Configuration("invalid ThreatMetrix tags URL"))?;
        url.set_fragment(None);
        if !is_threatmetrix_url(&url) {
            return Err(Error::Configuration(
                "ThreatMetrix tags URL requires one nonempty org_id and session_id",
            ));
        }
        Ok(Self {
            script: Script {
                page,
                url,
                provenance: None,
            },
            source: ThreatMetrixSource::Tags,
        })
    }

    /// Use the caller's absolute collector URL and explicit, source-owned IDs.
    ///
    /// The URL is sent unchanged. No query parameters or wrapper scripts are parsed.
    pub fn collector(
        page: Page,
        collector_url: &str,
        org_id: impl Into<String>,
        session_id: impl Into<String>,
    ) -> Result<Self, Error> {
        let (scheme, rest) = collector_url
            .split_once("://")
            .ok_or(Error::Configuration("invalid ThreatMetrix collector URL"))?;
        let authority = rest.split(['/', '?']).next().unwrap_or("");
        if !(scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https"))
            || authority.is_empty()
            || authority.contains('@')
            || authority.ends_with(':')
            || collector_url.contains(['#', '\\'])
            || collector_url
                .chars()
                .any(|character| character.is_whitespace() || character.is_ascii_control())
        {
            return Err(Error::Configuration("invalid ThreatMetrix collector URL"));
        }
        let url = http_url(collector_url)?;
        let org_id = org_id.into();
        let session_id = session_id.into();
        if org_id.trim().is_empty()
            || session_id.trim().is_empty()
            || org_id.contains(['\r', '\n'])
            || session_id.contains(['\r', '\n'])
        {
            return Err(Error::Configuration(
                "ThreatMetrix collector requires nonempty org_id and session_id without CR/LF",
            ));
        }
        Ok(Self {
            script: Script {
                page,
                url,
                provenance: None,
            },
            source: ThreatMetrixSource::Collector {
                url: collector_url.to_owned(),
                org_id,
                session_id,
            },
        })
    }

    /// Original document observation.
    pub fn page(&self) -> &Page {
        &self.script.page
    }

    /// Parsed entry URL. Direct collectors retain the original URL text on the wire.
    pub fn script_url(&self) -> &Url {
        &self.script.url
    }

    /// Resolved actual tags URL, or `None` for a direct collector.
    pub fn tags_url(&self) -> Option<&Url> {
        matches!(&self.source, ThreatMetrixSource::Tags).then_some(&self.script.url)
    }

    /// Discovery provenance, absent for caller-constructed protections.
    pub fn provenance(&self) -> Option<&ScriptReference> {
        self.script.provenance.as_ref()
    }
}

impl fmt::Debug for ThreatMetrix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ThreatMetrix")
            .field("script", &self.script)
            .finish_non_exhaustive()
    }
}

pub(crate) fn is_threatmetrix_url(url: &Url) -> bool {
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || !url.path().ends_with("/tags.js")
    {
        return false;
    }
    let mut org = None;
    let mut session = None;
    for (key, value) in url.query_pairs() {
        let slot = match key.as_ref() {
            "org_id" => &mut org,
            "session_id" => &mut session,
            _ => continue,
        };
        if slot.is_some() || value.is_empty() {
            return false;
        }
        *slot = Some(value);
    }
    org.is_some() && session.is_some()
}

/// Actual supported protection variants; discovery never invents a solver.
#[derive(Clone, Debug)]
pub enum Protection {
    /// Pixel with a concrete challenge pairing.
    Pixel(Pixel),
    /// Sensor candidate.
    Sensor(Sensor),
    /// SBSD protection.
    Sbsd(Sbsd),
    /// ThreatMetrix profiling; use `Session::profile`, not `Session::solve`.
    ThreatMetrix(ThreatMetrix),
}

impl Protection {
    /// Original page, shared across all candidates from the same discovery.
    pub fn page(&self) -> &Page {
        match self {
            Self::Pixel(p) => p.page(),
            Self::Sensor(p) => p.page(),
            Self::Sbsd(p) => p.page(),
            Self::ThreatMetrix(p) => p.page(),
        }
    }

    /// Resolved candidate source URL.
    pub fn script_url(&self) -> &Url {
        match self {
            Self::Pixel(p) => p.script_url(),
            Self::Sensor(p) => p.script_url(),
            Self::Sbsd(p) => p.script_url(),
            Self::ThreatMetrix(p) => p.script_url(),
        }
    }

    /// Source occurrence in the original document.
    pub fn provenance(&self) -> Option<&ScriptReference> {
        match self {
            Self::Pixel(p) => p.provenance(),
            Self::Sensor(p) => p.provenance(),
            Self::Sbsd(p) => p.provenance(),
            Self::ThreatMetrix(p) => p.provenance(),
        }
    }
}

pub(crate) fn http_url(value: &str) -> Result<Url, Error> {
    let url =
        Url::parse(value).map_err(|_| Error::Configuration("URL must be absolute HTTP(S)"))?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(Error::Configuration("URL must be absolute HTTP(S)"));
    }
    Ok(url)
}
