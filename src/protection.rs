use std::{fmt, sync::Arc};

use url::Url;

use crate::Error;

/// Caller-owned page content, shared cheaply among discovery candidates.
#[derive(Clone)]
pub struct Page(Arc<PageData>);

struct PageData {
    url: Url,
    html: String,
}

impl Page {
    /// Construct an absolute HTTP(S) page. No network request is made.
    pub fn new(url: &str, html: impl Into<String>) -> Result<Self, Error> {
        Ok(Self(Arc::new(PageData {
            url: http_url(url)?,
            html: html.into(),
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

/// Actual supported protection variants; discovery never invents a solver.
#[derive(Clone, Debug)]
pub enum Protection {
    /// Pixel with a concrete challenge pairing.
    Pixel(Pixel),
    /// Sensor candidate.
    Sensor(Sensor),
    /// SBSD protection.
    Sbsd(Sbsd),
}

impl Protection {
    /// Original page, shared across all candidates from the same discovery.
    pub fn page(&self) -> &Page {
        match self {
            Self::Pixel(p) => p.page(),
            Self::Sensor(p) => p.page(),
            Self::Sbsd(p) => p.page(),
        }
    }

    /// Resolved candidate source URL.
    pub fn script_url(&self) -> &Url {
        match self {
            Self::Pixel(p) => p.script_url(),
            Self::Sensor(p) => p.script_url(),
            Self::Sbsd(p) => p.script_url(),
        }
    }

    /// Source occurrence in the original document.
    pub fn provenance(&self) -> Option<&ScriptReference> {
        match self {
            Self::Pixel(p) => p.provenance(),
            Self::Sensor(p) => p.provenance(),
            Self::Sbsd(p) => p.provenance(),
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
