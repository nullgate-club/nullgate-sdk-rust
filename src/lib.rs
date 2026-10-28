//! Typed asynchronous Nullgate generation, without owning the target transport.
//!
//! ```no_run
//! use nullgate_sdk::{NullgateClient, Page, Params, PixelParams, Protection, SessionOptions};
//! use uuid::Uuid;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let client = NullgateClient::new(std::env::var("NULLGATE_API_KEY")?)?;
//! let page = Page::new("https://target.example/", "<script>bazadebezolkohpepadr='123'</script><script src='/akam/13/abc'></script>")?;
//! let mut session = client.open(SessionOptions::new(
//!     Uuid::parse_str("11111111-2222-4333-8444-555555555555")?,
//!     "the exact user agent used by your target transport",
//! ))?;
//! for protection in client.find_protections(&page) {
//!     if let Protection::Pixel(pixel) = protection {
//!         // Fetch this script with your existing target client/cookie jar.
//!         let script = "caller-fetched source text";
//!         let solution = session.solve(Params::Pixel(PixelParams::new(pixel, script)?)).await?;
//!         solution.wait().await?;
//!         // POST solution.body() unchanged, with solution.headers(), to solution.url().
//!     }
//! }
//! # Ok(()) }
//! ```
//!
//! Use a Tokio runtime for asynchronous I/O. Client, sessions, and solutions keep
//! the pooled transport alive through ordinary ownership/Drop. A mutable session
//! prevents overlapping generations; open separate sessions for parallel work.

pub mod akamai;
mod client;
mod discovery;
mod error;
mod params;
mod protection;
mod solution;

pub use client::{ClientBuilder, NullgateClient, Session, SessionOptions};
pub use discovery::find_protections;
pub use error::{ApiError, Error, ProtocolError};
pub use params::{Params, PixelParams, SbsdParams, SensorParams};
pub use protection::{Page, Pixel, Protection, Sbsd, ScriptReference, Sensor};
pub use solution::Solution;
