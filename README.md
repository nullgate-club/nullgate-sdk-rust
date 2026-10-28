# Nullgate Rust SDK

An asynchronous, typed client for Nullgate's supported Akamai Pixel, Sensor, and SBSD generation APIs. The SDK contacts Nullgate; your target HTTP transport and cookie jar remain yours.

This SDK requires the updated Nullgate backend, including `X-Request-ID` and
analytics reporting. Until the backend cutover, use `NullgateClient::builder(key)`
with `.base_url(...)` and `.analytics_url(...)` for an updated preview deployment; the target
example reads `NULLGATE_BASE_URL` and `ANALYTICS_URL`. It does not support the old
production API. Python users of that API should stay on the Python SDK's `main`.

## Install

```sh
cargo add nullgate-sdk --git https://github.com/nullgate-club/nullgate-sdk-rust.git
cargo add tokio --features macros,rt-multi-thread
cargo add uuid
```

Rust 1.98 or newer and a Tokio runtime are required. This SDK is source-installed
from public GitHub, not released to crates.io.

## Generate a target POST

```rust,no_run
use nullgate_sdk::{
    NullgateClient, Page, Params, PixelParams, Protection, SbsdParams, SensorParams,
    SessionOptions,
};
use uuid::Uuid;

async fn generate(html: String, script: String) -> Result<(), Box<dyn std::error::Error>> {
    let client = NullgateClient::builder(std::env::var("NULLGATE_API_KEY")?)
        .base_url(std::env::var("NULLGATE_BASE_URL")?)
        .analytics_url(std::env::var("ANALYTICS_URL")?)
        .build()?;
    let page = Page::new("https://target.example/", html)?;
    let mut session = client.open(SessionOptions::new(
        Uuid::parse_str("11111111-2222-4333-8444-555555555555")?,
        "the exact user agent configured on your target client",
    ))?;

    if let Some(protection) = client.find_protections(&page)?.into_iter().next() {
        // Fetch `script` from protection.script_url() with your target client.
        let params = match protection {
            Protection::Pixel(pixel) => Params::Pixel(PixelParams::new(pixel, script)?),
            Protection::Sensor(sensor) => {
                Params::Sensor(SensorParams::new(sensor, script)?)
            }
            Protection::Sbsd(sbsd) => Params::Sbsd(SbsdParams::new(sbsd, script)?),
        };
        let solution = session.solve(params).await?;
        solution.wait().await?;
        // POST solution.body() unchanged to solution.url(), with solution.headers().
    }
    Ok(())
}
```

`PixelParams::new(pixel, script)?` takes its challenge from the concrete `Pixel`; `SbsdParams::new(sbsd, script)?` takes the concrete `Sbsd`. Constructors cannot mix protection kinds. Scripts can be strings or shared `Arc<str>` values for inexpensive continuation.

Sensor/SBSD `.cookies(BTreeMap<String, String>)` supplies the current target cookie snapshot. Sensor `.inputs(Vec<BTreeMap<String, String>>)` hashes raw values locally using UTF-16 little-endian SHA-256 and sends only summaries. `.actions(Vec<serde_json::Map<String, serde_json::Value>>)?` accepts caller-supplied activity and rejects raw `input`/`change` text before transport; provide prepared summaries instead. Omitted inputs/actions preserve continuation semantics; explicitly empty lists remain empty lists.

A session's mutable borrow prevents overlapping solves. Separate sessions can run concurrently and share the client's pool; state headers never become client-wide defaults. Header rotations are retained even on API/protocol errors. Drop releases resources when the last client, session, or solution handle goes away.

Keep the client for your application lifetime and open a fresh session for each
new document. Reuse the identity and your target provider's cookie jar across
navigation; never reuse document state for a different page.

`Error::Api` exposes status, server detail, and the response request ID through accessors. Debug/Display omit raw service detail, keys, HTML, scripts, and cookies. Malformed successful responses return `Error::Protocol`; no default solution is invented. Reports contain only `{request_id}`, use a three-second timeout, and never send API authentication, state, or target cookies. Redirects/retries are disabled. Cancellation is ordinary future cancellation, not successful delivery.

Discovery is local and synchronous. `find_protections(&page)?` returns an empty
list for no match, a single-element list for one match, and
`Error::AmbiguousProtections { count }` for multiple candidates. It never panics.
To inspect or filter an ambiguous page explicitly, use:

```rust,ignore
let candidates = client.find_protections_with_options(
    &page,
    nullgate_sdk::FindOptions { panic: false },
)?;
```

The standalone `find_protections_with_options` function accepts the same options.
Opting out retains every candidate, duplicate source occurrence, original query,
source location, and distinct pixel challenge pairing; nothing is silently
selected or deduplicated. Sensor discovery is the same-origin, extensionless
classic-script heuristic, not source-content verification. SBSD blocking means
the raw `t` parameter is present, including `t=`.

## Runnable target example

The example uses published **wreq 0.16.1 + wreq-util 0.2.0**, Chrome146/Windows TLS, HTTP/2, client hints and matching user agent, a persistent scope-aware cookie jar, compression, and verified CA roots. These are dev dependencies, not dependencies of SDK consumers. There is no fallback to a standard target transport.

```sh
git clone https://github.com/nullgate-club/nullgate-sdk-rust.git
cd nullgate-sdk-rust
export TARGET_URL='https://your-target.example/'
export NULLGATE_API_KEY='your ng_ credential'
export NULLGATE_BASE_URL='https://your-updated-nullgate.example/'
cargo run --example target
```

`TARGET_URL` and `NULLGATE_API_KEY` are required. Set `NULLGATE_BASE_URL` for the
updated staging or local backend. Optional `NULLGATE_IDENTITY` reuses a UUID;
otherwise the example creates and prints a fresh one. `ANALYTICS_URL` is optional.
The same native jar handles page/script/POST cookies. Only script-visible
`_abck`/`bm_sz` cookies are sent for Sensor, and `bm_so`/`sbsd_o` for SBSD; unrelated
target cookies stay local.

The example performs one page GET, local discovery, one script GET, one
generation, a deadline wait, and one exact POST, then prints the response.
One POST is not a clearance claim. If the target needs another generation, read
the updated cookies and solve again in the same document session.
`akamai::is_enough(cookie, response_count)` describes the ordinary sensor-send
gate, not website acceptance. A new document needs a fresh session. Report an
observed rejection with `solution.report().await?`; it sends only the request ID
and makes no refund or acceptance promise.

## Quality and package checks

```sh
make setup
make format
make check
```

The gate runs rustfmt, Clippy with warnings denied, protocol/discovery/ownership tests, compile-fail ownership examples, rustdoc, and Cargo package verification. `make package` creates and verifies a local archive; no registry publication occurs. Building the target example's BoringSSL dependency also requires the provider's native build prerequisites (C/C++ toolchain, CMake, and libclang).

Standalone CI uses Rust 1.98 with rustfmt and Clippy, installs the native example
build prerequisites, then runs `make setup` and `make check`. Canonical SDK-first
documentation: [Quickstart](https://docs.nullgate.club/en/quickstart).
