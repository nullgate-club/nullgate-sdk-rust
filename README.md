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
use nullgate_sdk::{NullgateClient, Page, Params, Protection, SensorParams, SessionOptions};
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

    let sensors = client.find_protections(&page).into_iter().filter_map(|candidate| {
        match candidate {
            Protection::Sensor(sensor) => Some(sensor),
            _ => None,
        }
    }).collect::<Vec<_>>();
    if sensors.len() != 1 {
        return Err("select the intended sensor explicitly when discovery is ambiguous".into());
    }
    let sensor = sensors.into_iter().next().ok_or("missing sensor")?;
    // Fetch `script` from sensor.script_url() using your existing target client.
    let params = SensorParams::new(sensor, script)?;
    let solution = session.solve(Params::Sensor(params)).await?;
    solution.wait().await?;
    // POST solution.body() unchanged to solution.url(), with solution.headers().
    // On an observed target rejection, solution.report().await? delivers only
    // its diagnostic request ID; true does not mean acceptance or a refund.
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

Discovery is local and synchronous. It retains candidates, duplicate source occurrences, original query strings, source locations, and every ambiguous pixel challenge pairing. Sensor discovery is the same-origin, extensionless classic-script heuristic, not source-content verification. SBSD blocking means the raw `t` parameter is present, including `t=`. `akamai::is_enough(cookie, response_count)` closes the ordinary sensor-send gate, not an application-specific acceptance test.

## Runnable target example

The example uses published **wreq 0.16.1 + wreq-util 0.2.0**, Chrome146/Windows TLS, HTTP/2, client hints and matching user agent, a persistent scope-aware cookie jar, compression, and verified CA roots. These are dev dependencies, not dependencies of SDK consumers. There is no fallback to a standard target transport.

```sh
git clone https://github.com/nullgate-club/nullgate-sdk-rust.git
cd nullgate-sdk-rust
export TARGET_URL='https://your-target.example/'
export NULLGATE_API_KEY='your ng_ credential'
cargo run --example target
```

Optional environment variables: `NULLGATE_IDENTITY` (UUID; otherwise random and printed for reuse), `TARGET_PROXY` (HTTP/SOCKS URL), `NULLGATE_BASE_URL`, and `ANALYTICS_URL`. The last two allow isolated local-backend runs.

The example fetches page/script with one target client, generates, waits, and posts the exact body and headers. It re-fetches the original page after blocking SBSD and diagnoses persistent blocking instead of treating POST 200 as clearance. Sensor continuation follows the cookie gate with finite diagnostic ceilings, never a fixed number of submissions claimed as acceptance. A target 403 is a rejection signal, not proof of a generation defect. Verify your own application-specific outcome.

## Quality and package checks

```sh
make setup
make format
make check
```

The gate runs rustfmt, Clippy with warnings denied, protocol/discovery/ownership tests, compile-fail ownership examples, rustdoc, and Cargo package verification. `make package` creates and verifies a local archive; no registry publication occurs. Building the target example's BoringSSL dependency also requires the provider's native build prerequisites (C/C++ toolchain, CMake, and libclang).

Standalone CI uses Rust 1.98 with rustfmt and Clippy, installs the native example
build prerequisites, then runs `make setup` and `make check`. Canonical SDK-first
documentation: [docs.nullgate.club](https://docs.nullgate.club).
