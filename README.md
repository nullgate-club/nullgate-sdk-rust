# Nullgate Rust SDK

An asynchronous, typed client for Nullgate's Akamai Pixel, Sensor and SBSD generation APIs and active ThreatMetrix profiling. The SDK contacts Nullgate; your target HTTP transport, proxy and cookie jar remain yours.

The default endpoints are `https://akamai.nullgate.club` for generation,
`https://threatmetrix.nullgate.club` for profiling, and
`https://analytics.nullgate.club` for optional diagnostic reports.

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
    let client = NullgateClient::new(std::env::var("NULLGATE_API_KEY")?)?;
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
            Protection::ThreatMetrix(_) => return Err("use session.profile for ThreatMetrix".into()),
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

A session's mutable borrow serializes solves and profile starts. Separate sessions
can run concurrently and share the client's pool; state headers never become
client-wide defaults. Rotations are retained even on API/protocol errors. Drop
cancels owned profiles; explicit `close().await?` waits for cleanup.

Keep the client for your application lifetime. For Akamai, open a fresh session
for each new document. ThreatMetrix can start a new document profile on the same
session to preserve its service continuation. In either case create a new `Page`
for each document, and reuse the identity and target provider's cookie jar across
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

## Profile ThreatMetrix

Pass the detected `ThreatMetrix` to `ThreatMetrixParams::new`, then call
`session.profile(params, target).await?`. The existing
`ThreatMetrix::new(page, tags_url)?` constructor also supports caller-identified
tags entries, with the same tags/resource discovery behavior.

For a real, caller-generated direct collector URL, supply the organization's and
site session's explicit IDs instead of a tags URL:

```rust,no_run
use nullgate_sdk::{
    Error, Page, Profile, Session, Target, ThreatMetrix, ThreatMetrixParams,
};

async fn start_collector(
    session: &mut Session,
    page: Page,
    target: Target,
    collector_url: &str,
    org_id: &str,
    session_id: &str,
) -> Result<Profile, Error> {
    let collector = ThreatMetrix::collector(page, collector_url, org_id, session_id)?;
    session.profile(ThreatMetrixParams::new(collector), target).await
}
```

The collector URL must be absolute HTTP(S), with a host and valid port, without
userinfo, a fragment, raw whitespace or backslashes. Its original URL text, path
and opaque query are sent unchanged. IDs must contain non-whitespace text without
CR/LF. They are never recovered from query names, wrapper JavaScript or source maps.
The supplied `Page`, HTML and document identity remain the actual page context;
no synthetic iframe geometry or document URL is substituted.
Keep the **same session ID in the site's hidden form input**; the SDK does not
replace it with the service state ID or change the form. This supplies profiling
facts, not a website-acceptance guarantee.

Each start contains exactly one of `tags_url` or `collector`; a direct entry has
only `{url, org_id, session_id}` under `collector`, never fake tags.
`ThreatMetrix::tags_url()` now returns `Option<&Url>`: `Some` for tags, `None`
for direct collectors. Use `script_url()` for the parsed URL of either entry;
tags-only callers inspecting `tags_url()` must handle the option.
Each successfully issued target HTTP command is billed; callbacks, WebSocket
lifecycle controls and ICE/TURN have no separate charge.

`Target::new(fetch, proxy)?` takes your async
`TargetRequest -> Result<TargetResponse, E>` callback and an explicit local
TURN route: `None`/`Some("")` means direct; HTTP CONNECT, HTTPS CONNECT and
`socks5` URLs mean proxy. TURN endpoints are resolved locally; `socks5h` is
rejected rather than claiming remote-only DNS. Choose a route with a compatible
endpoint address family. Allocation failures yield missing ICE evidence, never a
direct fallback or fabricated related address. No proxy URL reaches the service
or appears in SDK errors. Invalid routes fail before opening a paid profile.

The callback must use the page's User-Agent, TLS client, cookie jar and route.
`TargetRequest.body` is `Option<Vec<u8>>`: absent and present-empty are distinct.
Honor `Credentials::Include`/`Omit`; for omit, use your maintained provider's
fresh per-request cookie jar, never clear or replace the shared jar. Return the
actual status, headers and raw bytes, including HTTP error responses; do not use
`error_for_status` or a text decoder. The runnable wreq adapter demonstrates this.

Optional `ThreatMetrixParams::inputs` and `actions` use the existing Sensor
observation types, local UTF-16 hashing and raw-input rejection. Omitted fields
are absent from the start frame; an explicitly supplied empty list stays `[]`.
No automatic keystrokes or activity are generated.

The returned `Profile` means startup is ready, **not** that collectors have
finished or that the target accepted it. Keep the handle alive while the document
is active. `profile.wait_collected().await?` observes all installed collector
lifetimes finishing without closing the socket. On actual departure, call
`profile.pagehide(None, false).await?`; `None` samples the caller clock and
`persisted=true` preserves the active handle for a cached document.

`profile.close().await?` cancels work, releases TURN and closes the socket without
inventing pagehide. Session/client `close().await?` awaits their owned profiles.
Drop requests cleanup, but explicit close awaits it. `profile.report().await?`
uses the existing analytics semantics. Service/protocol/transport failures are
`Error::Profile` with `ProfileErrorKind`, status and request-ID accessors.
`ClientBuilder::profile_base_url` overrides the profiling endpoint.

The SDK uses `tokio-tungstenite` for WebSocket framing and maintained `turn`
for Allocate/authentication/refresh. A narrow stream adapter preserves TCP STUN
and ChannelData records; it does not implement TURN or gather host/UDP candidates.
TURN control uses TCP through the selected route; the allocation/candidate
protocol remains UDP. Allocations stay alive until release/close. Provider close
sends Refresh(0), but does not expose its acknowledgement; deletion is not claimed.

## Runnable target example

The example uses published **wreq 0.16.1 + wreq-util 0.2.0**, Chrome146/Windows TLS, HTTP/2, client hints and matching user agent, a persistent scope-aware cookie jar, compression, and verified CA roots. These are dev dependencies, not dependencies of SDK consumers. There is no fallback to a standard target transport.

```sh
git clone https://github.com/nullgate-club/nullgate-sdk-rust.git
cd nullgate-sdk-rust
export TARGET_URL='https://your-target.example/'
export NULLGATE_API_KEY='your ng_ credential'
cargo run --example target
```

`TARGET_URL` and `NULLGATE_API_KEY` are required. `NULLGATE_BASE_URL`,
`NULLGATE_PROFILE_BASE_URL` and `ANALYTICS_URL` override the default services for
local development or staging.
Optional `NULLGATE_IDENTITY` reuses a UUID; otherwise the example creates and prints one.
The same native jar handles page/script/POST cookies. Only script-visible
`_abck`/`bm_sz` cookies are sent for Sensor, and `bm_so`/`sbsd_o` for SBSD; unrelated
target cookies stay local.

To select explicit direct profiling instead of discovery, set all three collector
facts:

```sh
export TMX_COLLECTOR_URL='https://signals.example/collector?wenkse=caller-generated-value'
export TMX_ORG_ID='the-site-org'
export TMX_SESSION_ID='the-same-session-id-written-to-the-form'
cargo run --example target
```

No collector URL or ID is extracted from the page; generate these values using
the site's real integration. With no collector facts, ordinary discovery is unchanged.

For Akamai, the example performs one page GET, local discovery, one script GET,
one generation, a deadline wait, and one exact POST, then prints the response.
For ThreatMetrix, it profiles through the same wreq client, explicitly leaves
the document after startup, then awaits cleanup. Real callers retain the handle
until their actual departure.
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
