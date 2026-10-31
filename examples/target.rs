use std::{env, error::Error, sync::Arc, time::Duration};

use nullgate_sdk::{
    Credentials, NullgateClient, Page, Params, PixelParams, Protection, SbsdParams, SensorParams,
    SessionOptions, Target, TargetRequest, TargetResponse, ThreatMetrixParams,
};
use uuid::Uuid;
use wreq::{Client, Proxy, cookie::Jar};
use wreq_util::{Emulation, Platform, Profile};

// Matches wreq-util's Chrome146 Windows profile and client hints.
const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let target_url = env::var("TARGET_URL")?;
    let proxy = match env::var("TARGET_PROXY") {
        Ok(value) => Some(value).filter(|value| !value.is_empty()),
        Err(env::VarError::NotPresent) => None,
        Err(_) => return Err("invalid TARGET_PROXY configuration".into()),
    };
    let identity = match env::var("NULLGATE_IDENTITY") {
        Ok(value) => Uuid::parse_str(&value)?,
        Err(env::VarError::NotPresent) => Uuid::new_v4(),
        Err(error) => return Err(error.into()),
    };
    println!("Nullgate identity: {identity}");
    let mut sdk_builder = NullgateClient::builder(env::var("NULLGATE_API_KEY")?);
    if let Ok(url) = env::var("NULLGATE_BASE_URL") {
        sdk_builder = sdk_builder.base_url(url);
    }
    if let Ok(url) = env::var("ANALYTICS_URL") {
        sdk_builder = sdk_builder.analytics_url(url);
    }
    if let Ok(url) = env::var("NULLGATE_PROFILE_BASE_URL") {
        sdk_builder = sdk_builder.profile_base_url(url);
    }
    let sdk = sdk_builder.build()?;
    let jar = Arc::new(Jar::default());
    let mut target_builder = Client::builder()
        .emulation(
            Emulation::builder()
                .profile(Profile::Chrome146)
                .platform(Platform::Windows)
                .build(),
        )
        .user_agent(USER_AGENT)
        .cookie_provider(jar.clone())
        .gzip(true)
        .brotli(true)
        .zstd(true)
        .deflate(true)
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .retry(wreq::retry::Policy::never())
        .no_proxy();
    if let Some(proxy) = proxy.as_deref() {
        target_builder = target_builder
            .proxy(Proxy::all(proxy).map_err(|_| "invalid TARGET_PROXY configuration")?);
    }
    let target = target_builder.build()?;
    let profile_target = profiling_target(target.clone(), proxy.as_deref())?;

    let response = target.get(target_url.as_str()).send().await?;
    println!("Target page HTTP {}", response.status());
    let page_url = response.uri().to_string();
    let page = Page::new(&page_url, response.text().await?)?;
    let mut session = sdk.open(SessionOptions::new(identity, USER_AGENT))?;

    for protection in sdk.find_protections(&page)? {
        if let Protection::ThreatMetrix(threatmetrix) = &protection {
            let profile = session
                .profile(
                    ThreatMetrixParams::new(threatmetrix.clone()),
                    profile_target.clone(),
                )
                .await?;
            println!("TMX startup ready, request_id={}", profile.request_id());
            // This example explicitly leaves its document now. Real callers
            // keep the handle until their actual departure.
            profile.pagehide(None, false).await?;
            profile.close().await?;
            continue;
        }
        let script = target
            .get(protection.script_url().as_str())
            .header("Referer", page.url().as_str())
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;
        let params = match protection {
            Protection::Pixel(pixel) => Params::Pixel(PixelParams::new(pixel, script)?),
            Protection::Sensor(sensor) => Params::Sensor(
                SensorParams::new(sensor, script)?.cookies(
                    jar.matches(page.url().as_str())
                        .filter(|cookie| {
                            !cookie.http_only() && matches!(cookie.name(), "_abck" | "bm_sz")
                        })
                        .map(|cookie| (cookie.name().to_owned(), cookie.value().to_owned()))
                        .collect(),
                ),
            ),
            Protection::Sbsd(sbsd) => Params::Sbsd(
                SbsdParams::new(sbsd, script)?.cookies(
                    jar.matches(page.url().as_str())
                        .filter(|cookie| {
                            !cookie.http_only()
                                && matches!(cookie.name(), "bm_so" | "sbsd_o" | "bm_s")
                        })
                        .map(|cookie| (cookie.name().to_owned(), cookie.value().to_owned()))
                        .collect(),
                ),
            ),
            Protection::ThreatMetrix(_) => unreachable!("handled as profiling above"),
        };
        let solution = session.solve(params).await?;
        solution.wait().await?;

        let mut request = target
            .post(solution.url().as_str())
            .redirect(wreq::redirect::Policy::none())
            .header("Referer", page.url().as_str())
            .header("Origin", page.url().origin().ascii_serialization())
            .body(solution.body().to_owned());
        for (name, value) in solution.headers() {
            request = request.header(name.as_str(), value.as_str());
        }
        let response = request.send().await?;
        println!(
            "Target POST HTTP {}, request_id={}",
            response.status(),
            solution.request_id()
        );
        println!("{}", response.text().await?);
    }
    session.close().await?;
    sdk.close().await?;
    Ok(())
}

fn profiling_target(client: Client, proxy: Option<&str>) -> Result<Target, nullgate_sdk::Error> {
    Target::new(
        move |request: TargetRequest| {
            let client = client.clone();
            async move {
                let method = wreq::Method::from_bytes(request.method.as_bytes())?;
                let mut fetch = client
                    .request(method, request.url.as_str())
                    .redirect(wreq::redirect::Policy::none());
                if request.credentials == Credentials::Omit {
                    fetch = fetch.cookie_provider(Arc::new(Jar::default()));
                }
                for (name, value) in request.headers {
                    fetch = fetch.header(name.as_str(), value.as_str());
                }
                if let Some(body) = request.body {
                    fetch = fetch.body(body);
                }
                let response = fetch.send().await?;
                let status = response.status().as_u16();
                let headers = response
                    .headers()
                    .iter()
                    .map(|(name, value)| Ok((name.as_str().to_owned(), value.to_str()?.to_owned())))
                    .collect::<Result<_, Box<dyn Error + Send + Sync>>>()?;
                let body = response.bytes().await?.into();
                Ok::<_, Box<dyn Error + Send + Sync>>(TargetResponse {
                    status,
                    headers,
                    body,
                })
            }
        },
        proxy,
    )
}
