use std::{env, error::Error, sync::Arc, time::Duration};

use nullgate_sdk::{
    NullgateClient, Page, Params, PixelParams, Protection, SbsdParams, SensorParams, SessionOptions,
};
use uuid::Uuid;
use wreq::{Client, cookie::Jar};
use wreq_util::{Emulation, Platform, Profile};

// Matches wreq-util's Chrome146 Windows profile and client hints.
const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let target_url = env::var("TARGET_URL")?;
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
    let sdk = sdk_builder.build()?;
    let jar = Arc::new(Jar::default());
    let target = Client::builder()
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
        .retry(wreq::retry::Policy::never())
        .no_proxy()
        .build()?;

    let response = target.get(target_url.as_str()).send().await?;
    println!("Target page HTTP {}", response.status());
    let page_url = response.uri().to_string();
    let page = Page::new(&page_url, response.text().await?)?;
    let mut session = sdk.open(SessionOptions::new(identity, USER_AGENT))?;

    for protection in sdk.find_protections(&page)? {
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
    Ok(())
}
