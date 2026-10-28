use std::{collections::BTreeMap, env, error::Error, sync::Arc, time::Duration};

use nullgate_sdk::{
    NullgateClient, Page, Params, PixelParams, Protection, SbsdParams, SensorParams,
    SessionOptions, Solution,
    akamai::{abck_counters, is_enough},
};
use uuid::Uuid;
use wreq::{Client, StatusCode, cookie::Jar};
use wreq_util::{Emulation, Platform, Profile};

type Result<T, E = Box<dyn Error>> = std::result::Result<T, E>;

// This exact UA matches wreq-util's Chrome146 Windows profile and client hints.
const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36";
// These are diagnostic ceilings, never a fixed number of sends claimed as acceptance.
const MAX_SENSOR_POSTS: usize = 4;

#[tokio::main]
async fn main() -> Result<()> {
    let target_url = env::var("TARGET_URL")?;
    let api_key = env::var("NULLGATE_API_KEY")
        .map_err(|_| "set NULLGATE_API_KEY to a UTF-8 ng_ credential")?;
    let identity = match env::var("NULLGATE_IDENTITY") {
        Ok(value) => Uuid::parse_str(&value)?,
        Err(env::VarError::NotPresent) => Uuid::new_v4(),
        Err(error) => return Err(error.into()),
    };
    println!("Nullgate identity: {identity}");
    let mut sdk_builder = NullgateClient::builder(api_key);
    if let Ok(url) = env::var("NULLGATE_BASE_URL") {
        sdk_builder = sdk_builder.base_url(url);
    }
    if let Ok(url) = env::var("ANALYTICS_URL") {
        sdk_builder = sdk_builder.analytics_url(url);
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
        .redirect(wreq::redirect::Policy::limited(5))
        .retry(wreq::retry::Policy::never())
        .no_proxy();
    if let Ok(proxy) = env::var("TARGET_PROXY") {
        target_builder = target_builder.proxy(wreq::Proxy::all(proxy)?);
    }
    let target = target_builder.build()?;
    let (mut page, mut page_status) = fetch_page(&target, &target_url).await?;
    let mut last_solution = None;

    let blocking = sdk
        .find_protections(&page)
        .into_iter()
        .filter_map(|protection| match protection {
            Protection::Sbsd(sbsd) if sbsd.blocking() => Some(sbsd),
            _ => None,
        })
        .collect::<Vec<_>>();
    if !blocking.is_empty() {
        if blocking.len() != 1 {
            return Err(
                "ambiguous blocking SBSD candidates; select the intended script explicitly".into(),
            );
        }
        let sbsd = blocking
            .into_iter()
            .next()
            .ok_or("missing blocking SBSD candidate")?;
        let script = fetch_script(&target, sbsd.script_url().as_str(), page.url().as_str()).await?;
        // A re-fetched document gets a fresh SDK state stream, not a recycled state ID.
        let mut session = sdk.open(SessionOptions::new(identity, USER_AGENT))?;
        let params =
            SbsdParams::new(sbsd, script)?.cookies(page_cookies(&jar, page.url().as_str()));
        let solution = session.solve(Params::Sbsd(params)).await?;
        submit(&target, &solution).await?;
        last_solution = Some(solution);
        // A successful challenge POST alone never proves the original page is clear.
        (page, page_status) = fetch_page(&target, &target_url).await?;
    }
    if sdk
        .find_protections(&page)
        .iter()
        .any(|p| matches!(p, Protection::Sbsd(sbsd) if sbsd.blocking()))
    {
        report_rejection(
            last_solution.as_ref(),
            "blocking SBSD remains after page re-fetch",
        )
        .await?;
        return Err("blocking SBSD remains after one submission and page re-fetch".into());
    }
    if !page_status.is_success() {
        report_rejection(
            last_solution.as_ref(),
            "original target page returned a non-success status",
        )
        .await?;
        return Err(format!(
            "target page HTTP {page_status}; this is not proof of a generated-payload defect"
        )
        .into());
    }

    let protections = sdk.find_protections(&page);
    for kind in ["pixel", "sensor", "sbsd"] {
        let count = protections
            .iter()
            .filter(|p| {
                matches!(
                    (kind, p),
                    ("pixel", Protection::Pixel(_))
                        | ("sensor", Protection::Sensor(_))
                        | ("sbsd", Protection::Sbsd(_))
                )
            })
            .count();
        if count > 1 {
            return Err(format!("ambiguous {kind} candidates; filter discovery explicitly").into());
        }
    }
    let mut session = sdk.open(SessionOptions::new(identity, USER_AGENT))?;
    for protection in protections {
        let source_url = protection.script_url().clone();
        let script: Arc<str> = fetch_script(&target, source_url.as_str(), page.url().as_str())
            .await?
            .into();
        match protection {
            Protection::Pixel(pixel) => {
                let solution = session
                    .solve(Params::Pixel(PixelParams::new(pixel, script)?))
                    .await?;
                submit(&target, &solution).await?;
                last_solution = Some(solution);
            }
            Protection::Sbsd(sbsd) => {
                let params =
                    SbsdParams::new(sbsd, script)?.cookies(page_cookies(&jar, page.url().as_str()));
                let solution = session.solve(Params::Sbsd(params)).await?;
                submit(&target, &solution).await?;
                last_solution = Some(solution);
            }
            Protection::Sensor(sensor) => {
                let mut responses = 0;
                let mut generation = abck_counters(
                    sensor_cookies(&jar, page.url().as_str())
                        .get("_abck")
                        .map(String::as_str),
                )
                .1;
                for _ in 0..MAX_SENSOR_POSTS {
                    let current = sensor_cookies(&jar, page.url().as_str());
                    let current_generation =
                        abck_counters(current.get("_abck").map(String::as_str)).1;
                    if current_generation >= 0.0 && current_generation != generation {
                        generation = current_generation;
                        responses = 0;
                    }
                    if is_enough(current.get("_abck").map(String::as_str), responses) {
                        break;
                    }
                    let params =
                        SensorParams::new(sensor.clone(), script.clone())?.cookies(current);
                    let solution = session.solve(Params::Sensor(params)).await?;
                    submit(&target, &solution).await?;
                    responses += 1;
                    last_solution = Some(solution);
                }
                let current = sensor_cookies(&jar, page.url().as_str());
                let current_generation = abck_counters(current.get("_abck").map(String::as_str)).1;
                if current_generation >= 0.0 && current_generation != generation {
                    responses = 0;
                }
                if !is_enough(current.get("_abck").map(String::as_str), responses) {
                    report_rejection(
                        last_solution.as_ref(),
                        "ordinary sensor-send gate remains open",
                    )
                    .await?;
                    return Err("sensor diagnostic ceiling reached; no acceptance claimed".into());
                }
                println!("ordinary sensor-send gate closed; this is not website acceptance");
            }
        }
    }
    let (verified_page, verified_status) = fetch_page(&target, &target_url).await?;
    let still_blocking = sdk
        .find_protections(&verified_page)
        .iter()
        .any(|p| matches!(p, Protection::Sbsd(sbsd) if sbsd.blocking()));
    if !verified_status.is_success() || still_blocking {
        report_rejection(
            last_solution.as_ref(),
            "target page still rejects or serves blocking SBSD",
        )
        .await?;
        return Err(format!("target page HTTP {verified_status}, blocking_sbsd={still_blocking}; not proof of a generator defect").into());
    }
    println!(
        "target page HTTP {verified_status}, no discovered blocking SBSD; verify your application-specific outcome"
    );
    Ok(())
}

async fn fetch_page(target: &Client, url: &str) -> Result<(Page, StatusCode)> {
    let response = target.get(url).send().await?;
    let status = response.status();
    let url = response.uri().to_string();
    Ok((Page::new(&url, response.text().await?)?, status))
}

async fn fetch_script(target: &Client, url: &str, referer: &str) -> Result<String> {
    Ok(target
        .get(url)
        .header("Referer", referer)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?)
}

fn sensor_cookies(jar: &Jar, url: &str) -> BTreeMap<String, String> {
    jar.matches(url)
        .filter(|cookie| !cookie.http_only() && matches!(cookie.name(), "_abck" | "bm_sz"))
        .map(|cookie| (cookie.name().to_owned(), cookie.value().to_owned()))
        .collect()
}

fn page_cookies(jar: &Jar, url: &str) -> BTreeMap<String, String> {
    jar.matches(url)
        .filter(|cookie| !cookie.http_only())
        .map(|cookie| (cookie.name().to_owned(), cookie.value().to_owned()))
        .collect()
}

async fn submit(target: &Client, solution: &Solution) -> Result<()> {
    solution.wait().await?;
    let mut request = target
        .post(solution.url().as_str())
        .redirect(wreq::redirect::Policy::none())
        .body(solution.body().to_owned());
    for (name, value) in solution.headers() {
        request = request.header(name.as_str(), value.as_str());
    }
    let response = request.send().await?;
    let status = response.status();
    let _ = response.bytes().await?;
    println!(
        "target POST HTTP {status}, request_id={}",
        solution.request_id()
    );
    if !status.is_success() {
        report_rejection(Some(solution), "target POST returned a non-success status").await?;
        return Err(format!(
            "target POST HTTP {status}; this signal does not prove a generated-payload defect"
        )
        .into());
    }
    Ok(())
}

async fn report_rejection(solution: Option<&Solution>, reason: &str) -> Result<()> {
    eprintln!("target rejection: {reason}");
    if let Some(solution) = solution {
        eprintln!(
            "analytics HTTP delivery={}; no refund or archive acceptance implied",
            solution.report().await?
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Jar, page_cookies, sensor_cookies};
    use std::collections::BTreeMap;

    #[test]
    fn sensor_snapshot_excludes_auth_httponly_and_out_of_scope_cookies() {
        let jar = Jar::default();
        jar.add(
            "_abck=visible; Secure; Path=/login",
            "https://target.example/login",
        );
        jar.add(
            "bm_sz=httponly-secret; Secure; HttpOnly; Path=/",
            "https://target.example/",
        );
        jar.add(
            "auth_token=login-secret; Secure; Path=/",
            "https://target.example/",
        );
        jar.add(
            "bm_sz=wrong-path; Secure; Path=/other",
            "https://target.example/other",
        );
        jar.add("_abck=wrong-host; Secure; Path=/", "https://other.example/");
        assert_eq!(
            sensor_cookies(&jar, "https://target.example/login/page"),
            BTreeMap::from([("_abck".to_owned(), "visible".to_owned())])
        );
        assert!(
            jar.matches("https://target.example/login/page")
                .any(|cookie| cookie.name() == "auth_token")
        );
    }

    #[test]
    fn sbsd_snapshot_keeps_page_scoped_script_visible_cookies() {
        let jar = Jar::default();
        jar.add(
            "bm_so=script-context; Secure; Path=/",
            "https://target.example/",
        );
        jar.add(
            "sbsd_o=challenge-context; Secure; Domain=target.example; Path=/login",
            "https://target.example/login",
        );
        jar.add(
            "page_context=other-context; Path=/",
            "https://target.example/",
        );
        jar.add(
            "auth_token=httponly-secret; Secure; HttpOnly; Path=/",
            "https://target.example/",
        );
        jar.add(
            "other_path=hidden; Path=/other",
            "https://target.example/other",
        );
        jar.add("other_host=hidden; Path=/", "https://other.example/");
        jar.add(
            "expired=hidden; Max-Age=0; Path=/",
            "https://target.example/",
        );
        assert_eq!(
            page_cookies(&jar, "https://target.example/login/page"),
            BTreeMap::from([
                ("bm_so".to_owned(), "script-context".to_owned()),
                ("page_context".to_owned(), "other-context".to_owned()),
                ("sbsd_o".to_owned(), "challenge-context".to_owned()),
            ])
        );
        assert_eq!(
            page_cookies(&jar, "http://target.example/login/page"),
            BTreeMap::from([("page_context".to_owned(), "other-context".to_owned())])
        );
        assert_eq!(
            page_cookies(&jar, "https://child.target.example/login/page"),
            BTreeMap::from([("sbsd_o".to_owned(), "challenge-context".to_owned())])
        );
    }
}
