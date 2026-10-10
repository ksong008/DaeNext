//! Xray's transport UA aliases and fetch headers, scoped to XHTTP requests.
use super::*;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

struct BrowserHeaders {
    chrome: String,
    chrome_ch: String,
    edge: String,
    edge_ch: String,
    firefox: String,
    safari: String,
    curl: String,
}

static BROWSERS: OnceLock<BrowserHeaders> = OnceLock::new();

type HeaderTemplate = (
    std::collections::BTreeMap<String, String>,
    ResidentXhttpHttpVersion,
    HeaderList,
);
static TEMPLATES: OnceLock<std::sync::Mutex<std::collections::VecDeque<HeaderTemplate>>> =
    OnceLock::new();

pub(super) fn request_headers(
    settings: &ResidentXhttpSettingsPlan,
    version: ResidentXhttpHttpVersion,
) -> HeaderList {
    let cache = TEMPLATES.get_or_init(std::sync::Mutex::default);
    {
        let mut templates = cache.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(index) = templates
            .iter()
            .position(|(headers, v, _)| headers == &settings.headers && *v == version)
            && let Some(template) = templates.remove(index)
        {
            let headers = template.2.clone();
            templates.push_back(template);
            return headers;
        }
    }
    let headers = build_request_headers(settings, version);
    if settings
        .headers
        .iter()
        .map(|(k, v)| k.len() + v.len())
        .sum::<usize>()
        <= 32 * 1024
    {
        let mut templates = cache.lock().unwrap_or_else(|error| error.into_inner());
        if templates.len() >= 64 {
            templates.pop_front();
        }
        templates.push_back((settings.headers.clone(), version, headers.clone()));
    }
    headers
}

fn build_request_headers(
    settings: &ResidentXhttpSettingsPlan,
    version: ResidentXhttpHttpVersion,
) -> HeaderList {
    let mut headers = settings
        .headers
        .iter()
        .map(|(k, v)| (Arc::<str>::from(k.as_str()), Arc::<str>::from(v.as_str())))
        .collect::<Vec<_>>();
    let alias = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("user-agent"))
        .map(|(_, v)| v.as_ref())
        .unwrap_or("chrome");
    if alias.is_empty() {
        // An explicitly empty UA suppresses the header in Go's encoders.
        headers.retain(|(key, _)| !key.eq_ignore_ascii_case("user-agent"));
        return headers;
    }
    // As in the official implementation, custom UAs opt out.
    // Alias values are case sensitive; header names are not.
    if !matches!(
        alias,
        "chrome" | "edge" | "firefox" | "safari" | "curl" | "golang"
    ) {
        let ua = alias.to_owned();
        // Use the same selected value for every encoder even if the input
        // contains differently cased spellings of User-Agent.
        set(&mut headers, "User-Agent", &ua);
        return headers;
    }
    if alias == "golang" {
        // Xray removes this alias and its HTTP library supplies the wire UA.
        // Our encoders do not add one, so reproduce each library's default.
        let ua = match version {
            ResidentXhttpHttpVersion::H1 => "Go-http-client/1.1",
            ResidentXhttpHttpVersion::H2 => "Go-http-client/2.0",
            ResidentXhttpHttpVersion::H3 => "quic-go HTTP/3",
        };
        set(&mut headers, "User-Agent", ua);
        return headers;
    }
    let profiles = BROWSERS.get_or_init(BrowserHeaders::new);
    let (ua, hints, language, priority, dnt) = match alias {
        "chrome" => (
            &profiles.chrome,
            Some(&profiles.chrome_ch),
            "en-US,en;q=0.9",
            "u=1, i",
            true,
        ),
        "edge" => (
            &profiles.edge,
            Some(&profiles.edge_ch),
            "en-US,en;q=0.9",
            "u=1, i",
            true,
        ),
        "firefox" => (&profiles.firefox, None, "en-US,en;q=0.5", "u=4", true),
        "safari" => (&profiles.safari, None, "en-US,en;q=0.9", "u=3, i", false),
        "curl" => {
            set(&mut headers, "User-Agent", &profiles.curl);
            return headers;
        }
        _ => unreachable!(),
    };
    set(&mut headers, "User-Agent", ua);
    set(&mut headers, "Accept-Language", language);
    if let Some(hints) = hints {
        set(&mut headers, "Sec-CH-UA", hints);
        set(&mut headers, "Sec-CH-UA-Mobile", "?0");
        set(&mut headers, "Sec-CH-UA-Platform", "\"Windows\"");
    }
    if dnt {
        set(&mut headers, "DNT", "1");
    }
    set(&mut headers, "Sec-Fetch-Mode", "cors");
    set(&mut headers, "Sec-Fetch-Dest", "empty");
    set(&mut headers, "Sec-Fetch-Site", "same-origin");
    for (key, value) in [
        ("Priority", priority),
        ("Cache-Control", "no-cache"),
        ("Pragma", "no-cache"),
        ("Accept", "*/*"),
    ] {
        if headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .is_none_or(|(_, v)| v.is_empty())
        {
            set(&mut headers, key, value);
        }
    }
    headers
}

fn set(headers: &mut HeaderList, name: &str, value: &str) {
    xhttp_set_header(headers, name.to_owned(), value.to_owned());
}

impl BrowserHeaders {
    fn new() -> Self {
        // Match the official release cadence and GREASE format. Sample once
        // per process with the existing PRNG, without probing CPU identity.
        let days = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            / 86400;
        let days = days.min(2_932_896) as i64;
        let chrome_version = (144
            + (days
                - year_start_days(2026)
                - 12
                - 35
                - (fastrand::f64().powi(2) * 105.0).floor() as i64)
                / 35)
            .max(1);
        let firefox_version = (128
            + (days
                - year_start_days(2024)
                - 210
                - 25
                - (fastrand::f64().powi(2) * 50.0).floor() as i64)
                / 30)
            .max(1);
        let curl_minor = ((days
            - year_start_days(2023)
            - 78
            - 60
            - (fastrand::f64().powi(2) * 165.0).floor() as i64)
            / 57)
            .max(0);
        let chrome = format!(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{chrome_version}.0.0.0 Safari/537.36"
        );
        let edge = format!("{chrome}Edg/{chrome_version}.0.0.0");
        let firefox = format!(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{firefox_version}.0) Gecko/20100101 Firefox/{firefox_version}.0"
        );
        let safari = format!(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{} Safari/605.1.15",
            safari_version(days, (fastrand::f64().powi(3) * 75.0).floor() as i64)
        );
        Self {
            chrome,
            chrome_ch: client_hints(chrome_version as usize, "Google Chrome"),
            edge,
            edge_ch: client_hints(chrome_version as usize, "Microsoft Edge"),
            firefox,
            safari,
            curl: format!("curl/8.{curl_minor}.0"),
        }
    }
}

fn year_start_days(year: i64) -> i64 {
    let previous = year - 1;
    365 * (year - 1970) + previous / 4 - previous / 100 + previous / 400 - 477
}

fn safari_version(days: i64, delay: i64) -> String {
    let mut year = 1970 + days / 366;
    while year_start_days(year + 1) <= days {
        year += 1;
    }
    let release_day = |year| {
        let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
        year_start_days(year) + 265 + i64::from(leap) + delay
    };
    if days < release_day(year) {
        year -= 1;
    }
    const MINORS: [u8; 25] = [
        0, 0, 0, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 4, 4, 4, 5, 5, 5, 5, 5, 6, 6, 6, 6,
    ];
    let minor = MINORS[((days - release_day(year)).max(0) / 15).min(24) as usize];
    format!("{}.{}", (year - 1999).max(1), minor)
}

fn client_hints(version: usize, brand: &str) -> String {
    const SYMBOLS: [&str; 11] = [" ", "(", ":", "-", ".", "/", ")", ";", "=", "?", "_"];
    const VERSIONS: [&str; 3] = ["8", "99", "24"];
    const ORDER: [[usize; 3]; 6] = [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ];
    let hints = [
        format!(
            "\"Not{}A{}Brand\";v=\"{}\"",
            SYMBOLS[version % 11],
            SYMBOLS[(version + 1) % 11],
            VERSIONS[version % 3]
        ),
        format!("\"Chromium\";v=\"{version}\""),
        format!("\"{brand}\";v=\"{version}\""),
    ];
    let mut shuffled = [""; 3];
    for (source, &destination) in ORDER[version % 6].iter().enumerate() {
        shuffled[destination] = &hints[source];
    }
    shuffled.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xhttp_client_hints_place_brands_in_official_order() {
        // These seeds exercise the two non-self-inverse permutations.
        assert_eq!(
            client_hints(147, "Google Chrome"),
            "\"Google Chrome\";v=\"147\", \"Not.A/Brand\";v=\"8\", \"Chromium\";v=\"147\""
        );
        assert_eq!(
            client_hints(148, "Microsoft Edge"),
            "\"Chromium\";v=\"148\", \"Microsoft Edge\";v=\"148\", \"Not/A)Brand\";v=\"99\""
        );
    }
}
