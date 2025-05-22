use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD as Base64Standard};
use reqwest::{
    blocking::Client,
    header::{
        ACCEPT, ACCEPT_LANGUAGE, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue, ORIGIN, REFERER,
        TE, UPGRADE_INSECURE_REQUESTS,
    },
};
use scraper::{Html, Selector};
use serde::Deserialize;
use serde_json::Value as JsonValue;
use std::{
    io::{BufRead, BufReader, Write},
    sync::Arc,
    time::Duration,
};

const TARGET_URL_TO_PROXY: &str = "https://api.deepinfra.com/v1/openai/chat/completions";
const API_REQUEST_BODY: &str = r#"{"model":"deepseek-ai/DeepSeek-R1-Turbo","messages":[{"role":"user","content":"Tell me a joke about the false sense of digital freedom in modern-day Canada and the United States."}],"stream":true,"stream_options":{"include_usage":true,"continuous_usage_stats":true}}"#;
const BROWSER_USER_AGENT: &str =
    "Mozilla/5.0 (X11; Linux x86_64; rv:138.0) Gecko/20100101 Firefox/138.0";
const ACCEPT_HTML_VAL: &str = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
const ACCEPT_EVENT_STREAM_VAL: &str = "text/event-stream";
const ACCEPT_LANG_VAL: &str = "en-US,en;q=0.5";
const PROXY_BASE_URL: &str = "https://www.croxyproxy.com";
const JSON_CONTENT_TYPE: &str = "application/json";
const SELECTOR_CSRF_TOKEN_MAIN_PAGE: &str = r#"form#request input[name="csrf"]"#;
const SELECTOR_SCRIPT_SERVER_SELECTOR: &str = "script#serverSelectorScript";
const SELECTOR_SCRIPT_INIT_SCRIPT: &str = "script#initScript";

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const SERVER_PING_TIMEOUT: Duration = Duration::from_secs(3);
const BUFFER_CAPACITY: usize = 8192;

#[derive(Deserialize, Debug, Clone)]
struct ServerInfo {
    id: u32,
    url: String,
}

fn hex_to_string(hex: &str) -> Result<String> {
    if hex.len() % 2 != 0 {
        bail!("Invalid hex string length");
    }

    let bytes = (0..hex.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect::<Vec<u8>>();

    String::from_utf8(bytes).context("Invalid UTF-8 sequence")
}

fn extract_attribute_from_html(
    document: &Html,
    element_selector_str: &str,
    attribute_name: &str,
) -> Result<String> {
    let selector =
        Selector::parse(element_selector_str).map_err(|e| anyhow!("Invalid selector: {}", e))?;

    document
        .select(&selector)
        .next()
        .and_then(|element| element.value().attr(attribute_name))
        .map(ToString::to_string)
        .ok_or_else(|| anyhow!("Attribute not found"))
}

fn select_proxy_server(
    client: &Client,
    servers_page_html: &str,
    proxy_base_url: &str,
) -> Result<ServerInfo> {
    let document = Html::parse_document(servers_page_html);
    let server_list_json_str =
        extract_attribute_from_html(&document, SELECTOR_SCRIPT_SERVER_SELECTOR, "data-ss")?;

    let server_list_b64: Vec<String> =
        serde_json::from_str(&server_list_json_str).context("Failed to parse server list")?;

    if server_list_b64.is_empty() {
        bail!("No servers available");
    }

    for s_b64 in server_list_b64 {
        let server_info = match (|| -> Result<ServerInfo> {
            let hex_encoded_json_bytes = Base64Standard.decode(&s_b64)?;
            let hex_encoded_json_str = String::from_utf8(hex_encoded_json_bytes)?;
            let server_json_str = hex_to_string(&hex_encoded_json_str)?;
            serde_json::from_str(&server_json_str).context("Failed to parse server info")
        })() {
            Ok(info) => info,
            Err(_) => continue,
        };

        if let Ok(res) = client
            .get(&server_info.url)
            .header(REFERER, proxy_base_url)
            .header(ORIGIN, proxy_base_url)
            .timeout(SERVER_PING_TIMEOUT)
            .send()
        {
            if res.status().is_success() && res.text().map(|t| t.trim() == "OK").unwrap_or(false) {
                return Ok(server_info);
            }
        }
    }

    bail!("No working proxy servers found")
}

fn create_common_headers() -> HeaderMap {
    let mut headers = HeaderMap::with_capacity(5);
    headers.insert(ACCEPT, HeaderValue::from_static(ACCEPT_HTML_VAL));
    headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static(ACCEPT_LANG_VAL));
    headers.insert(UPGRADE_INSECURE_REQUESTS, HeaderValue::from_static("1"));
    headers.insert(
        HeaderName::from_static("priority"),
        HeaderValue::from_static("u=0, i"),
    );
    headers.insert(TE, HeaderValue::from_static("trailers"));
    headers
}

fn main() -> Result<()> {
    let client = Arc::new(
        Client::builder()
            .cookie_store(true)
            .user_agent(BROWSER_USER_AGENT)
            .timeout(REQUEST_TIMEOUT)
            .tcp_keepalive(Some(Duration::from_secs(60)))
            .tcp_nodelay(true)
            .build()?,
    );

    let common_headers = create_common_headers();

    let res1 = client
        .get(PROXY_BASE_URL)
        .headers(common_headers.clone())
        .send()
        .context("Failed to make initial request")?;

    if !res1.status().is_success() {
        bail!("Initial request failed: {}", res1.status());
    }

    let html_body1 = res1.text()?;
    let document1 = Html::parse_document(&html_body1);
    let csrf_token1 =
        extract_attribute_from_html(&document1, SELECTOR_CSRF_TOKEN_MAIN_PAGE, "value")?;

    let servers_url = format!("{}/servers", PROXY_BASE_URL);
    let res2 = client
        .post(&servers_url)
        .headers(common_headers.clone())
        .form(&[("url", TARGET_URL_TO_PROXY), ("csrf", &csrf_token1)])
        .send()
        .context("Failed to request server list")?;

    if !res2.status().is_success() {
        bail!("Server list request failed: {}", res2.status());
    }

    let html_body2 = res2.text()?;
    let document2 = Html::parse_document(&html_body2);
    let csrf_token2_json =
        extract_attribute_from_html(&document2, SELECTOR_SCRIPT_SERVER_SELECTOR, "data-csrf")?;
    let csrf_token2: String = serde_json::from_str(&csrf_token2_json)?;

    let server_info = select_proxy_server(&client, &html_body2, PROXY_BASE_URL)?;

    let res_cpi = client
        .post(&format!("{}/requests?fso=", PROXY_BASE_URL))
        .headers(common_headers)
        .form(&[
            ("url", TARGET_URL_TO_PROXY),
            ("proxyServerId", &server_info.id.to_string()),
            ("csrf", &csrf_token2),
            ("demo", "0"),
            ("frontOrigin", PROXY_BASE_URL),
        ])
        .send()
        .context("Failed to setup proxy")?;

    if !res_cpi.status().is_success() {
        bail!("Proxy setup request failed: {}", res_cpi.status());
    }

    let cpi_url = res_cpi.url().clone();
    let cpi_page_html = res_cpi.text()?;
    let document_cpi = Html::parse_document(&cpi_page_html);

    let data_r = extract_attribute_from_html(&document_cpi, SELECTOR_SCRIPT_INIT_SCRIPT, "data-r")?;
    let final_url = String::from_utf8(Base64Standard.decode(data_r)?)?;

    let res_stream = client
        .post(&final_url)
        .header(ACCEPT, ACCEPT_EVENT_STREAM_VAL)
        .header(CONTENT_TYPE, JSON_CONTENT_TYPE)
        .header(ORIGIN, cpi_url.origin().ascii_serialization())
        .header(REFERER, cpi_url.as_str())
        .body(API_REQUEST_BODY.to_string())
        .send()
        .context("Failed to make API request")?;

    if !res_stream.status().is_success() {
        bail!("API request failed: {}", res_stream.status());
    }

    let reader = BufReader::with_capacity(BUFFER_CAPACITY, res_stream);
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();

    for line in reader.lines() {
        let line = line.context("Failed to read line from stream")?;
        if !line.starts_with("data: ") {
            continue;
        }

        let json_str = &line["data: ".len()..];
        if json_str.trim() == "[DONE]" {
            break;
        }

        if let Ok(json) = serde_json::from_str::<JsonValue>(json_str) {
            if let Some(content) = json
                .get("choices")
                .and_then(|c| c.as_array())
                .and_then(|c| c.first())
                .and_then(|c| c.get("delta"))
                .and_then(|d| d.get("content"))
                .and_then(|c| c.as_str())
            {
                write!(stdout, "{}", content)?;
                stdout.flush()?;
            }
        }
    }

    writeln!(stdout)?;
    Ok(())
}
