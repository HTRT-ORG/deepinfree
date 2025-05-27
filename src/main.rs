use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD as Base64Standard};
use reqwest::blocking::{Client, Response as BlockingResponse};
use reqwest::header::{
    ACCEPT, ACCEPT_LANGUAGE, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue, ORIGIN, REFERER, TE,
    UPGRADE_INSECURE_REQUESTS,
};
use scraper::{Html, Selector};
use serde::Deserialize;
use serde_json::Value as JsonValue;
use std::borrow::Cow;
use std::io::{self, BufRead, BufReader, Write};
use std::time::Duration;
use url::Url;

const TARGET_URL_TO_PROXY: &str = "https://api.deepinfra.com/v1/openai/chat/completions";
const DEEPINFRA_API_BODY: &str = r#"{"model":"deepseek-ai/DeepSeek-R1-Turbo","messages":[{"role":"user","content":"Tell me a joke about the false sense of digital freedom in modern-day Canada and the United States."}],"stream":true,"stream_options":{"include_usage":true,"continuous_usage_stats":true}}"#;

const CROXY_BASE_URL_STR: &str = "https://www.croxyproxy.com";

const USER_AGENT_VAL: &str =
    "Mozilla/5.0 (X11; Linux x86_64; rv:138.0) Gecko/20100101 Firefox/138.0";
const ACCEPT_HTML_VAL: &str = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
const ACCEPT_EVENT_STREAM_VAL: &str = "text/event-stream";
const ACCEPT_LANG_VAL: &str = "en-US,en;q=0.5";
const FORM_URLENCODED_CONTENT_TYPE: &str = "application/x-www-form-urlencoded";
const JSON_CONTENT_TYPE: &str = "application/json";

static SEC_FETCH_DEST: HeaderName = HeaderName::from_static("sec-fetch-dest");
static SEC_FETCH_MODE: HeaderName = HeaderName::from_static("sec-fetch-mode");
static SEC_FETCH_SITE: HeaderName = HeaderName::from_static("sec-fetch-site");
static SEC_FETCH_USER: HeaderName = HeaderName::from_static("sec-fetch-user");
static PRIORITY: HeaderName = HeaderName::from_static("priority");
static X_DEEPINFRA_SOURCE: HeaderName = HeaderName::from_static("x-deepinfra-source");

const SELECTOR_CSRF_TOKEN_MAIN_PAGE: &str = r#"form#request input[name="csrf"]"#;
const SELECTOR_SCRIPT_SERVER_SELECTOR: &str = "script#serverSelectorScript";
const SELECTOR_SCRIPT_INIT_SCRIPT: &str = "script#initScript";

#[derive(Deserialize, Debug, Clone)]
struct ServerInfo {
    id: u32,
    url: String,
    name: String,
}

fn hex_to_string(hex: &str) -> Result<String> {
    if hex.len() % 2 != 0 {
        bail!("Hex string has an odd number of characters: {}", hex);
    }
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16).with_context(|| {
                format!(
                    "Invalid hex pair: '{}' in hex string '{}'",
                    &hex[i..i + 2],
                    hex
                )
            })
        })
        .collect::<Result<Vec<u8>, _>>()?;
    String::from_utf8(bytes).with_context(|| "Failed to convert hex-decoded bytes to UTF-8 string")
}

fn extract_attribute_from_html(
    html_body: &str,
    element_selector_str: &str,
    attribute_name: &str,
) -> Result<String> {
    let document = Html::parse_document(html_body);
    let selector = Selector::parse(element_selector_str)
        .map_err(|e| anyhow!("Failed to parse selector '{}': {}", element_selector_str, e))?;

    let element = document
        .select(&selector)
        .next()
        .ok_or_else(|| anyhow!("Element not found with selector: {}", element_selector_str))?;

    element
        .value()
        .attr(attribute_name)
        .map(|s| s.to_string())
        .ok_or_else(|| {
            anyhow!(
                "Attribute '{}' not found on element selected by '{}'",
                attribute_name,
                element_selector_str
            )
        })
}

struct CroxyProxyInteractor {
    client: Client,
    croxy_base_url: Url,
    target_url_to_proxy: String,
    deepinfra_api_body: String,
}

impl CroxyProxyInteractor {
    fn new(target_url_to_proxy: &str, deepinfra_api_body: &str) -> Result<Self> {
        let client = Client::builder()
            .cookie_store(true)
            .user_agent(USER_AGENT_VAL)
            .timeout(Duration::from_secs(60))
            .redirect(reqwest::redirect::Policy::default())
            .build()
            .context("Failed to build reqwest client")?;

        let croxy_base_url = Url::parse(CROXY_BASE_URL_STR).with_context(|| {
            format!("Failed to parse CROXY_BASE_URL_STR: {}", CROXY_BASE_URL_STR)
        })?;

        Ok(Self {
            client,
            croxy_base_url,
            target_url_to_proxy: target_url_to_proxy.to_string(),
            deepinfra_api_body: deepinfra_api_body.to_string(),
        })
    }

    fn _build_common_croxy_headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_static(ACCEPT_HTML_VAL));
        headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static(ACCEPT_LANG_VAL));
        headers.insert(UPGRADE_INSECURE_REQUESTS, HeaderValue::from_static("1"));
        headers.insert(PRIORITY.clone(), HeaderValue::from_static("u=0, i"));
        headers.insert(TE, HeaderValue::from_static("trailers"));
        headers
    }

    fn fetch_initial_page_and_csrf(&self) -> Result<String> {
        let mut headers = self._build_common_croxy_headers();
        headers.insert(SEC_FETCH_DEST.clone(), HeaderValue::from_static("document"));
        headers.insert(SEC_FETCH_MODE.clone(), HeaderValue::from_static("navigate"));
        headers.insert(SEC_FETCH_SITE.clone(), HeaderValue::from_static("none"));
        headers.insert(SEC_FETCH_USER.clone(), HeaderValue::from_static("?1"));

        let res = self
            .client
            .get(self.croxy_base_url.clone())
            .headers(headers)
            .send()
            .context("Step 1: Request to fetch main CroxyProxy page failed")?;

        let status = res.status();
        let html_body = res.text().context("Step 1: Failed to read response body")?;
        println!("   Status from CroxyProxy main page: {}", status);
        if !status.is_success() {
            bail!("[FAIL] Step 1: HTTP {}. Body: {}", status, html_body);
        }

        let csrf_token =
            extract_attribute_from_html(&html_body, SELECTOR_CSRF_TOKEN_MAIN_PAGE, "value")
                .context("Step 1: Failed to extract initial CSRF token")?;
        println!("   CSRF Token 1: {}", csrf_token);
        Ok(csrf_token)
    }

    fn fetch_server_selection_data(
        &self,
        initial_csrf_token: &str,
    ) -> Result<(Url, String, String)> {
        let servers_url = self
            .croxy_base_url
            .join("/servers")
            .context("Failed to construct /servers URL")?;

        let form_params = [
            ("url", self.target_url_to_proxy.as_str()),
            ("csrf", initial_csrf_token),
        ];

        let mut headers = self._build_common_croxy_headers();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static(FORM_URLENCODED_CONTENT_TYPE),
        );
        headers.insert(
            ORIGIN,
            HeaderValue::from_str(
                self.croxy_base_url
                    .origin()
                    .unicode_serialization()
                    .as_str(),
            )
            .with_context(|| {
                format!("Failed to create Origin header for {}", self.croxy_base_url)
            })?,
        );
        headers.insert(
            REFERER,
            HeaderValue::from_str(self.croxy_base_url.as_str()).with_context(|| {
                format!(
                    "Failed to create Referer header for {}",
                    self.croxy_base_url
                )
            })?,
        );
        headers.insert(SEC_FETCH_DEST.clone(), HeaderValue::from_static("document"));
        headers.insert(SEC_FETCH_MODE.clone(), HeaderValue::from_static("navigate"));
        headers.insert(
            SEC_FETCH_SITE.clone(),
            HeaderValue::from_static("same-origin"),
        );
        headers.insert(SEC_FETCH_USER.clone(), HeaderValue::from_static("?1"));

        let res = self
            .client
            .post(servers_url.clone())
            .headers(headers)
            .form(&form_params)
            .send()
            .context("Step 2: Request to /servers failed")?;

        let status = res.status();
        let html_body = res
            .text()
            .context("Step 2: Failed to read response body from /servers")?;
        println!("   Status from /servers: {}", status);
        if !status.is_success() {
            bail!("[FAIL] Step 2: HTTP {}. Body: {}", status, html_body);
        }

        let document = Html::parse_document(&html_body);
        let script_selector = Selector::parse(SELECTOR_SCRIPT_SERVER_SELECTOR)
            .map_err(|e| anyhow!("Failed to parse server data script selector: {}", e))?;

        let server_data_script_element =
            document.select(&script_selector).next().ok_or_else(|| {
                anyhow!(
                    "Server data script element not found using selector: {}",
                    SELECTOR_SCRIPT_SERVER_SELECTOR
                )
            })?;

        let csrf_token2_json_escaped = server_data_script_element
            .value()
            .attr("data-csrf")
            .ok_or_else(|| {
                anyhow!(
                    "Attribute 'data-csrf' (CSRF Token 2) not found on server data script element"
                )
            })?
            .to_string();

        let server_list_json_data_ss_str = server_data_script_element
            .value()
            .attr("data-ss")
            .ok_or_else(|| {
                anyhow!("Attribute 'data-ss' (server list) not found on server data script element")
            })?
            .to_string();

        let csrf_token2: String =
            serde_json::from_str(&csrf_token2_json_escaped).with_context(|| {
                format!(
                    "Step 2: Failed to parse CSRF Token 2 from JSON. Value: '{}'",
                    csrf_token2_json_escaped
                )
            })?;
        println!("   CSRF Token 2: {}", csrf_token2);

        Ok((servers_url, csrf_token2, server_list_json_data_ss_str))
    }

    fn select_proxy_server(&self, server_list_json_data_ss_str: &str) -> Result<ServerInfo> {
        println!("   Attempting to select a proxy server automatically...");

        let server_list_b64: Vec<String> = serde_json::from_str(server_list_json_data_ss_str)
            .with_context(|| {
                format!(
                    "Failed to parse server list JSON (from data-ss). Content: {}",
                    server_list_json_data_ss_str
                )
            })?;

        if server_list_b64.is_empty() {
            bail!("Server list (data-ss) is empty after parsing.");
        }

        let croxy_origin_header_val = self.croxy_base_url.origin().unicode_serialization();
        let croxy_origin_header = HeaderValue::from_str(croxy_origin_header_val.as_str())?;
        let croxy_referer_header = HeaderValue::from_str(self.croxy_base_url.as_str())?;

        for s_b64 in server_list_b64 {
            let server_info_result: Result<ServerInfo> = (|| {
                let hex_encoded_json_bytes = Base64Standard.decode(&s_b64).with_context(|| {
                    format!("Base64 decoding of server entry failed. Entry: {}", s_b64)
                })?;
                let hex_encoded_json_str = String::from_utf8(hex_encoded_json_bytes).with_context(
                    || "UTF8 conversion after Base64 decode failed for server entry.",
                )?;
                let server_json_str = hex_to_string(&hex_encoded_json_str).with_context(|| {
                    format!(
                        "Hex to string decoding failed. Hex: {}",
                        hex_encoded_json_str
                    )
                })?;
                serde_json::from_str(&server_json_str).with_context(|| {
                    format!(
                        "JSON parsing of server info failed. JSON: '{}'",
                        server_json_str
                    )
                })
            })();

            let server_info = match server_info_result {
                Ok(info) => info,
                Err(e) => {
                    eprintln!(
                        "     [WARN] Failed to decode/parse server entry: {:?}. Skipping.",
                        e
                    );
                    continue;
                }
            };

            println!(
                "     Testing server: ID {}, Name '{}', URL {}...",
                server_info.id, server_info.name, server_info.url
            );
            match self
                .client
                .get(&server_info.url)
                .header(REFERER, croxy_referer_header.clone())
                .header(ORIGIN, croxy_origin_header.clone())
                .timeout(Duration::from_secs(5))
                .send()
            {
                Ok(ping_res) => {
                    let status = ping_res.status();
                    if status.is_success() {
                        match ping_res.text() {
                            Ok(text) => {
                                if text.trim() == "OK" {
                                    println!(
                                        "     Server ID {} ('{}') responded OK. Selecting this server.",
                                        server_info.id, server_info.name
                                    );
                                    return Ok(server_info);
                                } else {
                                    eprintln!(
                                        "     [WARN] Server ID {} pinged, but response was not 'OK': '{}'",
                                        server_info.id,
                                        text.trim()
                                    );
                                }
                            }
                            Err(e) => eprintln!(
                                "     [WARN] Server ID {} pinged, but failed to read response body: {}",
                                server_info.id, e
                            ),
                        }
                    } else {
                        eprintln!(
                            "     [WARN] Server ID {} ping failed with status: {}",
                            server_info.id, status
                        );
                    }
                }
                Err(e) => eprintln!(
                    "     [WARN] Error pinging server ID {}: {}",
                    server_info.id, e
                ),
            }
        }
        bail!("Could not find a working proxy server after trying all options.")
    }

    fn submit_proxy_request_and_get_cpi_details(
        &self,
        chosen_server: &ServerInfo,
        csrf_token2: &str,
        servers_page_url: &Url,
    ) -> Result<(Url, String)> {
        let requests_url = self
            .croxy_base_url
            .join("/requests?fso=")
            .context("Failed to construct /requests URL")?;

        let server_id_str = chosen_server.id.to_string();
        let front_origin_str = self.croxy_base_url.origin().unicode_serialization();

        let form_params = [
            ("url", self.target_url_to_proxy.as_str()),
            ("proxyServerId", server_id_str.as_str()),
            ("csrf", csrf_token2),
            ("demo", "0"),
            ("frontOrigin", front_origin_str.as_str()),
        ];

        let mut headers = self._build_common_croxy_headers();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static(FORM_URLENCODED_CONTENT_TYPE),
        );
        let origin_header_val = self.croxy_base_url.origin().unicode_serialization();
        headers.insert(ORIGIN, HeaderValue::from_str(origin_header_val.as_str())?);
        headers.insert(REFERER, HeaderValue::from_str(servers_page_url.as_str())?);
        headers.insert(SEC_FETCH_DEST.clone(), HeaderValue::from_static("document"));
        headers.insert(SEC_FETCH_MODE.clone(), HeaderValue::from_static("navigate"));
        headers.insert(
            SEC_FETCH_SITE.clone(),
            HeaderValue::from_static("same-origin"),
        );

        let res_cpi = self
            .client
            .post(requests_url)
            .headers(headers)
            .form(&form_params)
            .send()
            .context("Step 4: Request to /requests (leading to __cpi.php) failed")?;

        let status_cpi = res_cpi.status();
        let cpi_url_after_redirect = res_cpi.url().clone();
        println!(
            "   Status after redirect (should be for __cpi.php): {}",
            status_cpi
        );
        println!("   URL after redirect: {}", cpi_url_after_redirect);

        let cpi_page_html = res_cpi
            .text()
            .context("Step 4: Failed to read response body from __cpi.php")?;
        if !status_cpi.is_success() {
            bail!(
                "[FAIL] Step 4 (loading __cpi.php): HTTP {}. Body: {}",
                status_cpi,
                cpi_page_html
            );
        }
        Ok((cpi_url_after_redirect, cpi_page_html))
    }

    fn extract_final_proxied_url_from_cpi_page(&self, cpi_page_html: &str) -> Result<Url> {
        let data_r_b64_encoded =
            extract_attribute_from_html(cpi_page_html, SELECTOR_SCRIPT_INIT_SCRIPT, "data-r")
                .context("Step 5: Failed to extract data-r attribute from __cpi.php")?;
        println!(
            "   data-r (Base64 encoded final URL part): {}",
            data_r_b64_encoded
        );

        let final_proxied_url_bytes = Base64Standard
            .decode(data_r_b64_encoded)
            .context("Step 6: Failed to Base64 decode data-r attribute")?;
        let final_proxied_url_str = String::from_utf8(final_proxied_url_bytes)
            .context("Step 6: Failed to convert decoded data-r to UTF-8 string")?;

        let final_url = Url::parse(&final_proxied_url_str).with_context(|| {
            format!(
                "Step 6: Failed to parse final proxied URL: {}",
                final_proxied_url_str
            )
        })?;
        println!(
            "\n[6] Decoded final proxied URL for DeepInfra API: {}",
            final_url
        );
        Ok(final_url)
    }

    fn stream_from_proxied_url(
        &self,
        final_proxied_url: &Url,
        cpi_redirect_url: &Url,
    ) -> Result<BlockingResponse> {
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_static(ACCEPT_EVENT_STREAM_VAL));
        headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static(ACCEPT_LANG_VAL));
        headers.insert(CONTENT_TYPE, HeaderValue::from_static(JSON_CONTENT_TYPE));
        headers.insert(
            X_DEEPINFRA_SOURCE.clone(),
            HeaderValue::from_static("model-embed"),
        );
        headers.insert(SEC_FETCH_DEST.clone(), HeaderValue::from_static("empty"));
        headers.insert(SEC_FETCH_MODE.clone(), HeaderValue::from_static("cors"));
        headers.insert(
            SEC_FETCH_SITE.clone(),
            HeaderValue::from_static("same-site"),
        );
        headers.insert(PRIORITY.clone(), HeaderValue::from_static("u=0"));
        headers.insert(
            REFERER,
            HeaderValue::from_str(cpi_redirect_url.as_str())
                .context("Step 7: Failed to create Referer header from CPI URL")?,
        );

        let cpi_host_for_origin: Cow<str> = cpi_redirect_url.host_str()
            .map(Cow::Borrowed)
            .unwrap_or_else(|| {
                eprintln!("[WARN] CPI redirect URL {} has no host, using CroxyProxy base host {} for Origin header as fallback", cpi_redirect_url, self.croxy_base_url);
                Cow::Owned(self.croxy_base_url.host_str()
                    .expect("CroxyProxy base URL should have a host")
                    .to_string())
            });

        let cpi_origin_str = format!(
            "{}://{}",
            cpi_redirect_url.scheme(),
            cpi_host_for_origin.as_ref()
        );
        headers.insert(ORIGIN, HeaderValue::from_str(&cpi_origin_str)
            .with_context(|| format!("Step 7: Failed to create Origin header from CPI URL components: scheme '{}', host '{}'", cpi_redirect_url.scheme(), cpi_host_for_origin))?);

        self.client
            .post(final_proxied_url.clone())
            .headers(headers)
            .body(self.deepinfra_api_body.clone())
            .timeout(Duration::from_secs(10 * 60))
            .send()
            .context("Step 7: POST request to DeepInfra API via proxy failed")
    }
}

fn process_deepinfra_stream(response_stream: BlockingResponse) -> Result<()> {
    let status = response_stream.status();
    println!("   Status from DeepInfra API via proxy: {}", status);

    if !status.is_success() {
        let error_body = response_stream
            .text()
            .context("Step 7: Failed to read error response body from DeepInfra API")?;
        bail!(
            "[FAIL] Step 7 (DeepInfra POST): HTTP {}. Body: {}",
            status,
            error_body
        );
    }

    println!("   Streaming Response Body from DeepInfra API via proxy:");
    let reader = BufReader::new(response_stream);
    let mut stdout = io::stdout();

    for line_result in reader.lines() {
        let line = line_result.context("Error reading line from stream")?;
        if line.starts_with("data: ") {
            let json_str = &line["data: ".len()..];
            if json_str.trim() == "[DONE]" {
                println!("data: [DONE]");
                stdout
                    .flush()
                    .context("Failed to flush stdout after [DONE]")?;
                break;
            }
            match serde_json::from_str::<JsonValue>(json_str) {
                Ok(json_chunk) => {
                    if let Some(content) = json_chunk
                        .get("choices")
                        .and_then(|c| c.as_array())
                        .and_then(|choices| choices.get(0))
                        .and_then(|first_choice| first_choice.get("delta"))
                        .and_then(|delta| delta.get("content"))
                        .and_then(|c| c.as_str())
                    {
                        print!("{}", content);
                        stdout
                            .flush()
                            .context("Failed to flush stdout while streaming content")?;
                    }

                    if json_chunk
                        .get("choices")
                        .and_then(|c| c.as_array())
                        .and_then(|choices| choices.get(0))
                        .and_then(|first_choice| first_choice.get("finish_reason"))
                        .and_then(|fr| fr.as_str())
                        .map_or(false, |reason| reason == "stop")
                    {
                        println!("\n[STREAM FINISHED: stop reason]");
                        stdout
                            .flush()
                            .context("Failed to flush stdout after stop reason")?;
                    }
                }
                Err(e) => {
                    eprintln!(
                        "\n[WARN] Error parsing JSON chunk: {}. Line: '{}'",
                        e, json_str
                    );
                }
            }
        } else if !line.is_empty() {
            println!("{}", line);
            stdout
                .flush()
                .context("Failed to flush stdout for non-data line")?;
        }
    }
    println!();
    Ok(())
}

fn main() -> Result<()> {
    let interactor = CroxyProxyInteractor::new(TARGET_URL_TO_PROXY, DEEPINFRA_API_BODY)
        .context("Failed to initialize CroxyProxyInteractor")?;

    println!(
        "[1] Fetching main page and initial CSRF token from {}...",
        CROXY_BASE_URL_STR
    );
    let csrf_token1 = interactor.fetch_initial_page_and_csrf()?;

    println!("\n[2] Posting to /servers to get server list and secondary CSRF token...");
    let (servers_page_url, csrf_token2, server_list_json_data_ss_str) =
        interactor.fetch_server_selection_data(&csrf_token1)?;

    println!("\n[3] Automatically selecting a proxy server...");
    let chosen_server_info = interactor
        .select_proxy_server(&server_list_json_data_ss_str)
        .context("Step 3: Failed to select a proxy server")?;
    println!(
        "   Selected Proxy Server: ID {}, Name '{}', URL {}",
        chosen_server_info.id, chosen_server_info.name, chosen_server_info.url
    );

    println!("\n[4] Posting to /requests (client will follow redirect to __cpi.php)...");
    let (cpi_url_after_redirect, cpi_page_html) = interactor
        .submit_proxy_request_and_get_cpi_details(
            &chosen_server_info,
            &csrf_token2,
            &servers_page_url,
        )
        .context("Step 4: Failed to submit proxy request or get CPI details")?;

    if let (Some(cpi_host), Some(croxy_base_host)) = (
        cpi_url_after_redirect.host_str(),
        interactor.croxy_base_url.host_str(),
    ) {
        if cpi_host != croxy_base_host
            && !cpi_host.ends_with(&format!(".{}", croxy_base_host))
            && !croxy_base_host.ends_with(&format!(".{}", cpi_host))
        {
            println!(
                "[INFO] CPI page host ({}) differs significantly from CroxyProxy base host ({}). This might be unexpected or part of a complex proxy setup.",
                cpi_host, croxy_base_host
            );
        } else if cpi_host != croxy_base_host {
            println!(
                "[INFO] CPI page host ({}) differs from CroxyProxy base host ({}). This is typical for subdomained proxy servers.",
                cpi_host, croxy_base_host
            );
        }
    }

    println!("\n[5 & 6] Parsing __cpi.php page content and getting final proxied URL...");
    let final_proxied_url = interactor
        .extract_final_proxied_url_from_cpi_page(&cpi_page_html)
        .context("Step 5/6: Failed to extract final proxied URL")?;

    println!(
        "\n[7] POSTing to DeepInfra API via proxy {} and streaming response...",
        final_proxied_url
    );
    let response_stream = interactor
        .stream_from_proxied_url(&final_proxied_url, &cpi_url_after_redirect)
        .context("Step 7: Failed to initiate stream from proxied URL")?;

    process_deepinfra_stream(response_stream).context("Error processing DeepInfra stream")?;

    Ok(())
}
