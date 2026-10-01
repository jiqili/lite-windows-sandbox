use anyhow::{Context, Result, bail};
use reqwest::{Method, Url, blocking::Client, redirect::Policy};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    net::TcpListener,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};
use tiny_http::{Header, Request, Response, Server, StatusCode};
use zeroize::Zeroizing;

use crate::{login, providers, win};

struct Route {
    provider: &'static providers::Provider,
    placeholder: String,
    key: Zeroizing<Vec<u8>>,
}

pub struct Proxy {
    port: u16,
    routes: Arc<BTreeMap<String, Route>>,
    running: Arc<AtomicBool>,
}

impl Proxy {
    pub fn start(state: &Path) -> Result<Option<Self>> {
        let mut routes = BTreeMap::new();
        for name in login::names(state)? {
            let Some(provider) = providers::get(&name) else {
                continue;
            };
            if let Some(key) = login::key(state, &name)? {
                routes.insert(
                    name,
                    Route {
                        provider,
                        placeholder: win::random_password()?,
                        key,
                    },
                );
            }
        }
        if routes.is_empty() {
            return Ok(None);
        }
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        let server = Server::from_listener(listener, None)
            .map_err(|e| anyhow::anyhow!("HTTP listener: {e}"))?;
        let client = Client::builder()
            .redirect(Policy::none())
            .timeout(Duration::from_secs(300))
            .build()?;
        let routes = Arc::new(routes);
        let running = Arc::new(AtomicBool::new(true));
        let active = Arc::clone(&running);
        let configured = Arc::clone(&routes);
        thread::spawn(move || {
            while active.load(Ordering::Relaxed) {
                if let Ok(Some(request)) = server.recv_timeout(Duration::from_millis(100)) {
                    let routes = Arc::clone(&configured);
                    let client = client.clone();
                    thread::spawn(move || forward(request, &routes, &client));
                }
            }
        });
        Ok(Some(Self {
            port,
            routes,
            running,
        }))
    }

    pub fn config(&self) -> Value {
        Value::Object(self.routes.iter().map(|(name, route)| {
            (name.clone(), json!({
                "baseUrl": format!("http://127.0.0.1:{}/{}{}", self.port, name, route.provider.path),
                "apiKey": route.placeholder
            }))
        }).collect())
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

pub fn configure_sandbox(routes: &Value) -> Result<()> {
    let agent_dir =
        PathBuf::from(std::env::var_os("USERPROFILE").context("USERPROFILE is missing")?)
            .join(".pi")
            .join("agent");
    configure_sandbox_at(&agent_dir, routes)
}

fn configure_sandbox_at(agent_dir: &Path, routes: &Value) -> Result<()> {
    let empty = serde_json::Map::new();
    let routes = routes.as_object().unwrap_or(&empty);
    let managed_file = agent_dir.join("sandbox-proxy-providers.json");
    let previous: Vec<String> = match fs::read(&managed_file) {
        Ok(data) => serde_json::from_slice(&data)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(error) => return Err(error.into()),
    };
    if routes.is_empty() && previous.is_empty() {
        return Ok(());
    }
    fs::create_dir_all(agent_dir)?;
    let auth_file = agent_dir.join("auth.json");
    let auth = match fs::read(&auth_file) {
        Ok(data) => Some(serde_json::from_slice::<Value>(&data)?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    for name in routes.keys() {
        if auth
            .as_ref()
            .is_some_and(|stored| stored.get(name).is_some())
        {
            bail!(
                "{name} has sandbox-local credentials; remove them before using host-managed login"
            );
        }
    }
    let path = agent_dir.join("models.json");
    let mut models: Value = match fs::read(&path) {
        Ok(data) => serde_json::from_slice(&data)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => json!({"providers": {}}),
        Err(error) => return Err(error.into()),
    };
    if !models.is_object() || !models["providers"].is_object() {
        bail!("invalid sandbox models.json provider configuration");
    }
    let configured = models["providers"]
        .as_object_mut()
        .context("invalid provider config")?;
    for name in &previous {
        configured.remove(name);
    }
    for (name, route) in routes {
        if providers::get(name).is_none() {
            bail!("unsupported provider route {name}");
        }
        if configured.contains_key(name) {
            bail!("existing sandbox model configuration for {name}");
        }
        configured.insert(name.clone(), route.clone());
    }
    let temporary = agent_dir.join("models.tmp");
    fs::write(&temporary, serde_json::to_vec_pretty(&models)?)?;
    fs::rename(temporary, path)?;
    fs::write(
        managed_file,
        serde_json::to_vec(&routes.keys().collect::<Vec<_>>())?,
    )?;
    Ok(())
}

fn send(request: Request, status: u16, text: &str) {
    let _ = request.respond(Response::from_string(text).with_status_code(StatusCode(status)));
}

fn forward(mut request: Request, routes: &BTreeMap<String, Route>, client: &Client) {
    match forward_inner(&mut request, routes, client) {
        Ok(upstream) => {
            let headers = upstream
                .headers()
                .iter()
                .filter(|(name, _)| {
                    ["content-type", "cache-control", "content-encoding"].contains(&name.as_str())
                })
                .filter_map(|(name, value)| {
                    Header::from_bytes(name.as_str(), value.as_bytes()).ok()
                })
                .collect();
            let response = Response::new(
                StatusCode(upstream.status().as_u16()),
                headers,
                upstream,
                None,
                None,
            );
            let _ = request.respond(response);
        }
        Err(error) => {
            let status = if error.to_string() == "invalid placeholder credential" {
                403
            } else {
                502
            };
            send(request, status, &format!("provider proxy failed: {error}"));
        }
    }
}

fn upstream_path(name: &str, suffix: &str) -> String {
    let path = suffix.split('?').next().unwrap_or("");
    if name == "openrouter"
        && let Some(rest) = path.strip_prefix("api/v1/v1/")
    {
        return format!("/api/v1/{rest}");
    }
    format!("/{path}")
}

fn forward_inner(
    request: &mut Request,
    routes: &BTreeMap<String, Route>,
    client: &Client,
) -> Result<reqwest::blocking::Response> {
    let path = request.url().to_owned();
    let (name, suffix) = path
        .trim_start_matches('/')
        .split_once('/')
        .context("missing provider route")?;
    let route = routes.get(name).context("provider is not enabled")?;
    let allowed = ["GET", "POST"].contains(&request.method().as_str());
    if !allowed {
        bail!("unsupported request method");
    }
    let inbound = Url::parse(&format!("http://localhost/{name}/{suffix}"))?;
    let placeholder = &route.placeholder;
    let authorized = request.headers().iter().any(|header| {
        let field = header.field.as_str().as_str();
        let value = header.value.as_str();
        (field.eq_ignore_ascii_case("authorization") && value == format!("Bearer {placeholder}"))
            || (field.eq_ignore_ascii_case("x-api-key") && value == placeholder)
            || (field.eq_ignore_ascii_case("x-goog-api-key") && value == placeholder)
    }) || inbound
        .query_pairs()
        .any(|(key, value)| key == "key" && value == *placeholder);
    if !authorized {
        bail!("invalid placeholder credential");
    }
    let mut upstream = Url::parse(route.provider.origin)?;
    upstream.set_path(&upstream_path(name, suffix));
    let clean_query = inbound
        .query_pairs()
        .filter(|(key, _)| key != "key")
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    if !clean_query.is_empty() {
        upstream.query_pairs_mut().extend_pairs(clean_query);
    }
    let method = Method::from_bytes(request.method().as_str().as_bytes())?;
    let mut call = client.request(method, upstream);
    for header in request.headers() {
        let field = header.field.as_str().as_str();
        if [
            "content-type",
            "accept",
            "anthropic-version",
            "anthropic-beta",
            "openai-organization",
        ]
        .iter()
        .any(|allowed| field.eq_ignore_ascii_case(allowed))
        {
            call = call.header(field, header.value.as_str());
        }
    }
    let real_key = std::str::from_utf8(&route.key)?;
    let credential = if route.provider.bearer {
        format!("Bearer {real_key}")
    } else {
        real_key.to_owned()
    };
    call = call.header(route.provider.auth_header, credential);
    let mut body = Vec::new();
    request
        .as_reader()
        .take(32 * 1024 * 1024)
        .read_to_end(&mut body)?;
    Ok(call.body(body).send()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{BufRead, BufReader, Write},
        sync::mpsc,
    };

    #[test]
    fn forwards_stream_without_disclosing_host_key() {
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin =
            Box::leak(format!("http://{}", upstream.local_addr().unwrap()).into_boxed_str());
        let (tx, rx) = mpsc::channel();
        let backend = thread::spawn(move || {
            let (mut socket, _) = upstream.accept().unwrap();
            let mut reader = BufReader::new(socket.try_clone().unwrap());
            let mut headers = String::new();
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                headers.push_str(&line);
            }
            tx.send(headers).unwrap();
            let body = b"data: ok\n\n";
            write!(
                socket,
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .unwrap();
            socket.write_all(body).unwrap();
        });
        let provider = Box::leak(Box::new(providers::Provider {
            name: "openrouter",
            origin,
            path: "/api/v1",
            auth_header: "authorization",
            bearer: true,
        }));
        let mut routes = BTreeMap::new();
        routes.insert(
            "openrouter".into(),
            Route {
                provider,
                placeholder: "sandbox-placeholder".into(),
                key: Zeroizing::new(b"host-only-secret".to_vec()),
            },
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!(
            "http://{}/openrouter/api/v1/chat/completions",
            listener.local_addr().unwrap()
        );
        let server = Server::from_listener(listener, None).unwrap();
        let client = Client::builder().no_proxy().build().unwrap();
        let worker = thread::spawn(move || forward(server.recv().unwrap(), &routes, &client));
        let result = Client::builder()
            .no_proxy()
            .build()
            .unwrap()
            .post(url)
            .header("authorization", "Bearer sandbox-placeholder")
            .body("{}")
            .send()
            .unwrap();
        let status = result.status();
        let body = result.text().unwrap();
        worker.join().unwrap();
        backend.join().unwrap();
        assert_eq!(status, reqwest::StatusCode::OK);
        assert_eq!(body, "data: ok\n\n");
        let headers = rx.recv().unwrap().to_ascii_lowercase();
        assert!(headers.contains("authorization: bearer host-only-secret"));
        assert!(!body.contains("host-only-secret"));
    }

    #[test]
    fn rejects_requests_without_session_placeholder() {
        let mut routes = BTreeMap::new();
        routes.insert(
            "openrouter".into(),
            Route {
                provider: providers::get("openrouter").unwrap(),
                placeholder: "only-this-session".into(),
                key: Zeroizing::new(b"host-only-secret".to_vec()),
            },
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!(
            "http://{}/openrouter/api/v1/chat/completions",
            listener.local_addr().unwrap()
        );
        let server = Server::from_listener(listener, None).unwrap();
        let client = Client::builder().no_proxy().build().unwrap();
        let worker = thread::spawn(move || forward(server.recv().unwrap(), &routes, &client));
        let response = Client::builder()
            .no_proxy()
            .build()
            .unwrap()
            .post(url)
            .header("authorization", "Bearer wrong")
            .body("{}")
            .send()
            .unwrap();
        let status = response.status();
        let text = response.text().unwrap();
        worker.join().unwrap();
        assert_eq!(status, reqwest::StatusCode::FORBIDDEN);
        assert!(text.contains("invalid placeholder credential"));
        assert!(!text.contains("host-only-secret"));
    }

    #[test]
    fn preserves_openrouter_anthropic_and_openai_paths() {
        assert_eq!(
            upstream_path("openrouter", "api/v1/v1/messages"),
            "/api/v1/messages"
        );
        assert_eq!(
            upstream_path("openrouter", "api/v1/chat/completions"),
            "/api/v1/chat/completions"
        );
        assert_eq!(
            upstream_path("google", "v1beta/models/gemini:generateContent?key=dummy"),
            "/v1beta/models/gemini:generateContent"
        );
    }

    #[test]
    fn sandbox_model_routes_preserve_user_config_and_remove_stale_routes() {
        let temp = tempfile::tempdir().unwrap();
        let agent = temp.path();
        fs::write(
            agent.join("models.json"),
            r#"{"providers":{"custom":{"baseUrl":"http://localhost:7777"}}}"#,
        )
        .unwrap();
        let routes = json!({"openrouter":{"baseUrl":"http://127.0.0.1:9000/openrouter/api/v1","apiKey":"placeholder"}});
        configure_sandbox_at(agent, &routes).unwrap();
        let models: Value =
            serde_json::from_slice(&fs::read(agent.join("models.json")).unwrap()).unwrap();
        assert_eq!(
            models["providers"]["custom"]["baseUrl"],
            "http://localhost:7777"
        );
        assert_eq!(models["providers"]["openrouter"]["apiKey"], "placeholder");
        configure_sandbox_at(agent, &Value::Null).unwrap();
        let models: Value =
            serde_json::from_slice(&fs::read(agent.join("models.json")).unwrap()).unwrap();
        assert!(models["providers"].get("openrouter").is_none());
        assert!(models["providers"].get("custom").is_some());
    }
}
