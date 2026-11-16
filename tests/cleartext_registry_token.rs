//! Spec for registry bearer tokens on non-local HTTP API URLs.
//!
//! These tests fail while the client will save or attach a bearer token for an
//! index `config.json` `api` whose scheme is `http` and whose host is not
//! loopback. They pass once login, download, search, publish, install, and
//! update refuse that URL before the token is written or put on the wire.
//!
//! `prompt_github_auth` (device flow) is not driven here. It posts to GitHub
//! and retries until a person approves the device code. The API-key login
//! branch is the one this file runs; both branches call `AuthStore::set_token`
//! with the index API address.

use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use libwally::auth::AuthStore;
use libwally::package_id::PackageId;
use libwally::package_source::{PackageSourceProvider, Registry};
use libwally::{GlobalOptions, InstallSubcommand, PublishSubcommand, SearchSubcommand};

const TOKEN: &str = "PLACEHOLDER_REGISTRY_TOKEN";

static ENV_LOCK: Mutex<()> = Mutex::new(());

struct EnvLock {
    home: PathBuf,
    previous: Vec<(&'static str, Option<std::ffi::OsString>)>,
    _guard: std::sync::MutexGuard<'static, ()>,
}

fn enter_env(label: &str) -> EnvLock {
    let guard = ENV_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let home = std::env::temp_dir().join(format!(
        "wally-cleartext-{label}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&home).unwrap();

    let keys = [
        "HOME",
        "XDG_CACHE_HOME",
        "http_proxy",
        "HTTP_PROXY",
        "https_proxy",
        "HTTPS_PROXY",
        "all_proxy",
        "ALL_PROXY",
    ];
    let previous = keys
        .iter()
        .copied()
        .map(|key| (key, std::env::var_os(key)))
        .collect::<Vec<_>>();

    std::env::set_var("HOME", &home);
    std::env::set_var("XDG_CACHE_HOME", home.join("cache"));
    for key in [
        "http_proxy",
        "HTTP_PROXY",
        "https_proxy",
        "HTTPS_PROXY",
        "all_proxy",
        "ALL_PROXY",
    ] {
        std::env::remove_var(key);
    }

    EnvLock {
        home,
        previous,
        _guard: guard,
    }
}

impl Drop for EnvLock {
    fn drop(&mut self) {
        for (key, value) in &self.previous {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
        let _ = fs::remove_dir_all(&self.home);
    }
}

fn non_loopback_ipv4() -> Ipv4Addr {
    let output = Command::new("hostname")
        .arg("-I")
        .output()
        .expect("hostname -I");
    let text = String::from_utf8_lossy(&output.stdout);
    text.split_whitespace()
        .filter_map(|part| part.parse::<Ipv4Addr>().ok())
        .find(|ip| !ip.is_loopback() && !ip.is_unspecified() && !ip.is_multicast())
        .expect("a non-loopback IPv4 address")
}

struct Server {
    addr: SocketAddr,
    saw_token: Arc<AtomicBool>,
    requests: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl Server {
    fn bind(ip: Ipv4Addr) -> Self {
        let listener = TcpListener::bind(SocketAddr::from((ip, 0))).expect("bind registry api");
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let saw_token = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let saw_token_thread = Arc::clone(&saw_token);
        let requests_thread = Arc::clone(&requests);
        let stop_thread = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            while !stop_thread.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        requests_thread.fetch_add(1, Ordering::SeqCst);
                        if serve_one(stream, TOKEN) {
                            saw_token_thread.store(true, Ordering::SeqCst);
                        }
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(err) => panic!("accept failed: {}", err),
                }
            }
        });
        Self {
            addr,
            saw_token,
            requests,
            stop,
            thread: Some(thread),
        }
    }

    fn api(&self, scheme: &str) -> String {
        format!("{scheme}://{}/", self.addr)
    }

    fn saw_token(&self) -> bool {
        self.saw_token.load(Ordering::SeqCst)
    }

    fn request_count(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn serve_one(mut stream: TcpStream, token: &str) -> bool {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut buf = Vec::new();
    let mut tmp = [0u8; 2048];
    let header_end;
    loop {
        match stream.read(&mut tmp) {
            Ok(0) => return false,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    header_end = pos + 4;
                    break;
                }
                if buf.len() > 1024 * 1024 {
                    return false;
                }
            }
            Err(_) => return false,
        }
    }
    let header_text = String::from_utf8_lossy(&buf[..header_end]).to_lowercase();
    let mut content_length = 0usize;
    for line in header_text.split("\r\n") {
        if let Some(value) = line.strip_prefix("content-length:") {
            content_length = value.trim().parse().unwrap_or(0);
        }
    }
    let mut body = buf[header_end..].to_vec();
    while body.len() < content_length {
        match stream.read(&mut tmp) {
            Ok(0) | Err(_) => break,
            Ok(n) => body.extend_from_slice(&tmp[..n]),
        }
    }
    let had_token = header_text.contains(&format!("bearer {token}").to_lowercase());
    let path = header_text
        .lines()
        .next()
        .unwrap_or("")
        .split_whitespace()
        .nth(1)
        .unwrap_or("");
    let response_body: &[u8] = if path.contains("package-search") {
        b"[]"
    } else if path.contains("publish") {
        b"{\"message\":\"ok\"}"
    } else {
        b"not-a-zip"
    };
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response_body.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.write_all(response_body);
    let _ = stream.flush();
    had_token
}

fn git(dir: &Path, args: &[&str]) {
    let output = Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_AUTHOR_NAME", "Wally Test")
        .env("GIT_AUTHOR_EMAIL", "wally-test@example.com")
        .env("GIT_COMMITTER_NAME", "Wally Test")
        .env("GIT_COMMITTER_EMAIL", "wally-test@example.com")
        .output()
        .unwrap_or_else(|err| panic!("git {:?} failed to start: {}", args, err));
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

struct Index {
    /// `file://` URL of the index git repository.
    url: String,
    root: PathBuf,
}

fn init_index(home: &Path, config_body: &str, package_manifest: Option<&str>) -> Index {
    let root = home.join("index");
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("config.json"), config_body).unwrap();
    if let Some(manifest) = package_manifest {
        let package_dir = root.join("demo");
        fs::create_dir_all(&package_dir).unwrap();
        fs::write(package_dir.join("widget"), manifest).unwrap();
    }
    git(&root, &["init", "-b", "main"]);
    git(&root, &["add", "config.json"]);
    if package_manifest.is_some() {
        git(&root, &["add", "demo"]);
    }
    git(&root, &["commit", "-m", "index"]);
    Index {
        url: format!("file://{}", root.display()),
        root,
    }
}

fn config_json(api: &str) -> String {
    format!("{{\"api\":{}}}", serde_json_string(api))
}

fn serde_json_string(value: &str) -> String {
    // Index config is JSON. The API value is a URL we generated, so escaping
    // quotes and backslashes is enough.
    format!(
        "\"{}\"",
        value.replace('\\', "\\\\").replace('"', "\\\"")
    )
}

fn project(home: &Path, index_url: &str, with_dependency: bool) -> PathBuf {
    let dir = home.join("project");
    fs::create_dir_all(&dir).unwrap();
    let deps = if with_dependency {
        "\n[dependencies]\nWidget = \"demo/widget@0.1.0\"\n"
    } else {
        ""
    };
    let manifest = format!(
        "[package]\nname = \"demo/root\"\nversion = \"0.1.0\"\nlicense = \"MIT\"\nrealm = \"shared\"\nregistry = \"{index_url}\"\n{deps}"
    );
    fs::write(dir.join("wally.toml"), manifest).unwrap();
    dir
}

fn package_manifest(index_url: &str) -> String {
    format!(
        "{{\"package\":{{\"name\":\"demo/widget\",\"version\":\"0.1.0\",\"registry\":{},\"realm\":\"shared\",\"license\":\"MIT\",\"authors\":[]}},\"dependencies\":{{}},\"server-dependencies\":{{}},\"dev-dependencies\":{{}}}}",
        serde_json_string(index_url)
    )
}

fn seed_token(api: &str) {
    AuthStore::set_token(api, Some(TOKEN)).unwrap();
}

fn auth_contains_token(home: &Path) -> bool {
    let path = home.join(".wally").join("auth.toml");
    fs::read_to_string(path)
        .map(|contents| contents.contains(TOKEN))
        .unwrap_or(false)
}

fn assert_refused(server: &Server, result: anyhow::Result<()>) {
    assert!(
        !server.saw_token(),
        "non-loopback HTTP registry received the bearer token ({} request(s))",
        server.request_count()
    );
    assert!(
        result.is_err(),
        "operation succeeded for a non-loopback HTTP registry API"
    );
}

fn global() -> GlobalOptions {
    GlobalOptions {
        verbosity: 0,
        test_registry: None,
        use_temp_index: false,
    }
}

#[test]
fn download_does_not_send_bearer_token_to_non_loopback_http() {
    let env = enter_env("download");
    let server = Server::bind(non_loopback_ipv4());
    let api = server.api("http");
    let index = init_index(&env.home, &config_json(&api), None);
    seed_token(&api);

    let registry = Registry::from_registry_spec(&index.url).unwrap();
    let package_id: PackageId = "demo/widget@0.1.0".parse().unwrap();
    let result = PackageSourceProvider::download_package(&registry, &package_id).map(|_| ());

    assert_refused(&server, result);
}

#[test]
fn search_does_not_send_bearer_token_to_non_loopback_http() {
    let env = enter_env("search");
    let server = Server::bind(non_loopback_ipv4());
    let api = server.api("http");
    let index = init_index(&env.home, &config_json(&api), None);
    let project = project(&env.home, &index.url, false);
    seed_token(&api);

    let result = SearchSubcommand {
        project_path: project,
        query: "widget".to_owned(),
    }
    .run();

    assert_refused(&server, result);
}

#[test]
fn publish_does_not_send_bearer_token_to_non_loopback_http() {
    let env = enter_env("publish");
    let server = Server::bind(non_loopback_ipv4());
    let api = server.api("http");
    let index = init_index(&env.home, &config_json(&api), None);
    let project = project(&env.home, &index.url, false);
    seed_token(&api);

    let result = PublishSubcommand {
        project_path: project,
    }
    .run(global());

    assert_refused(&server, result);
}

#[test]
fn install_does_not_send_bearer_token_to_non_loopback_http() {
    let env = enter_env("install");
    let server = Server::bind(non_loopback_ipv4());
    let api = server.api("http");
    let index = init_index(
        &env.home,
        &config_json(&api),
        Some(&package_manifest(&format!(
            "file://{}",
            env.home.join("index").display()
        ))),
    );
    let project = project(&env.home, &index.url, true);
    seed_token(&api);

    let result = InstallSubcommand {
        project_path: project,
    }
    .run(global());

    assert_refused(&server, result);
}

#[test]
fn update_does_not_send_bearer_token_to_non_loopback_http() {
    let env = enter_env("update");
    let server = Server::bind(non_loopback_ipv4());
    let api = server.api("http");
    let index = init_index(
        &env.home,
        &config_json(&api),
        Some(&package_manifest(&format!(
            "file://{}",
            env.home.join("index").display()
        ))),
    );
    let project = project(&env.home, &index.url, true);
    seed_token(&api);

    let output = Command::new(env!("CARGO_BIN_EXE_wally"))
        .args(["update", "--project-path"])
        .arg(&project)
        .env("HOME", &env.home)
        .env("XDG_CACHE_HOME", env.home.join("cache"))
        .env_remove("http_proxy")
        .env_remove("HTTP_PROXY")
        .env_remove("https_proxy")
        .env_remove("HTTPS_PROXY")
        .env_remove("all_proxy")
        .env_remove("ALL_PROXY")
        .output()
        .expect("spawn wally update");

    assert!(
        !server.saw_token(),
        "wally update sent the bearer token to non-loopback HTTP ({} request(s)): {}",
        server.request_count(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !output.status.success(),
        "wally update succeeded for a non-loopback HTTP registry API"
    );
}

#[test]
fn login_does_not_store_token_for_non_loopback_http_api() {
    let env = enter_env("login");
    let server = Server::bind(non_loopback_ipv4());
    let api = server.api("http");
    let index = init_index(&env.home, &config_json(&api), None);
    let project = project(&env.home, &index.url, false);
    let saw_during = watch_auth_file(&env.home);

    let mut child = Command::new(env!("CARGO_BIN_EXE_wally"))
        .args(["login", "--project-path"])
        .arg(&project)
        .env("HOME", &env.home)
        .env("XDG_CACHE_HOME", env.home.join("cache"))
        .env_remove("http_proxy")
        .env_remove("HTTP_PROXY")
        .env_remove("https_proxy")
        .env_remove("HTTPS_PROXY")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn wally login");
    let child_id = child.id();
    thread::spawn(move || {
        thread::sleep(Duration::from_secs(30));
        let _ = Command::new("kill").arg(child_id.to_string()).status();
    });
    {
        let mut stdin = child.stdin.take().unwrap();
        writeln!(stdin, "{TOKEN}").unwrap();
    }
    let output = child.wait_with_output().expect("wait for login");
    let stored = saw_during.load(Ordering::SeqCst) || auth_contains_token(&env.home);

    assert!(
        !stored,
        "login stored a bearer token for a non-loopback HTTP API ({})",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !output.status.success(),
        "wally login succeeded for a non-loopback HTTP registry API"
    );
    assert!(
        !server.saw_token(),
        "login sent the bearer token to the HTTP API"
    );
}

#[test]
fn loopback_http_may_still_receive_a_bearer_token() {
    let env = enter_env("loopback");
    let server = Server::bind(Ipv4Addr::LOCALHOST);
    let api = server.api("http");
    let index = init_index(&env.home, &config_json(&api), None);
    let project = project(&env.home, &index.url, false);
    seed_token(&api);

    let result = SearchSubcommand {
        project_path: project,
        query: "widget".to_owned(),
    }
    .run();

    assert!(
        result.is_ok(),
        "loopback HTTP search failed: {:?}",
        result
    );
    assert!(
        server.saw_token(),
        "loopback HTTP registry did not receive the bearer token"
    );
}

fn watch_auth_file(home: &Path) -> Arc<AtomicBool> {
    let saw = Arc::new(AtomicBool::new(false));
    let saw_thread = Arc::clone(&saw);
    let home = home.to_owned();
    thread::spawn(move || {
        for _ in 0..4000 {
            if auth_contains_token(&home) {
                saw_thread.store(true, Ordering::SeqCst);
                return;
            }
            thread::sleep(Duration::from_millis(5));
        }
    });
    saw
}
