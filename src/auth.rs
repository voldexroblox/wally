//! Defines storage of authentication information when interacting with
//! registries.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};

use anyhow::{bail, format_err, Context};
use reqwest::blocking::Client;
use reqwest::redirect;
use serde::{Deserialize, Serialize};
use toml_edit::{table, value, Document, Item};
use url::{Host, Url};

const DEFAULT_AUTH_TOML: &str = r#"
# This is where Wally stores details for authenticating with registries.
# It can be updated using `wally login` and `wally logout`.

[tokens]

"#;

#[derive(Serialize, Deserialize)]
pub struct AuthStore {
    pub tokens: HashMap<String, String>,
}

impl AuthStore {
    pub fn load() -> anyhow::Result<Self> {
        let path = file_path()?;
        let contents = Self::contents(&path)?;

        let auth = toml::from_str(&contents).with_context(|| {
            format!(
                "Malformed Wally auth config file. Try deleting {}",
                path.display()
            )
        })?;

        Ok(auth)
    }

    /// Simplifies the usecase of AuthStore::load()?.tokens.get(key)
    /// If multiple tokens are needed you should use AuthStore::load()?.tokens instead
    pub fn get_token(key: &str) -> anyhow::Result<Option<String>> {
        // As this auth store will only live as long as this function we can just remove the value
        // to give ownership to whatever needs it
        Ok(Self::load()?.tokens.remove(key))
    }

    pub fn set_token(key: &str, token: Option<&str>) -> anyhow::Result<()> {
        let path = file_path()?;
        let contents = Self::contents(&path)?;

        let mut auth: Document = contents.parse().unwrap();

        if !auth.as_table_mut().contains_table("tokens") {
            auth["tokens"] = table();
        }

        let tokens = auth.as_table_mut().entry("tokens");

        if let Some(token) = token {
            tokens[key] = value(token);
        } else {
            tokens[key] = Item::None;
        }

        fs_err::create_dir_all(path.parent().unwrap())?;
        fs_err::write(&path, auth.to_string())?;

        Ok(())
    }

    fn contents(path: &Path) -> anyhow::Result<String> {
        match fs_err::read_to_string(&path) {
            Ok(contents) => Ok(contents),
            Err(err) => {
                if err.kind() == io::ErrorKind::NotFound {
                    Ok(DEFAULT_AUTH_TOML.to_owned())
                } else {
                    return Err(err.into());
                }
            }
        }
    }
}

/// Refuses URLs that would expose a registry token in cleartext. Tokens may
/// only be sent over HTTPS, or over plain HTTP to a loopback host for local
/// development.
pub fn check_token_url(url: &Url) -> anyhow::Result<()> {
    match url.scheme() {
        "https" => Ok(()),
        "http" if is_loopback(url) => Ok(()),
        _ => bail!(
            "Refusing to use a registry token with {}: the registry API must use https \
             (plain http is only allowed for localhost)",
            url
        ),
    }
}

/// Builds a client for a request that carries a registry token to `url`.
///
/// reqwest keeps the Authorization header on redirects that stay on the same
/// host and port, even if they downgrade from https to http, so redirects are
/// checked with `check_token_url` too. Loopback requests skip any configured
/// proxy, which could otherwise carry the token off this machine in cleartext.
pub fn token_client(url: &Url) -> anyhow::Result<Client> {
    check_token_url(url)?;

    let policy = redirect::Policy::custom(|attempt| {
        if let Err(err) = check_token_url(attempt.url()) {
            attempt.error(err)
        } else if attempt.previous().len() >= 10 {
            attempt.error(format_err!("too many redirects"))
        } else {
            attempt.follow()
        }
    });

    let mut builder = Client::builder().redirect(policy);

    if url.scheme() == "http" {
        log::warn!(
            "Sending a registry token over plain http to local address {}",
            url
        );
        builder = builder.no_proxy();
    }

    Ok(builder.build()?)
}

fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        None => false,
    }
}

fn file_path() -> anyhow::Result<PathBuf> {
    let mut path = dirs::home_dir().context("Failed to find home directory")?;
    path.push(".wally");
    path.push("auth.toml");
    Ok(path)
}
