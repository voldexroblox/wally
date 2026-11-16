use std::collections::HashMap;
use std::io::Read;
use std::sync::Arc;

use anyhow::bail;
use once_cell::unsync::OnceCell;
use reqwest::{blocking::Client, header::AUTHORIZATION};
use url::Url;

use crate::auth::{self, AuthStore};
use crate::manifest::Manifest;
use crate::package_id::PackageId;
use crate::package_index::PackageIndex;
use crate::package_req::PackageReq;
use crate::package_source::{PackageContents, PackageSource};

pub struct Registry {
    index_url: Url,
    auth_tokens: OnceCell<Arc<HashMap<String, String>>>,
    index: OnceCell<PackageIndex>,
    client: Client,
}

impl Registry {
    /// Create a `Registry` from a registry spec, which usually comes from the
    /// `registry` field of a package manifest.
    pub fn from_registry_spec(spec: &str) -> anyhow::Result<Self> {
        let index_url = Url::parse(spec)?;

        Ok(Self {
            index_url,
            auth_tokens: OnceCell::new(),
            index: OnceCell::new(),
            client: Client::new(),
        })
    }

    fn auth_token(&self, api: &Url) -> anyhow::Result<Option<String>> {
        let tokens = self
            .auth_tokens
            .get_or_try_init(|| AuthStore::load().map(|store| Arc::new(store.tokens)))?;
        Ok(tokens.get(api.as_str()).cloned())
    }

    fn index(&self) -> anyhow::Result<&PackageIndex> {
        self.index
            .get_or_try_init(|| PackageIndex::new(&self.index_url, None, true))
    }

    fn api_url(&self) -> anyhow::Result<Url> {
        let config = self.index()?.config()?;
        Ok(config.api)
    }
}

impl PackageSource for Registry {
    fn update(&self) -> anyhow::Result<()> {
        self.index()?.update()
    }

    fn query(&self, package_req: &PackageReq) -> anyhow::Result<Vec<Manifest>> {
        let metadata = self.index()?.get_package_metadata(package_req.name())?;
        let versions: Vec<_> = metadata
            .versions
            .iter()
            .filter(|manifest| {
                package_req.matches(&manifest.package.name, &manifest.package.version)
            })
            .cloned()
            .collect();

        Ok(versions)
    }

    fn download_package(&self, package_id: &PackageId) -> anyhow::Result<PackageContents> {
        log::info!("Downloading {}...", package_id);

        let path = format!(
            "/v1/package-contents/{}/{}/{}",
            package_id.name().scope(),
            package_id.name().name(),
            package_id.version()
        );

        let api = self.api_url()?;
        let url = api.join(&path)?;

        let request = match self.auth_token(&api)? {
            Some(token) => auth::token_client(&url)?
                .get(url)
                .header(AUTHORIZATION, format!("Bearer {}", token)),
            None => self.client.get(url),
        };
        let mut response = request.send()?;

        if !response.status().is_success() {
            bail!(
                "Failed to download package {} from registry: {}",
                package_id,
                response.status()
            );
        }

        let mut data = Vec::new();
        response.read_to_end(&mut data)?;

        Ok(PackageContents::from_buffer(data))
    }
}
