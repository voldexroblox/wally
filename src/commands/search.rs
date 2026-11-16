use std::path::PathBuf;

use anyhow::bail;
use reqwest::{blocking::Client, header::AUTHORIZATION};
use serde::Deserialize;
use structopt::StructOpt;
use termion::color::{self};

use crate::{
    auth::{self, AuthStore},
    manifest::Manifest,
    package_index::PackageIndex,
};

/// Search a registry for packages matching a query.
#[derive(Debug, StructOpt)]
pub struct SearchSubcommand {
    /// Path to a project to decide how to search
    #[structopt(long = "project-path", default_value = ".")]
    pub project_path: PathBuf,

    /// The query to be dispatched to the search endpoint
    pub query: String,
}

impl SearchSubcommand {
    pub fn run(self) -> anyhow::Result<()> {
        let manifest = Manifest::load(&self.project_path)?;
        let registry = url::Url::parse(&manifest.package.registry)?;
        let auth_store = AuthStore::load()?;
        let package_index = PackageIndex::new(&registry, None, false)?;
        let api = package_index.config()?.api;

        let auth = auth_store.tokens.get(api.as_str());

        let url = api.join("/v1/package-search/")?;

        let request = match auth {
            Some(auth) => auth::token_client(&url)?
                .get(url)
                .header(AUTHORIZATION, format!("Bearer {}", auth)),
            None => Client::new().get(url),
        }
        .query(&[("query", &self.query)]);

        let response = request.send()?;

        if !response.status().is_success() {
            bail!(
                "Failed to search: {} {}",
                response.status(),
                response.text()?
            );
        }

        let mut results: Vec<SearchResult> = response.json()?;
        println!();

        for result in &mut results {
            print!("{}{}/", color::Fg(color::LightBlack), result.scope);
            print!("{}{}", color::Fg(color::Reset), result.name);
            print!(
                "{}@{}{}",
                color::Fg(color::LightBlack),
                color::Fg(color::Green),
                result.versions.pop().unwrap(),
            );

            if !result.versions.is_empty() {
                print!(
                    "{} ({})",
                    color::Fg(color::LightBlack),
                    result.versions.join(", ")
                );
            }

            println!("{}", color::Fg(color::Reset));

            if let Some(description) = &result.description {
                println!("    {}", description);
                println!();
            }
        }

        println!();

        Ok(())
    }
}

#[derive(Deserialize)]
struct SearchResult {
    pub scope: String,
    pub name: String,
    pub versions: Vec<String>,
    pub description: Option<String>,
}
