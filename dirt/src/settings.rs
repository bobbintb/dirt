use serde::Deserialize;
use std::{env, fs, path::PathBuf};

#[derive(Debug, Deserialize)]
pub struct Settings {
    pub share: Vec<String>,
}

pub fn load_settings() -> anyhow::Result<Settings> {
    let search_paths = [
        PathBuf::from("/etc/dirt/settings.toml"),
        PathBuf::from("/boot/config/plugins/bobbintb.system.dirt/settings.toml"),
        env::current_exe()?.parent().unwrap().join("settings.toml"),
    ];

    for path in &search_paths {
        if path.exists() {
            let content = fs::read_to_string(path)?;
            let settings: Settings = toml::from_str(&content)?;
            return Ok(settings);
        }
    }

    Err(anyhow::anyhow!("Configuration file not found in any of the specified paths"))
}