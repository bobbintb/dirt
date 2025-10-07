use ini::Ini;
use std::{env, path::PathBuf};

#[derive(Debug)]
pub struct Settings {
    pub share: Vec<String>,
}

pub fn load_settings() -> anyhow::Result<Settings> {
    let search_paths = [
        PathBuf::from("/etc/dirt/dirt.cfg"),
        PathBuf::from("/boot/config/plugins/dirt/dirt.cfg"),
        env::current_exe()?.parent().unwrap().join("dirt.cfg"),
    ];

    for path in &search_paths {
        if path.exists() {
            let conf = Ini::load_from_file(path).map_err(|e| anyhow::anyhow!(e))?;
            if let Some(section) = conf.section(None::<String>) {
                if let Some(share_list) = section.get("share") {
                    let shares: Vec<String> = share_list
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                    return Ok(Settings { share: shares });
                }
            }
        }
    }

    Err(anyhow::anyhow!("Configuration file with `share` key not found in any of the specified paths"))
}