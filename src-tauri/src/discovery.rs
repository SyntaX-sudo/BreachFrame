//! Locate MCP client configuration files in well-known per-OS locations.
//! Files are only listed here; nothing is read until the user imports one.

use serde::Serialize;
use std::path::PathBuf;

#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveredConfig {
    pub client: String,
    pub path: String,
    pub size: u64,
}

fn candidates() -> Vec<(&'static str, PathBuf)> {
    let mut out = Vec::new();
    let home = dirs::home_dir();
    let config = dirs::config_dir(); // %APPDATA% | ~/Library/Application Support | ~/.config
    if let Some(c) = &config {
        out.push((
            "Claude Desktop",
            c.join("Claude").join("claude_desktop_config.json"),
        ));
        out.push(("VS Code", c.join("Code").join("User").join("mcp.json")));
        out.push((
            "VS Code (settings)",
            c.join("Code").join("User").join("settings.json"),
        ));
        out.push((
            "VS Code Insiders",
            c.join("Code - Insiders").join("User").join("mcp.json"),
        ));
    }
    if let Some(h) = &home {
        out.push(("Claude Code", h.join(".claude.json")));
        out.push(("Claude Code (project)", h.join(".mcp.json")));
        out.push(("Cursor", h.join(".cursor").join("mcp.json")));
        out.push((
            "Windsurf",
            h.join(".codeium").join("windsurf").join("mcp_config.json"),
        ));
        out.push(("Gemini CLI", h.join(".gemini").join("settings.json")));
        // Linux Claude Desktop builds and some tools use ~/.config even on macOS.
        out.push((
            "Claude Desktop (~/.config)",
            h.join(".config")
                .join("Claude")
                .join("claude_desktop_config.json"),
        ));
    }
    out
}

pub fn discover() -> Vec<DiscoveredConfig> {
    let mut seen = std::collections::HashSet::new();
    candidates()
        .into_iter()
        .filter_map(|(client, path)| {
            let meta = std::fs::metadata(&path).ok()?;
            if !meta.is_file() || !seen.insert(path.clone()) {
                return None;
            }
            Some(DiscoveredConfig {
                client: client.to_string(),
                path: path.display().to_string(),
                size: meta.len(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn candidates_are_absolute() {
        for (_, p) in super::candidates() {
            assert!(p.is_absolute(), "{}", p.display());
        }
    }
}
