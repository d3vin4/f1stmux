//! Bookmarks: a tiny JSON store (title + URL) under ~/.f1stmux.
//!
//! Deliberately boring: a sorted Vec persisted whole-file on every change.
//! Bookmark collections stay small; no database needed.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bookmark {
    pub title: String,
    pub url: String,
    pub added_ms: u64,
}

fn path() -> std::path::PathBuf {
    let base = std::env::var("F1STMUX_HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
            std::path::PathBuf::from(home).join(".f1stmux")
        });
    base.join("bookmarks.json")
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub fn list() -> Vec<Bookmark> {
    std::fs::read_to_string(path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save(all: &[Bookmark]) -> Result<(), String> {
    let p = path();
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    // Atomic replace so a crash never leaves half a JSON file.
    let tmp = p.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_string_pretty(all).unwrap_or_default())
        .map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, &p).map_err(|e| e.to_string())
}

pub fn add(title: &str, url: &str) -> Result<Bookmark, String> {
    if url.trim().is_empty() {
        return Err("empty URL".into());
    }
    let mut all = list();
    if let Some(b) = all.iter().find(|b| b.url == url) {
        return Ok(b.clone());
    }
    let b = Bookmark {
        title: if title.trim().is_empty() { url.into() } else { title.into() },
        url: url.into(),
        added_ms: now_ms(),
    };
    all.push(b.clone());
    all.sort_by(|a, b| a.title.to_lowercase().cmp(&b.title.to_lowercase()));
    save(&all)?;
    Ok(b)
}

pub fn remove(url_or_title: &str) -> Result<bool, String> {
    let mut all = list();
    let n = all.len();
    all.retain(|b| b.url != url_or_title && b.title != url_or_title);
    if all.len() == n {
        return Ok(false);
    }
    save(&all)?;
    Ok(true)
}

/// First bookmark whose title or URL contains the query (for the omnibox).
pub fn find(query: &str) -> Option<Bookmark> {
    let q = query.to_ascii_lowercase();
    list().into_iter().find(|b| {
        b.title.to_ascii_lowercase().contains(&q) || b.url.to_ascii_lowercase().contains(&q)
    })
}
