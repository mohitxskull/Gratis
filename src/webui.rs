//! Embedded admin web UI: vanilla HTML+JS, no build step, no external CDN/script tags — it
//! must work fully offline against a local daemon. Served at `GET /` by `src/api.rs`.
pub const INDEX_HTML: &str = include_str!("webui/index.html");
