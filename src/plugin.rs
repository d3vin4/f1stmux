//! Plugins: install anything (tool, inspector, parser, agent, proxy, hook) without
//! touching the core.
//!
//! Two kinds — `js` (inside a QuickJS realm), `proc` (subprocess) — both speaking
//! JSON-lines. NEVER load a dylib: a dylib is an ABI constraint (it breaks on every
//! crate version bump) and a bug in a plugin would take down the whole daemon instead
//! of just one child process.
//!
//! Permissions are enforced at RUN TIME, not only at load: `PluginCtx` records an
//! entry in `violations` every time a plugin calls something it is not allowed to.

use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::rc::Rc;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use crate::jsenv::Realm;

/// The plugin API version this host understands. A manifest declaring a higher one is rejected.
pub const CURRENT_API_VERSION: u32 = 1;
/// The manifest filename inside a plugin directory.
pub const MANIFEST_FILE: &str = "plugin.json";

/// The JS shell for plugins, read from disk at compile time (`include_str` — no I/O at run time).
pub const PLUGIN_API_JS: &str = include_str!("../assets/plugin-api.js");

// ---------------------------------------------------------------------------
// Manifest
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PluginKind {
    /// Runs inside the host's QuickJS realm.
    Js,
    /// Runs as a subprocess, talking JSON-lines over stdin/stdout.
    Proc,
    /// Needs a wasm runtime — no crate yet, so running it reports a clear error.
    Wasm,
}

impl PluginKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Js => "js",
            Self::Proc => "proc",
            Self::Wasm => "wasm",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Permission {
    #[serde(rename = "net.intercept")]
    NetIntercept,
    #[serde(rename = "dom.read")]
    DomRead,
    #[serde(rename = "dom.write")]
    DomWrite,
    #[serde(rename = "page.script")]
    PageScript,
    #[serde(rename = "session.read")]
    SessionRead,
    #[serde(rename = "tool.register")]
    ToolRegister,
    #[serde(rename = "storage")]
    Storage,
}

pub const ALL_PERMISSIONS: &[Permission] = &[
    Permission::NetIntercept,
    Permission::DomRead,
    Permission::DomWrite,
    Permission::PageScript,
    Permission::SessionRead,
    Permission::ToolRegister,
    Permission::Storage,
];

impl Permission {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NetIntercept => "net.intercept",
            Self::DomRead => "dom.read",
            Self::DomWrite => "dom.write",
            Self::PageScript => "page.script",
            Self::SessionRead => "session.read",
            Self::ToolRegister => "tool.register",
            Self::Storage => "storage",
        }
    }

    pub fn from_name(s: &str) -> Option<Self> {
        ALL_PERMISSIONS.iter().copied().find(|p| p.as_str() == s)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Hook {
    #[serde(rename = "onRequest")]
    OnRequest,
    #[serde(rename = "onResponse")]
    OnResponse,
    #[serde(rename = "onDOMReady")]
    OnDomReady,
    #[serde(rename = "onToolCall")]
    OnToolCall,
    #[serde(rename = "onPageScript")]
    OnPageScript,
    #[serde(rename = "onSessionCreate")]
    OnSessionCreate,
    #[serde(rename = "onSessionEnd")]
    OnSessionEnd,
}

pub const ALL_HOOKS: &[Hook] = &[
    Hook::OnRequest,
    Hook::OnResponse,
    Hook::OnDomReady,
    Hook::OnToolCall,
    Hook::OnPageScript,
    Hook::OnSessionCreate,
    Hook::OnSessionEnd,
];

impl Hook {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OnRequest => "onRequest",
            Self::OnResponse => "onResponse",
            Self::OnDomReady => "onDOMReady",
            Self::OnToolCall => "onToolCall",
            Self::OnPageScript => "onPageScript",
            Self::OnSessionCreate => "onSessionCreate",
            Self::OnSessionEnd => "onSessionEnd",
        }
    }

    pub fn from_name(s: &str) -> Option<Self> {
        ALL_HOOKS.iter().copied().find(|h| h.as_str() == s)
    }

    /// The alias accepted from `plugin.on(...)` in JS (friendlier for plugin authors).
    pub fn from_js_name(s: &str) -> Option<Self> {
        Self::from_name(s).or_else(|| match s {
            "domReady" => Some(Self::OnDomReady),
            "toolCall" => Some(Self::OnToolCall),
            "pageScript" => Some(Self::OnPageScript),
            "sessionCreate" => Some(Self::OnSessionCreate),
            "sessionEnd" => Some(Self::OnSessionEnd),
            _ => None,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub id: String,
    pub name: String,
    pub version: String,
    pub kind: PluginKind,
    pub entry: String,
    /// The plugin API version needed. Higher than `CURRENT_API_VERSION` is rejected.
    #[serde(default = "default_api")]
    pub api: u32,
    #[serde(default)]
    pub permissions: Vec<Permission>,
    /// Accepts both `["onRequest"]` and `{"onRequest": 1}` (map = hook → priority).
    #[serde(default, deserialize_with = "hooks_from_any")]
    pub hooks: Vec<Hook>,
}

fn default_api() -> u32 {
    1
}

#[derive(Deserialize)]
#[serde(untagged)]
enum HooksRaw {
    List(Vec<Hook>),
    Map(BTreeMap<String, u32>),
}

fn hooks_from_any<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<Hook>, D::Error> {
    match HooksRaw::deserialize(d)? {
        HooksRaw::List(v) => Ok(v),
        HooksRaw::Map(m) => {
            let mut out = Vec::with_capacity(m.len());
            for k in m.keys() {
                match Hook::from_name(k) {
                    Some(h) => out.push(h),
                    None => return Err(serde::de::Error::custom(format!("unknown hook: {k}"))),
                }
            }
            out.sort_by_key(|h| *h as u8);
            Ok(out)
        }
    }
}

impl Manifest {
    /// Check the structure only. Use [`Manifest::validate_at`] to also check the entry file.
    pub fn validate(&self) -> Result<(), String> {
        if !valid_id(&self.id) {
            return Err(format!(
                "invalid plugin id: {:?} (must match ^[a-z0-9][a-z0-9._-]{{0,63}}$)",
                self.id
            ));
        }
        if self.name.trim().is_empty() {
            return Err("missing name".into());
        }
        if self.version.trim().is_empty() {
            return Err("missing version".into());
        }
        if self.entry.trim().is_empty() {
            return Err("missing entry".into());
        }
        let e = Path::new(&self.entry);
        if e.is_absolute() || e.components().any(|c| c.as_os_str() == "..") {
            return Err(format!("entry must be a relative path inside the plugin directory: {:?}", self.entry));
        }
        if self.api > CURRENT_API_VERSION {
            return Err(format!(
                "plugin needs api {} > {} (the host is too old, upgrade f1stmux)",
                self.api, CURRENT_API_VERSION
            ));
        }
        if self.api == 0 {
            return Err("api must be >= 1".into());
        }
        if self.hooks.is_empty() && self.kind != PluginKind::Js {
            return Err("a plugin with no hooks does nothing — declare at least 1 hook".into());
        }
        Ok(())
    }

    /// Check the structure + that the entry really lives inside `dir` (blocks path escape).
    pub fn validate_at(&self, dir: &Path) -> Result<(), String> {
        self.validate()?;
        let entry = entry_path(dir, &self.entry)?;
        if !entry.is_file() {
            return Err(format!("entry not found: {}", entry.display()));
        }
        Ok(())
    }

    /// The permissions declared in the manifest (host grants not added yet).
    pub fn permits(&self, p: Permission) -> bool {
        self.permissions.contains(&p)
    }
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id.bytes().next().is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'_' || b == b'-')
}

fn entry_path(dir: &Path, entry: &str) -> Result<PathBuf, String> {
    let p = dir.join(entry);
    // `entry` was already blocked for `..`/absolute in validate, but check again after
    // the join to be sure — it is cheap, and the entry comes from disk.
    let canon_dir = dir.canonicalize().map_err(|e| format!("{}: {e}", dir.display()))?;
    let canon = p.canonicalize().map_err(|e| format!("{}: {e}", p.display()))?;
    if !canon.starts_with(&canon_dir) {
        return Err(format!("entry is outside the plugin directory: {}", canon.display()));
    }
    Ok(canon)
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Enabled,
    Disabled,
}

pub struct LoadedPlugin {
    pub dir: PathBuf,
    pub manifest: Manifest,
    pub state: State,
    /// Extra permissions granted by the host beyond the manifest (host-side state, not in the manifest).
    pub grants: Vec<Permission>,
}

impl LoadedPlugin {
    /// The manifest plus the host grants.
    pub fn permits(&self, p: Permission) -> bool {
        self.manifest.permits(p) || self.grants.contains(&p)
    }

    pub fn enabled(&self) -> bool {
        self.state == State::Enabled
    }

    pub fn entry_path(&self) -> Result<PathBuf, String> {
        entry_path(&self.dir, &self.manifest.entry)
    }

    pub fn read_entry(&self) -> Result<String, String> {
        let p = self.entry_path()?;
        std::fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))
    }
}

/// Host-side state stored alongside the plugin, so grants/enabled survive a daemon restart.
#[derive(Serialize, Deserialize)]
struct HostState {
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default)]
    grants: Vec<Permission>,
}

fn default_true() -> bool {
    true
}

impl Default for HostState {
    fn default() -> Self {
        Self { enabled: true, grants: Vec::new() }
    }
}

fn host_state_path(dir: &Path) -> PathBuf {
    dir.join(".host.json")
}

fn read_host_state(dir: &Path) -> HostState {
    std::fs::read_to_string(host_state_path(dir))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn write_host_state(dir: &Path, st: &HostState) -> Result<(), String> {
    let body = serde_json::to_vec_pretty(st).map_err(|e| e.to_string())?;
    std::fs::write(host_state_path(dir), body).map_err(|e| format!("{}: {e}", host_state_path(dir).display()))
}

pub struct Registry {
    pub root: PathBuf,
    pub plugins: Vec<LoadedPlugin>,
    /// Plugins skipped during the scan, with the reason — so the daemon can report them instead of staying silent.
    pub skipped: Vec<(String, String)>,
}

impl Registry {
    pub fn new(root: PathBuf) -> Self {
        Self { root, plugins: Vec::new(), skipped: Vec::new() }
    }

    /// Scan `root/*/plugin.json`. Invalid ones are skipped without breaking the whole registry.
    pub fn scan(&mut self) {
        self.plugins.clear();
        self.skipped.clear();
        let Ok(rd) = std::fs::read_dir(&self.root) else { return };
        let mut dirs: Vec<PathBuf> = rd
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.is_dir())
            .collect();
        dirs.sort();
        for dir in dirs {
            match load_plugin(&dir) {
                Ok(p) => self.plugins.push(p),
                Err(e) => {
                    let id = dir
                        .file_name()
                        .map(|s| s.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    self.skipped.push((id, e));
                }
            }
        }
    }

    pub fn get(&self, id: &str) -> Option<&LoadedPlugin> {
        self.plugins.iter().find(|p| p.manifest.id == id)
    }

    pub fn list(&self) -> Vec<&LoadedPlugin> {
        self.plugins.iter().collect()
    }

    /// Plugins that are enabled and declare this hook — this is the list the hook dispatcher calls.
    pub fn by_hook(&self, h: Hook) -> Vec<&LoadedPlugin> {
        self.plugins
            .iter()
            .filter(|p| p.enabled() && p.manifest.hooks.contains(&h))
            .collect()
    }

    pub fn enable(&mut self, id: &str) -> Result<(), String> {
        self.set_enabled(id, true)
    }

    pub fn disable(&mut self, id: &str) -> Result<(), String> {
        self.set_enabled(id, false)
    }

    fn set_enabled(&mut self, id: &str, on: bool) -> Result<(), String> {
        let p = self
            .plugins
            .iter_mut()
            .find(|p| p.manifest.id == id)
            .ok_or_else(|| format!("no plugin: {id}"))?;
        p.state = if on { State::Enabled } else { State::Disabled };
        write_host_state(&p.dir, &host_state_of(p))
    }

    /// Delete the plugin from disk. Child processes must be cleaned up by `ProcHost::kill` first.
    pub fn uninstall(&mut self, id: &str) -> Result<(), String> {
        let Some(p) = self.plugins.iter().find(|p| p.manifest.id == id) else {
            return Err(format!("no plugin: {id}"));
        };
        let dir = p.dir.clone();
        std::fs::remove_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        self.plugins.retain(|p| p.manifest.id != id);
        Ok(())
    }

    pub fn grant(&mut self, id: &str, perm: Permission) -> Result<(), String> {
        let p = self
            .plugins
            .iter_mut()
            .find(|p| p.manifest.id == id)
            .ok_or_else(|| format!("no plugin: {id}"))?;
        if !p.grants.contains(&perm) {
            p.grants.push(perm);
        }
        write_host_state(&p.dir, &host_state_of(p))
    }

    pub fn revoke(&mut self, id: &str, perm: Permission) -> Result<(), String> {
        let p = self
            .plugins
            .iter_mut()
            .find(|p| p.manifest.id == id)
            .ok_or_else(|| format!("no plugin: {id}"))?;
        p.grants.retain(|x| *x != perm);
        write_host_state(&p.dir, &host_state_of(p))
    }
}

fn host_state_of(p: &LoadedPlugin) -> HostState {
    HostState { enabled: p.enabled(), grants: p.grants.clone() }
}

fn load_plugin(dir: &Path) -> Result<LoadedPlugin, String> {
    let mpath = dir.join(MANIFEST_FILE);
    let raw = std::fs::read_to_string(&mpath).map_err(|e| format!("{}: {e}", mpath.display()))?;
    let manifest: Manifest = serde_json::from_str(&raw).map_err(|e| format!("{}: {e}", mpath.display()))?;
    manifest.validate_at(dir)?;
    let hs = read_host_state(dir);
    Ok(LoadedPlugin {
        dir: dir.to_path_buf(),
        manifest,
        state: if hs.enabled { State::Enabled } else { State::Disabled },
        grants: hs.grants,
    })
}

/// Install from a plugin directory. Usable immediately afterwards, no daemon restart needed.
pub fn install_from_dir(dir: &Path, root: &Path) -> Result<String, String> {
    let mpath = dir.join(MANIFEST_FILE);
    let raw = std::fs::read_to_string(&mpath).map_err(|e| format!("{}: {e}", mpath.display()))?;
    let manifest: Manifest = serde_json::from_str(&raw).map_err(|e| format!("{}: {e}", mpath.display()))?;
    manifest.validate_at(dir)?;

    let dest = root.join(&manifest.id);
    if dest.exists() {
        return Err(format!("{} already exists — uninstall it first", dest.display()));
    }
    std::fs::create_dir_all(root).map_err(|e| format!("{}: {e}", root.display()))?;
    copy_dir(dir, &dest)?;
    Ok(manifest.id)
}

/// Does NOT auto-extract archives — there is no tar/gzip crate, and auto-extraction is
/// the easiest place to get a path traversal. The user extracts it themselves and then
/// calls `install_from_dir`.
pub fn install_from_archive(path: &Path, _root: &Path) -> Result<String, String> {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    let hint = match ext {
        "gz" | "tgz" => format!("tar -xzf {} -C <temp dir>", path.display()),
        "zip" => format!("unzip -d <temp dir> {}", path.display()),
        _ => format!("extract {} then call install_from_dir", path.display()),
    };
    Err(format!(
        "this Rust process does not extract archives (there is no tar/gzip crate, and auto-extraction is the easiest place to get a path traversal). Do it manually: {hint}"
    ))
}

fn copy_dir(from: &Path, to: &Path) -> Result<(), String> {
    let rd = std::fs::read_dir(from).map_err(|e| format!("{}: {e}", from.display()))?;
    std::fs::create_dir_all(to).map_err(|e| format!("{}: {e}", to.display()))?;
    for e in rd.filter_map(|e| e.ok()) {
        let src = e.path();
        let dst = to.join(e.file_name());
        let ft = e.file_type().map_err(|e| format!("{}: {e}", src.display()))?;
        if ft.is_dir() {
            copy_dir(&src, &dst)?;
        } else if ft.is_file() {
            // Do not preserve symlinks: a symlink is a way out of the plugin directory.
            std::fs::copy(&src, &dst).map_err(|e| format!("{} -> {}: {e}", src.display(), dst.display()))?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// PluginCtx — permission enforcement at the call site
// ---------------------------------------------------------------------------

/// A tool registered by a plugin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tool {
    pub name: String,
    pub schema: serde_json::Value,
}

type DomQueryFn = Box<dyn FnMut(&str) -> Result<Vec<usize>, String>>;
type DomTextFn = Box<dyn FnMut(usize) -> String>;
type DomWriteFn = Box<dyn FnMut(usize, &str) -> bool>;

/// The context bundle passed to the host JS. Every function checks permissions itself
/// and records `violations` when denied — there is no bypass.
pub struct PluginCtx {
    pub plugin_id: String,
    /// The source of truth for permissions: the manifest + host grants.
    pub allows: Rc<dyn Fn(Permission) -> bool>,
    pub logs: Vec<String>,
    pub violations: Vec<String>,
    /// URLs blocked via `emit_request_block`.
    pub blocked: Vec<String>,
    pub tools: Vec<Tool>,
    pub query: Option<DomQueryFn>,
    pub text: Option<DomTextFn>,
    pub html: Option<DomTextFn>,
    pub write: Option<DomWriteFn>,
}

impl PluginCtx {
    /// A ctx with no permissions — closed by default.
    pub fn new(plugin_id: &str) -> Self {
        Self {
            plugin_id: plugin_id.to_string(),
            allows: Rc::new(|_| false),
            logs: Vec::new(),
            violations: Vec::new(),
            blocked: Vec::new(),
            tools: Vec::new(),
            query: None,
            text: None,
            html: None,
            write: None,
        }
    }

    /// A ctx matching the permissions of the loaded plugin.
    pub fn for_plugin(p: &LoadedPlugin) -> Self {
        let m = p.manifest.permissions.clone();
        let g = p.grants.clone();
        Self {
            allows: Rc::new(move |x| m.contains(&x) || g.contains(&x)),
            ..Self::new(&p.manifest.id)
        }
    }

    /// Wire the real DOM into the ctx (the caller owns `Dom`, borrowed via closures).
    pub fn with_dom(
        mut self,
        query: DomQueryFn,
        text: DomTextFn,
        html: DomTextFn,
        write: DomWriteFn,
    ) -> Self {
        self.query = Some(query);
        self.text = Some(text);
        self.html = Some(html);
        self.write = Some(write);
        self
    }

    pub fn permits(&self, p: Permission) -> bool {
        (self.allows)(p)
    }

    /// `true` if allowed; otherwise records a violation and returns `false`.
    pub fn require(&mut self, p: Permission, what: &str) -> bool {
        if (self.allows)(p) {
            return true;
        }
        self.violations
            .push(format!("{}: needs the {} permission for {}", self.plugin_id, p.as_str(), what));
        false
    }

    pub fn dom_query(&mut self, sel: &str) -> Result<Vec<usize>, String> {
        if !self.require(Permission::DomRead, "dom.query") {
            return Err(format!("missing the {} permission", Permission::DomRead.as_str()));
        }
        match self.query.as_mut() {
            Some(f) => f(sel),
            None => Err("the host did not grant a DOM to the plugin".into()),
        }
    }

    pub fn dom_text(&mut self, id: usize) -> Result<String, String> {
        if !self.require(Permission::DomRead, "dom.text") {
            return Err(format!("missing the {} permission", Permission::DomRead.as_str()));
        }
        self.text
            .as_mut()
            .map(|f| f(id))
            .ok_or_else(|| "the host did not grant a DOM to the plugin".to_string())
    }

    pub fn dom_html(&mut self, id: usize) -> Result<String, String> {
        if !self.require(Permission::DomRead, "dom.html") {
            return Err(format!("missing the {} permission", Permission::DomRead.as_str()));
        }
        self.html
            .as_mut()
            .map(|f| f(id))
            .ok_or_else(|| "the host did not grant a DOM to the plugin".to_string())
    }

    pub fn dom_write(&mut self, id: usize, text: &str) -> Result<(), String> {
        if !self.require(Permission::DomWrite, "dom.write") {
            return Err(format!("missing the {} permission", Permission::DomWrite.as_str()));
        }
        match self.write.as_mut() {
            Some(f) => {
                if f(id, text) {
                    Ok(())
                } else {
                    Err(format!("node does not exist: {id}"))
                }
            }
            None => Err("the host did not grant a DOM to the plugin".into()),
        }
    }

    pub fn log(&mut self, msg: impl Into<String>) {
        if self.logs.len() < 512 {
            self.logs.push(msg.into());
        }
    }

    /// Block a URL. Without `net.intercept` it returns `false` and records a violation.
    pub fn emit_request_block(&mut self, url: &str) -> bool {
        if !self.require(Permission::NetIntercept, "request.block") {
            return false;
        }
        if self.blocked.len() < 1024 {
            self.blocked.push(url.to_string());
        }
        true
    }

    pub fn register_tool(&mut self, name: &str, schema: &serde_json::Value) -> Result<(), String> {
        if !self.require(Permission::ToolRegister, "tool.register") {
            return Err(format!("missing the {} permission", Permission::ToolRegister.as_str()));
        }
        if name.is_empty() || name.len() > 64 || name.chars().any(|c| c.is_whitespace()) {
            return Err(format!("invalid tool name: {name:?}"));
        }
        if self.tools.iter().any(|t| t.name == name) {
            return Err(format!("tool already registered: {name}"));
        }
        self.tools.push(Tool { name: name.to_string(), schema: schema.clone() });
        Ok(())
    }

    /// Whether any violations happened — the caller should drop permissions or report back.
    pub fn violated(&self) -> bool {
        !self.violations.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Host JS
// ---------------------------------------------------------------------------

/// Run the entry of a `kind: js` plugin inside the existing realm, returning
/// `{ id, api, hooks, exports, errors }`.
///
/// The realm must be supplied by the caller: a QuickJS realm is tied to the session's
/// `Rc<RefCell<Dom>>`, and creating a separate one here would produce a second DOM —
/// exactly the two-sources-of-truth bug.
pub fn run_js_plugin(
    p: &LoadedPlugin,
    realm: &Realm,
    ctx: &mut PluginCtx,
) -> Result<serde_json::Value, String> {
    match p.manifest.kind {
        PluginKind::Js => {}
        PluginKind::Proc => return Err("proc plugin: use ProcHost::call".into()),
        PluginKind::Wasm => {
            return Err("wasm plugin: there is no wasm runtime in this build".into());
        }
    }
    if !p.enabled() {
        return Err(format!("plugin {} is disabled", p.manifest.id));
    }
    let src = p.read_entry()?;
    let api = p.manifest.api;

    // Install the `__plugin` bridge (permission-checked) before running the shell and entry.
    let shared = Rc::new(RefCell::new(std::mem::replace(ctx, PluginCtx::new(&p.manifest.id))));
    install_bridge(realm, shared.clone(), &p.manifest.id, api)?;
    eval(realm, PLUGIN_API_JS, "plugin-api")?;
    eval(realm, &src, &format!("plugin:{}", p.manifest.id))?;

    let epilogue = "\
        if (globalThis.module && module.exports && module.exports !== plugin.exports) { \
          for (const k in module.exports) plugin.exports[k] = module.exports[k]; } \
        return { id: plugin.id, api: plugin.api, hooks: Object.keys(__pluginState.hooks), \
                 exports: plugin.exports === undefined ? null : plugin.exports };";
    let mut out = realm
        .eval_json(epilogue)
        .map_err(|e| format!("plugin {}: reading exports failed: {e}", p.manifest.id))?;

    // Hand the ctx (log, violation, tool) back to the caller.
    let back = std::mem::replace(&mut *shared.borrow_mut(), PluginCtx::new(&p.manifest.id));
    *ctx = back;

    if let Some(obj) = out.as_object_mut() {
        obj.insert(
            "logs".into(),
            serde_json::to_value(&ctx.logs).unwrap_or(serde_json::Value::Null),
        );
        obj.insert(
            "violations".into(),
            serde_json::to_value(&ctx.violations).unwrap_or(serde_json::Value::Null),
        );
        obj.insert(
            "tools".into(),
            serde_json::to_value(&ctx.tools).unwrap_or(serde_json::Value::Null),
        );
    }
    Ok(out)
}

fn eval(realm: &Realm, src: &str, tag: &str) -> Result<(), String> {
    realm
        .ctx
        .with(|c| c.eval::<rquickjs::Value, _>(src).map(|_| ()).map_err(|e| format!("{tag}: {e}")))
}

/// Install the `__plugin` global — every call from a plugin goes through here to enforce permissions.
fn install_bridge(
    realm: &Realm,
    ctx: Rc<RefCell<PluginCtx>>,
    id: &str,
    api: u32,
) -> Result<(), String> {
    realm
        .ctx
        .with(|c| -> rquickjs::Result<()> {
            let o = rquickjs::Object::new(c.clone())?;
            o.set("id", id)?;
            o.set("api", api as f64)?;
            o.set("hostApi", CURRENT_API_VERSION as f64)?;

            {
                let c2 = ctx.clone();
                o.set(
                    "permitted",
                    rquickjs::Function::new(c.clone(), move |name: String| -> bool {
                        Permission::from_name(&name).is_some_and(|p| c2.borrow().permits(p))
                    })?,
                )?;
            }
            {
                let c2 = ctx.clone();
                o.set(
                    "permissions",
                    rquickjs::Function::new(c.clone(), move || -> Vec<String> {
                        ALL_PERMISSIONS
                            .iter()
                            .filter(|p| c2.borrow().permits(**p))
                            .map(|p| p.as_str().to_string())
                            .collect()
                    })?,
                )?;
            }
            {
                let c2 = ctx.clone();
                o.set(
                    "log",
                    rquickjs::Function::new(c.clone(), move |msg: String| {
                        c2.borrow_mut().log(msg);
                    })?,
                )?;
            }
            {
                let c2 = ctx.clone();
                o.set(
                    "domQuery",
                    rquickjs::Function::new(c.clone(), move |sel: String| -> Vec<i32> {
                        c2.borrow_mut().dom_query(&sel).map(|ids| ids.iter().map(|i| *i as i32).collect()).unwrap_or_default()
                    })?,
                )?;
            }
            {
                let c2 = ctx.clone();
                o.set(
                    "domText",
                    rquickjs::Function::new(c.clone(), move |id: i32| -> String {
                        c2.borrow_mut().dom_text(id.max(0) as usize).unwrap_or_default()
                    })?,
                )?;
            }
            {
                let c2 = ctx.clone();
                o.set(
                    "domHtml",
                    rquickjs::Function::new(c.clone(), move |id: i32| -> String {
                        c2.borrow_mut().dom_html(id.max(0) as usize).unwrap_or_default()
                    })?,
                )?;
            }
            {
                let c2 = ctx.clone();
                o.set(
                    "domWrite",
                    rquickjs::Function::new(c.clone(), move |id: i32, t: String| -> bool {
                        c2.borrow_mut().dom_write(id.max(0) as usize, &t).is_ok()
                    })?,
                )?;
            }
            {
                let c2 = ctx.clone();
                o.set(
                    "block",
                    rquickjs::Function::new(c.clone(), move |url: String| -> bool {
                        c2.borrow_mut().emit_request_block(&url)
                    })?,
                )?;
            }
            {
                let c2 = ctx.clone();
                o.set(
                    "tool",
                    rquickjs::Function::new(c.clone(), move |name: String, schema: String| -> bool {
                        let v: serde_json::Value = match serde_json::from_str(&schema) {
                            Ok(v) => v,
                            Err(_) => return false,
                        };
                        c2.borrow_mut().register_tool(&name, &v).is_ok()
                    })?,
                )?;
            }
            c.globals().set("__plugin", o)?;
            Ok(())
        })
        .map_err(|e| format!("cannot install the plugin bridge: {e}"))
}

// ---------------------------------------------------------------------------
// Host proc
// ---------------------------------------------------------------------------

/// The default timeout for one hook call.
pub const DEFAULT_CALL_TIMEOUT: Duration = Duration::from_secs(5);
/// A JSON line longer than this limit kills the process (prevents memory blowup).
pub const MAX_LINE: usize = 1024 * 1024;

pub struct ProcHandle {
    pub id: String,
    child: Child,
    stdin: std::process::ChildStdin,
    lines: Receiver<String>,
    next_id: u64,
    /// Lines already read whose id does not match (the plugin sent them early / logged to stdout).
    spare: Vec<String>,
    pub tools: Vec<serde_json::Value>,
    pub hooks: Vec<String>,
    pub killed: bool,
}

impl Drop for ProcHandle {
    fn drop(&mut self) {
        // Always kill along with it: never leave a zombie or an orphan process.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub struct ProcHost {
    pub timeout: Duration,
    pub max_line: usize,
    procs: Vec<ProcHandle>,
}

impl Default for ProcHost {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcHost {
    pub fn new() -> Self {
        Self { timeout: DEFAULT_CALL_TIMEOUT, max_line: MAX_LINE, procs: Vec::new() }
    }

    pub fn len(&self) -> usize {
        self.procs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.procs.is_empty()
    }

    /// Run the entry of a plugin. `proc` = subprocess, never `sh -c`.
    pub fn spawn(&mut self, p: &LoadedPlugin, args: &[String]) -> Result<&mut ProcHandle, String> {
        if p.manifest.kind != PluginKind::Proc {
            return Err(format!("{} is not a proc plugin", p.manifest.id));
        }
        if !p.enabled() {
            return Err(format!("plugin {} is disabled", p.manifest.id));
        }
        let entry = p.entry_path()?;
        let mut cmd = entry_cmd(&entry)?;
        cmd.args(args);
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());

        let mut child = cmd.spawn().map_err(|e| format!("spawn {}: {e}", entry.display()))?;
        let stdin = child.stdin.take().ok_or("no stdin".to_string())?;
        let out = child.stdout.take().ok_or("no stdout".to_string())?;
        let (tx, rx) = mpsc::channel();
        let max_line = self.max_line;
        std::thread::spawn(move || pump(out, tx, max_line));

        let mut h = ProcHandle {
            id: p.manifest.id.clone(),
            child,
            stdin,
            lines: rx,
            next_id: 0,
            spare: Vec::new(),
            tools: Vec::new(),
            hooks: Vec::new(),
            killed: false,
        };
        // The handshake is optional: if the plugin does not answer, skip it — that is not an error.
        if let Ok(v) = self.call_in(&mut h, "onReady", &serde_json::json!({}), Duration::from_millis(300)) {
            if let Some(obj) = v.as_object() {
                h.tools = obj
                    .get("tools")
                    .and_then(|t| t.as_array())
                    .cloned()
                    .unwrap_or_default();
                h.hooks = obj
                    .get("hooks")
                    .and_then(|t| t.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default();
            }
        }
        self.procs.push(h);
        self.procs.last_mut().ok_or("cannot get the handle".to_string())
    }

    pub fn call(
        &mut self,
        h: &mut ProcHandle,
        hook: &str,
        payload: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let t = self.timeout;
        self.call_in(h, hook, payload, t)
    }

    /// Send `{"hook":..,"payload":..,"id":n}` and wait for `{"id":n,"result":..}`.
    /// A timeout / an over-long line / garbage JSON all kill the process.
    pub fn call_in(
        &mut self,
        h: &mut ProcHandle,
        hook: &str,
        payload: &serde_json::Value,
        timeout: Duration,
    ) -> Result<serde_json::Value, String> {
        if h.killed {
            return Err(format!("plugin {} was stopped", h.id));
        }
        h.next_id += 1;
        let id = h.next_id;
        let req = serde_json::json!({ "hook": hook, "payload": payload, "id": id });
        let mut line = req.to_string();
        line.push('\n');
        if let Err(e) = h.stdin.write_all(line.as_bytes()).and_then(|_| h.stdin.flush()) {
            h.killed = true;
            let _ = h.child.kill();
            return Err(format!("plugin {} no longer accepts input: {e}", h.id));
        }

        let deadline = Instant::now() + timeout;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                h.killed = true;
                let _ = h.child.kill();
                return Err(format!("plugin {} timed out after {:?}", h.id, timeout));
            }
            let got = match h.lines.recv_timeout(left) {
                Ok(l) => l,
                Err(RecvTimeoutError::Timeout) => {
                    h.killed = true;
                    let _ = h.child.kill();
                    return Err(format!("plugin {} timed out after {:?}", h.id, timeout));
                }
                Err(RecvTimeoutError::Disconnected) => {
                    h.killed = true;
                    return Err(format!("plugin {} has exited", h.id));
                }
            };
            if got.len() > self.max_line {
                h.killed = true;
                let _ = h.child.kill();
                return Err(format!("plugin {} wrote a line > {} bytes", h.id, self.max_line));
            }
            let v: serde_json::Value = match serde_json::from_str(&got) {
                Ok(v) => v,
                Err(e) => {
                    h.killed = true;
                    let _ = h.child.kill();
                    return Err(format!("plugin {} printed garbage JSON: {e}", h.id));
                }
            };
            if v.get("id").and_then(|i| i.as_u64()) != Some(id) {
                h.spare.push(got);
                continue;
            }
            if let Some(e) = v.get("error") {
                return Err(format!("plugin {} error: {e}", h.id));
            }
            return Ok(v.get("result").cloned().unwrap_or(serde_json::Value::Null));
        }
    }

    /// Kill one plugin's process (called on uninstall/disable).
    pub fn kill(&mut self, id: &str) -> bool {
        let before = self.procs.len();
        for h in self.procs.iter_mut() {
            if h.id == id {
                h.killed = true;
                let _ = h.child.kill();
            }
        }
        self.procs.retain(|h| h.id != id);
        self.procs.len() != before
    }

    /// Kill everything — the host `Drop` calls it too, so when the daemon dies every plugin dies with it.
    pub fn kill_all(&mut self) {
        for h in self.procs.iter_mut() {
            h.killed = true;
        }
        self.procs.clear();
    }
}

impl Drop for ProcHost {
    fn drop(&mut self) {
        self.kill_all();
    }
}

/// Read stdout into lines, capped by `cap`. Going over the cap reports an error and stops pumping.
fn pump(mut out: ChildStdout, tx: mpsc::Sender<String>, cap: usize) {
    let mut buf: Vec<u8> = Vec::with_capacity(8192);
    let mut chunk = [0u8; 8192];
    loop {
        let n = match out.read(&mut chunk) {
            Ok(0) => return,
            Ok(n) => n,
            Err(_) => return,
        };
        for &b in &chunk[..n] {
            if b == b'\n' {
                let line = String::from_utf8_lossy(&buf).trim().to_string();
                buf.clear();
                if !line.is_empty() && tx.send(line).is_err() {
                    return;
                }
            } else {
                buf.push(b);
                if buf.len() > cap {
                    let _ = tx.send(String::from_utf8_lossy(&buf).into_owned());
                    return;
                }
            }
        }
    }
}

/// The command that runs the entry: `.py` → python3, `.js` → node, `.sh` → sh, anything
/// else is the real binary (argv[0] directly). There is no `sh -c` anywhere.
fn entry_cmd(entry: &Path) -> Result<Command, String> {
    let mut c = match entry.extension().and_then(|e| e.to_str()).unwrap_or("") {
        "py" => {
            let mut c = Command::new("python3");
            c.arg(entry);
            c
        }
        "js" | "mjs" | "cjs" => {
            let mut c = Command::new("node");
            c.arg(entry);
            c
        }
        "sh" => {
            let mut c = Command::new("sh");
            c.arg(entry);
            c
        }
        _ => Command::new(entry),
    };
    if let Some(d) = entry.parent() {
        c.current_dir(d);
    }
    c.env_remove("LD_PRELOAD");
    Ok(c)
}

// ---------------------------------------------------------------------------
// Interpreter discovery
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
pub struct PluginType {
    /// The entry file extension.
    pub ext: &'static str,
    /// The matching interpreter.
    pub interp: &'static str,
    pub available: bool,
}

/// Whether the interpreter really exists on this machine (scans PATH, runs nothing).
pub fn plugin_types() -> Vec<PluginType> {
    [("py", "python3"), ("js", "node"), ("sh", "sh")]
        .iter()
        .map(|&(ext, interp)| PluginType { ext, interp, available: on_path(interp) })
        .collect()
}

fn on_path(name: &str) -> bool {
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|d| d.join(name).is_file()))
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Test
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("f1-plugin-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn manifest(id: &str, kind: PluginKind, hooks: &str) -> String {
        format!(
            r#"{{"id":"{id}","name":"T","version":"1.0.0","kind":"{}","entry":"main.txt",
                "api":1,"permissions":["dom.read"],"hooks":{hooks}}}"#,
            kind.as_str()
        )
    }

    #[test]
    fn id_and_api_and_entry_checked() {
        let mut m: Manifest = serde_json::from_str(&manifest("acme.x", PluginKind::Proc, r#"{"onRequest":1}"#)).unwrap();
        assert!(m.validate().is_ok());

        m.id = "Acme/Bad".into();
        assert!(m.validate().is_err());
        m.id = "acme.x".into();

        m.api = CURRENT_API_VERSION + 1;
        assert!(m.validate().is_err());
        m.api = 1;

        m.entry = "../outside.js".into();
        assert!(m.validate().is_err());
        m.entry = "/etc/passwd".into();
        assert!(m.validate().is_err());
    }

    #[test]
    fn hooks_accept_list_and_map() {
        let a: Manifest = serde_json::from_str(&manifest("a.b", PluginKind::Js, r#"["onDOMReady","onRequest"]"#)).unwrap();
        assert_eq!(a.hooks, vec![Hook::OnRequest, Hook::OnDomReady]);
        let b: Manifest = serde_json::from_str(&manifest("a.b", PluginKind::Js, r#"{"onRequest":1,"onToolCall":2}"#)).unwrap();
        assert_eq!(b.hooks, vec![Hook::OnRequest, Hook::OnToolCall]);
        assert!(serde_json::from_str::<Manifest>(&manifest("a.b", PluginKind::Js, r#"{"nope":1}"#)).is_err());
    }

    #[test]
    fn install_scan_grant_uninstall() {
        let root = tmpdir("root");
        let src = tmpdir("src");
        std::fs::write(src.join("main.js"), "// noop").unwrap();

        assert!(load_plugin(&src).is_err(), "a missing entry must fail");
        std::fs::write(src.join("main.txt"), "x").unwrap();
        let id = install_from_dir(&src, &root).unwrap();
        assert_eq!(id, "acme.x");
        assert!(install_from_dir(&src, &root).is_err(), "installing twice must fail");

        let mut reg = Registry::new(root.clone());
        reg.scan();
        assert_eq!(reg.list().len(), 1);
        assert!(reg.skipped.is_empty());
        assert_eq!(reg.by_hook(Hook::OnRequest).len(), 1);

        let p = reg.get("acme.x").unwrap();
        assert!(p.permits(Permission::DomRead));
        assert!(!p.permits(Permission::NetIntercept));

        reg.grant("acme.x", Permission::NetIntercept).unwrap();
        assert!(reg.get("acme.x").unwrap().permits(Permission::NetIntercept));

        // The grant must survive the next scan (not lost on a daemon restart).
        reg.scan();
        assert!(reg.get("acme.x").unwrap().permits(Permission::NetIntercept));
        reg.disable("acme.x").unwrap();
        reg.scan();
        assert!(!reg.get("acme.x").unwrap().enabled());
        assert!(reg.by_hook(Hook::OnRequest).is_empty());

        reg.uninstall("acme.x").unwrap();
        assert!(reg.list().is_empty());
        assert!(!root.join("acme.x").exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn ctx_denies_without_permission_and_records() {
        let p = LoadedPlugin {
            dir: PathBuf::from("."),
            manifest: serde_json::from_str(&manifest("a.b", PluginKind::Js, r#"["onDOMReady"]"#)).unwrap(),
            state: State::Enabled,
            grants: vec![Permission::DomWrite],
        };
        let mut ctx = PluginCtx::for_plugin(&p);
        ctx.query = Some(Box::new(|_s| Ok(vec![1, 2])));
        ctx.text = Some(Box::new(|_i| "txt".into()));

        assert!(ctx.dom_query("div").is_ok());
        assert!(ctx.dom_text(1).is_ok());
        assert!(ctx.violations.is_empty());

        assert!(ctx.dom_write(1, "x").is_err(), "dom.write was not granted");
        assert!(!ctx.emit_request_block("http://ads/"));
        assert!(ctx.register_tool("t", &serde_json::json!({})).is_err());
        assert_eq!(ctx.violations.len(), 3);
        assert!(ctx.violated());

        // With extra grants it goes through.
        let mut p2 = p;
        p2.grants.push(Permission::NetIntercept);
        p2.grants.push(Permission::ToolRegister);
        let mut ctx2 = PluginCtx::for_plugin(&p2);
        assert!(ctx2.emit_request_block("http://ads/"));
        assert!(ctx2.register_tool("scrape", &serde_json::json!({"type":"object"})).is_ok());
        assert!(!ctx2.violated());
    }

    #[test]
    fn entry_cmd_never_uses_sh_c() {
        let c = entry_cmd(Path::new("main.py")).unwrap();
        assert_eq!(c.get_program().to_string_lossy(), "python3");
        assert_eq!(c.get_args().count(), 1);
        let c = entry_cmd(Path::new("bin/tool")).unwrap();
        assert_eq!(c.get_program().to_string_lossy(), "bin/tool");
        assert_eq!(c.get_args().count(), 0, "no shell, argv holds only the entry");
    }

    #[test]
    fn plugin_types_reports_real_interpreters() {
        let t = plugin_types();
        assert_eq!(t.len(), 3);
        assert!(t.iter().any(|x| x.ext == "py" && x.available), "this machine has python3");
        assert!(t.iter().any(|x| x.ext == "js" && x.available), "this machine has node");
    }
}

/// The default plugin directory: `~/.f1stmux/plugins`.
///
/// Uses the `F1STMUX_HOME` environment variable so it is testable without touching the real home.
pub fn default_root() -> PathBuf {
    let base = std::env::var("F1STMUX_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
            PathBuf::from(home).join(".f1stmux")
        });
    base.join("plugins")
}
