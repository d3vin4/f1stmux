//! DOM + bridge into QuickJS.
//!
//! A single DOM tree living in Rust. QuickJS sees it through a thin JS shell
//! (see `assets/dom.js`). There is no second source of truth — if there were, every
//! DOM bug would be of the hardest-to-find kind.

use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::rc::Rc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    pub id: usize,
    pub parent: Option<usize>,
    /// The name, or "#text" for a text node.
    pub name: String,
    pub attrs: Vec<(String, String)>,
    pub text: String,
    pub children: Vec<usize>,
    /// A script node from the original DOM — not exposed to JS (safer, and faster).
    pub raw: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectErr {
    BadSelector,
    Oob,
}

/// The DOM tree owning the nodes; it is also the source for querySelector and for JS.
#[derive(Debug, Default)]
pub struct Dom {
    pub nodes: Vec<Node>,
}

impl Dom {
    pub fn new() -> Self {
        Self { nodes: vec![Node { id: 0, parent: None, name: "#document".into(), attrs: vec![], text: String::new(), children: vec![], raw: false }] }
    }

    fn add(&mut self, parent: usize, name: &str, text: &str) -> usize {
        let id = self.nodes.len();
        self.nodes.push(Node {
            id,
            parent: Some(parent),
            name: name.to_string(),
            attrs: vec![],
            text: text.to_string(),
            children: vec![],
            raw: false,
        });
        self.nodes[parent].children.push(id);
        id
    }

    pub fn get(&self, id: usize) -> Option<&Node> {
        self.nodes.get(id)
    }

    /// The innerHTML of one node (serialised from the tree, not from the raw string).
    pub fn inner_html(&self, id: usize) -> String {
        let Some(n) = self.nodes.get(id) else { return String::new() };
        if n.name == "#text" {
            return n.text.clone();
        }
        let mut out = String::new();
        if n.name != "#document" {
            out.push('<');
            out.push_str(&n.name);
            for (k, v) in &n.attrs {
                out.push(' ');
                out.push_str(k);
                out.push_str("=\"");
                out.push_str(&escape_attr(v));
                out.push('"');
            }
            out.push('>');
        }
        for c in &n.children {
            out.push_str(&self.inner_html(*c));
        }
        if n.name != "#document" && !VOID.contains(&n.name.as_str()) {
            out.push_str("</");
            out.push_str(&n.name);
            out.push('>');
        }
        out
    }

    pub fn set_attr(&mut self, id: usize, k: &str, v: &str) -> bool {
        let Some(n) = self.nodes.get_mut(id) else { return false };
        match n.attrs.iter_mut().find(|(a, _)| a == k) {
            Some(e) => e.1 = v.to_string(),
            None => n.attrs.push((k.into(), v.into())),
        }
        true
    }

    pub fn remove(&mut self, id: usize) -> bool {
        let Some(p) = self.nodes.get(id).and_then(|n| n.parent) else { return false };
        self.nodes[p].children.retain(|c| *c != id);
        true
    }

    pub fn text_content(&self, id: usize) -> String {
        let mut out = String::new();
        self.collect_text(id, &mut out);
        // Collapse whitespace: like a browser, and it makes the output much easier
        // for an LLM to read.
        out.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    fn collect_text(&self, id: usize, out: &mut String) {
        let Some(n) = self.nodes.get(id) else { return };
        if n.name == "#text" {
            out.push_str(&n.text);
            out.push(' ');
            return;
        }
        if SKIP.contains(&n.name.as_str()) {
            return;
        }
        for c in &n.children {
            self.collect_text(*c, out);
        }
        if BLOCK.contains(&n.name.as_str()) {
            out.push('\n');
        }
    }

    /// Simple selectors first, enough for most real work.
    /// Supported: `tag`, `#id`, `.class`, `tag#id`, `[attr]`, `tag[attr]`, combinations.
    /// Deliberately NOT a full CSS selector engine — add one when it is truly needed.
    pub fn query(&self, sel: &str, from: usize) -> Result<Vec<usize>, SelectErr> {
        let sel = sel.trim();
        if sel.is_empty() {
            return Err(SelectErr::BadSelector);
        }
        let mut matches = Vec::new();
        let mut cur = vec![from];
        let mut parts = Vec::new();
        let mut buf = String::new();
        let mut depth = 0usize;
        for c in sel.chars() {
            match c {
                '[' | '(' => { depth += 1; buf.push(c); }
                ']' | ')' => { depth = depth.saturating_sub(1); buf.push(c); }
                c if c.is_whitespace() && depth == 0 => {
                    if !buf.is_empty() { parts.push(std::mem::take(&mut buf)); }
                }
                '>' | '+' | '~' if depth == 0 => { return Err(SelectErr::BadSelector); }
                _ => buf.push(c),
            }
        }
        if !buf.is_empty() { parts.push(buf); }
        if parts.is_empty() { return Err(SelectErr::BadSelector); }
        // Only a single simple chain, or nesting by whitespace (descendant).
        let simple: Vec<&str> = parts.iter().map(|s| s.as_str()).collect();
        for &p in &simple {
            cur = cur.iter().flat_map(|&i| self.descendants(i)).collect();
            cur.retain(|&i| self.matches(i, p));
        }
        matches.extend(cur);
        Ok(matches)
    }

    fn descendants(&self, from: usize) -> Vec<usize> {
        let mut out = Vec::new();
        let mut stack: Vec<usize> = self.nodes.get(from).map(|n| n.children.clone()).unwrap_or_default();
        while let Some(id) = stack.pop() {
            out.push(id);
            if let Some(n) = self.nodes.get(id) {
                stack.extend(n.children.iter().copied());
            }
        }
        out
    }

    fn matches(&self, id: usize, simple: &str) -> bool {
        let Some(n) = self.nodes.get(id) else { return false };
        if n.name == "#text" || n.name == "#document" {
            return false;
        }
        let mut tag = "";
        let mut id_sel = "";
        let mut classes: Vec<&str> = vec![];
        let mut attrs: Vec<&str> = vec![];
        let b = simple.as_bytes();
        let mut i = 0;
        while i < b.len() {
            match b[i] {
                b'#' => { let (s, n) = token(simple, i + 1); id_sel = s; i = n; }
                b'.' => { let (s, n) = token(simple, i + 1); classes.push(s); i = n; }
                b'[' => {
                    let close = simple[i..].find(']').map(|p| i + p).unwrap_or(b.len());
                    attrs.push(&simple[i + 1..close]);
                    i = close + 1;
                }
                _ => {
                    let (s, n) = token(simple, i);
                    tag = s;
                    i = n;
                }
            }
        }
        if !tag.is_empty() && tag != "*" && n.name != tag { return false; }
        if !id_sel.is_empty() {
            match n.attrs.iter().find(|(k, _)| k == "id") {
                Some((_, v)) if v == id_sel => {}
                _ => return false,
            }
        }
        if !classes.is_empty() {
            let have = n.attrs.iter().find(|(k, _)| k == "class").map(|(_, v)| v.as_str()).unwrap_or("");
            let list: Vec<&str> = have.split_whitespace().collect();
            for want in classes {
                if !list.contains(&want) { return false; }
            }
        }
        for a in attrs {
            let a = a.trim_start_matches(|c| c == '^' || c == '$' || c == '*' || c == '~');
            let k = a.split(['=', '~', '^', '$', '*', '|']).next().unwrap_or(a);
            if !n.attrs.iter().any(|(ak, _)| ak == k) { return false; }
        }
        true
    }
}

/// Cut a selector token at a byte position. Every cut lands right before an ASCII
/// character (# . [) or at the end of the string, so it is always a valid UTF-8 char
/// boundary — no `unsafe` needed, slicing &str directly is enough.
fn token(s: &str, mut i: usize) -> (&str, usize) {
    let b = s.as_bytes();
    let start = i;
    while i < b.len() && !matches!(b[i], b'#' | b'.' | b'[') {
        i += 1;
    }
    (&s[start..i], i)
}

/// Escape an attribute value while serialising: not escaping produces broken HTML.
fn escape_attr(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for c in v.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            _ => out.push(c),
        }
    }
    out
}

static VOID: &[&str] = &["area","base","br","col","embed","hr","img","input","link","meta","source","track","wbr"];
static SKIP: &[&str] = &["script","style","noscript","template","head","meta","link","title"];
static BLOCK: &[&str] = &["p","div","section","article","header","footer","li","tr","h1","h2","h3","h4","h5","h6","br","table","ul","ol","main","nav","aside","blockquote","pre"];

/// Wrap the DOM in an Rc so it is shared between Rust and the JS shell without cloning.
pub type SharedDom = Rc<RefCell<Dom>>;