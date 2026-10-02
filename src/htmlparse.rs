//! Parse HTML5 bằng html5ever, xuất ra `Dom` của ta.
//!
//! html5ever sinh `RcDom` riêng. Ta duyệt nó một lần để dựng cây của mình —
//! đổi lại ta sở hữu cây đó và bridge sang JS được sạch sẽ.

use crate::dom::Dom;
use html5ever::tendril::TendrilSink;
use html5ever::{parse_document, Attribute, LocalName, Namespace, ParseOpts};
use markup5ever_rcdom::{Handle, NodeData, RcDom};
use std::cell::RefCell;
use std::rc::Rc;

pub struct Parsed {
    pub dom: Dom,
    pub scripts: Vec<PageScript>,
    pub title: String,
}

/// Script theo đúng thứ tự xuất hiện: inline chạy code, external tải về rồi chạy.
#[derive(Debug, Clone)]
pub enum PageScript {
    Inline(String),
    External(String),
}

const HTML_NS: &str = "http://www.w3.org/1999/xhtml";

pub fn parse(html: &str) -> Parsed {
    let dom_sink = parse_document(RcDom::default(), ParseOpts::default()).one(html);
    let doc = dom_sink.document;

    let mut dom = Dom::new();
    let mut scripts = Vec::new();
    let mut title = String::new();

    fn walk(
        node: &Handle,
        parent: usize,
        dom: &mut Dom,
        scripts: &mut Vec<PageScript>,
        title: &mut String,
    ) {
        match &node.data {
            NodeData::Element { name, attrs, .. } => {
                let id = dom.nodes.len();
                let html_ns = Namespace::from(HTML_NS);
                // Attr HTML không tiền tố mang namespace RỖNG (chỉ element mới có ns html).
                // Lọc sai ở đây là rụng hết id/class/href/src.
                let attrs: Vec<(String, String)> = attrs
                    .borrow()
                    .iter()
                    .filter(|a: &&Attribute| a.name.ns.is_empty() || a.name.ns == html_ns)
                    .map(|a| (a.name.local.to_string(), a.value.to_string()))
                    .collect();
                let tag = name.local.to_string();
                let src = if tag == "script" {
                    attrs.iter().find(|(k, _)| k == "src").map(|(_, v)| v.trim().to_string()).filter(|s| !s.is_empty())
                } else {
                    None
                };
                dom.nodes.push(crate::dom::Node {
                    id,
                    parent: Some(parent),
                    name: tag.clone(),
                    attrs,
                    text: String::new(),
                    children: vec![],
                    raw: false,
                });
                dom.nodes[parent].children.push(id);
                if tag == "script" {
                    match src {
                        Some(s) => scripts.push(PageScript::External(s)),
                        None => {
                            let mut buf = String::new();
                            for c in node.children.borrow().iter() {
                                if let NodeData::Text { ref contents } = c.data {
                                    buf.push_str(contents.borrow().as_ref());
                                }
                            }
                            if !buf.trim().is_empty() {
                                scripts.push(PageScript::Inline(buf));
                            }
                        }
                    }
                }
                if tag == "title" && title.is_empty() {
                    let mut buf = String::new();
                    for c in node.children.borrow().iter() {
                        if let NodeData::Text { ref contents } = c.data {
                            buf.push_str(contents.borrow().as_ref());
                        }
                    }
                    *title = buf.trim().to_string();
                }
                let _ = LocalName::from(tag.as_str());
                for c in node.children.borrow().iter() {
                    walk(c, id, dom, scripts, title);
                }
            }
            NodeData::Text { contents } => {
                let t = contents.borrow();
                if !t.trim().is_empty() {
                    let id = dom.nodes.len();
                    dom.nodes.push(crate::dom::Node {
                        id,
                        parent: Some(parent),
                        name: "#text".into(),
                        attrs: vec![],
                        text: t.to_string(),
                        children: vec![],
                        raw: false,
                    });
                    dom.nodes[parent].children.push(id);
                }
            }
            NodeData::Document => {
                for c in node.children.borrow().iter() {
                    walk(c, parent, dom, scripts, title);
                }
            }
            _ => {}
        }
    }

    for c in doc.children.borrow().iter() {
        walk(c, 0, &mut dom, &mut scripts, &mut title);
    }

    Parsed { dom, scripts, title }
}

pub fn shared(d: Dom) -> Rc<RefCell<Dom>> {
    Rc::new(RefCell::new(d))
}
