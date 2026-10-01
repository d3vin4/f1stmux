//! Realm QuickJS: cài `__f1host` (bridge sang DOM của Rust), nạp lớp vờ DOM,
//! rồi chạy script của trang và script của plugin.

use crate::dom::Dom;
use rquickjs::{Context, Ctx, Function, Object, Runtime, Value};
use std::cell::RefCell;
use std::rc::Rc;

/// Kết quả chạy JS trên trang.
#[derive(Debug, Default)]
pub struct JsOut {
    pub console: Vec<(String, String)>,
    pub errors: Vec<String>,
    pub timers: usize,
    pub timed_out: bool,
}

const MAX_STEPS: usize = 2_000_000;

pub struct Realm {
    pub rt: Runtime,
    pub ctx: Context,
    pub dom: Rc<RefCell<Dom>>,
    console: Rc<RefCell<Vec<(String, String)>>>,
    errors: Rc<RefCell<Vec<String>>>,
    timers: Rc<RefCell<usize>>,
    pub deadline: std::time::Instant,
}

/// Thông tin môi trường JS — truyền vào để lớp vờ DOM dựng global cho khớp profile.
pub struct Env {
    pub ua: &'static str,
    pub platform: &'static str,
    pub concurrency: u32,
    pub device_memory: u32,
    pub screen: (u32, u32),
    pub title: &'static str,
    pub url: &'static str,
    pub cookie: &'static str,
    pub timezone: &'static str,
}

impl Realm {
    pub fn new(dom: Rc<RefCell<Dom>>, e: &Env) -> rquickjs::Result<Self> {
        let rt = Runtime::new()?;
        rt.set_memory_limit(128 * 1024 * 1024);
        rt.set_max_stack_size(4 * 1024 * 1024);
        let ctx = Context::full(&rt)?;

        let console = Rc::new(RefCell::new(Vec::new()));
        let errors = Rc::new(RefCell::new(Vec::new()));
        let timers = Rc::new(RefCell::new(0usize));

        // Copy ra khỏi `e` để closure trong `with` không mượn `e`.
        let (ua, platform, conc, mem, sw, sh, title, url, cookie, tz) = (
            e.ua, e.platform, e.concurrency, e.device_memory,
            e.screen.0 as f64, e.screen.1 as f64,
            e.title, e.url, e.cookie, e.timezone,
        );

        ctx.with(|ctx: Ctx| -> rquickjs::Result<()> {
            let g = ctx.globals();
            let host = Object::new(ctx.clone())?;

            host.set("name", Function::new(ctx.clone(), {
                let d = dom.clone();
                move |id: i32| d.borrow().get(id as usize).map(|n| n.name.clone()).unwrap_or_default()
            })?)?;
            host.set("parent", Function::new(ctx.clone(), {
                let d = dom.clone();
                move |id: i32| d.borrow().get(id as usize).and_then(|n| n.parent).map(|p| p as i32).unwrap_or(-1)
            })?)?;
            host.set("children", Function::new(ctx.clone(), {
                let d = dom.clone();
                move |id: i32| -> Vec<i32> {
                    d.borrow().get(id as usize).map(|n| n.children.iter().map(|c| *c as i32).collect()).unwrap_or_default()
                }
            })?)?;
            host.set("attrs", Function::new(ctx.clone(), {
                let d = dom.clone();
                move |id: i32| -> Vec<Vec<String>> {
                    d.borrow().get(id as usize).map(|n| n.attrs.iter().map(|(k, v)| vec![k.clone(), v.clone()]).collect()).unwrap_or_default()
                }
            })?)?;
            host.set("attr", Function::new(ctx.clone(), {
                let d = dom.clone();
                move |id: i32, k: String| -> Option<String> {
                    d.borrow().get(id as usize).and_then(|n| n.attrs.iter().find(|(a, _)| *a == k).map(|(_, v)| v.clone()))
                }
            })?)?;
            host.set("setAttr", Function::new(ctx.clone(), {
                let d = dom.clone();
                move |id: i32, k: String, v: String| { d.borrow_mut().set_attr(id as usize, &k, &v); }
            })?)?;
            host.set("setText", Function::new(ctx.clone(), {
                let d = dom.clone();
                move |id: i32, v: String| {
                    if let Some(n) = d.borrow_mut().nodes.get_mut(id as usize) { n.text = v; }
                }
            })?)?;
            host.set("remove", Function::new(ctx.clone(), {
                let d = dom.clone();
                move |id: i32| { d.borrow_mut().remove(id as usize); }
            })?)?;
            host.set("innerHtml", Function::new(ctx.clone(), {
                let d = dom.clone();
                move |id: i32| d.borrow().inner_html(id as usize)
            })?)?;
            host.set("text", Function::new(ctx.clone(), {
                let d = dom.clone();
                move |id: i32| d.borrow().text_content(id as usize)
            })?)?;
            host.set("query", Function::new(ctx.clone(), {
                let d = dom.clone();
                move |sel: String, from: i32| -> Vec<i32> {
                    d.borrow().query(&sel, from.max(0) as usize)
                        .map(|v| v.into_iter().map(|i| i as i32).collect())
                        .unwrap_or_default()
                }
            })?)?;
            host.set("create", Function::new(ctx.clone(), {
                let d = dom.clone();
                move |t: String| -> i32 {
                    let mut g = d.borrow_mut();
                    let id = g.nodes.len();
                    g.nodes.push(crate::dom::Node { id, parent: None, name: t, attrs: vec![], text: String::new(), children: vec![], raw: false });
                    id as i32
                }
            })?)?;
            host.set("createText", Function::new(ctx.clone(), {
                let d = dom.clone();
                move |t: String| -> i32 {
                    let mut g = d.borrow_mut();
                    let id = g.nodes.len();
                    g.nodes.push(crate::dom::Node { id, parent: None, name: "#text".into(), attrs: vec![], text: t, children: vec![], raw: false });
                    id as i32
                }
            })?)?;

            host.set("title", Function::new(ctx.clone(), move || title.to_string())?)?;
            host.set("url", Function::new(ctx.clone(), move || url.to_string())?)?;
            host.set("cookie", Function::new(ctx.clone(), move || cookie.to_string())?)?;
            host.set("ua", Function::new(ctx.clone(), move || ua.to_string())?)?;
            host.set("platform", Function::new(ctx.clone(), move || platform.to_string())?)?;
            host.set("concurrency", Function::new(ctx.clone(), move || conc as f64)?)?;
            host.set("deviceMemory", Function::new(ctx.clone(), move || mem as f64)?)?;
            host.set("screenW", Function::new(ctx.clone(), move || sw)?)?;
            host.set("screenH", Function::new(ctx.clone(), move || sh)?)?;
            host.set("timezone", Function::new(ctx.clone(), move || tz.to_string())?)?;

            // Storage: không trả Object từ function (rquickjs lifetime invariant).
            // Expose 4 hàm nguyên thủy; dom.js bọc thành localStorage/sessionStorage.
            host.set("storageGet", Function::new(ctx.clone(), move |k: String| hstorage::get(&k))?)?;
            host.set("storageSet", Function::new(ctx.clone(), move |k: String, v: String| { hstorage::set(&k, &v); })?)?;
            host.set("storageRemove", Function::new(ctx.clone(), move |k: String| { hstorage::clear_key(&k); })?)?;
            host.set("storageClear", Function::new(ctx.clone(), move || hstorage::clear())?)?;

            {
                let c = console.clone();
                host.set("log", Function::new(ctx.clone(), move |kind: String, msg: String| {
                    c.borrow_mut().push((kind, msg));
                })?)?;
            }
            {
                let t = timers.clone();
                host.set("timeout", Function::new(ctx.clone(), move |_cb: Value, _ms: f64| {
                    *t.borrow_mut() += 1;
                })?)?;
            }

            g.set("__f1host", host)?;
            Ok(())
        })?;

        Ok(Self {
            rt,
            ctx,
            dom,
            console,
            errors,
            timers,
            deadline: std::time::Instant::now() + std::time::Duration::from_secs(10),
        })
    }

    /// Chạy script. Lỗi được thu thập chứ không làm sập — trang hỏng vẫn đọc được phần còn lại.
    pub fn run(&self, src: &str, tag: &str) {
        let r = self.ctx.with(|c| c.eval::<Value, _>(src).map(|_| ()));
        if let Err(e) = r {
            self.errors.borrow_mut().push(format!("{tag}: {e}"));
        }
    }

    /// Chạy script, trả về JSON. Script phải tự `JSON.stringify`.
    pub fn eval_json(&self, src: &str) -> Result<serde_json::Value, String> {
        // `src` là expression (giống DevTools console). Chạy qua eval trong để
        // cả expression lẫn statement đều chạy được; statement trả về Null.
        let arg = serde_json::to_string(src).unwrap_or_default();
        let wrapped = format!("JSON.stringify((function(__s){{ return (0, eval(__s)); }})({arg}))");
        let s: Result<String, _> = self.ctx.with(|c| c.eval(wrapped));
        match s {
            Ok(s) => serde_json::from_str(&s).map_err(|e| e.to_string()),
            // JSON.stringify(undefined) → undefined, không phải string.
            Err(_) => Ok(serde_json::Value::Null),
        }
    }

    pub fn expired(&self) -> bool {
        std::time::Instant::now() > self.deadline
    }

    pub fn take(&self) -> JsOut {
        JsOut {
            console: self.console.borrow().clone(),
            errors: self.errors.borrow().clone(),
            timers: *self.timers.borrow(),
            timed_out: self.expired(),
        }
    }
}

/// Storage tĩnh, đủ cho script trang kiểm tra sự tồn tại.
pub mod hstorage {
    use std::cell::RefCell;
    thread_local! {
        static KV: RefCell<std::collections::HashMap<String, String>> = RefCell::new(std::collections::HashMap::new());
    }
    pub fn get(k: &str) -> Option<String> { KV.with(|m| m.borrow().get(k).cloned()) }
    pub fn set(k: &str, v: &str) { KV.with(|m| m.borrow_mut().insert(k.into(), v.into())); }
    pub fn clear() { KV.with(|m| m.borrow_mut().clear()); }
    pub fn clear_key(k: &str) { KV.with(|m| { m.borrow_mut().remove(k); }); }
    pub fn all() -> std::collections::HashMap<String, String> { KV.with(|m| m.borrow().clone()) }
}

pub const DOM_JS: &str = include_str!("../assets/dom.js");
pub const MAX_SCRIPT_STEPS: usize = MAX_STEPS;
