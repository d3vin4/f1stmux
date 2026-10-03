//! QuickJS realm: install `__f1host` (the bridge into Rust's DOM), load the fake DOM
//! layer, then run the page scripts and the plugin scripts.

use crate::dom::Dom;
use rquickjs::{Context, Ctx, Function, Object, Runtime, Value};
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

/// The result of running JS on the page.
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
    deadline_ms: Arc<AtomicU64>,
    steps: Arc<AtomicUsize>,
}

/// Storage for exactly one session — no more shared global thread-local.
/// The session owns this map and passes a clone into every Realm it creates.
pub type SessionStore = Rc<RefCell<HashMap<String, String>>>;

pub fn new_store() -> SessionStore {
    Rc::new(RefCell::new(HashMap::new()))
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// JS environment info — owned Strings, no Box::leak.
pub struct Env {
    pub ua: String,
    pub platform: String,
    pub concurrency: u32,
    pub device_memory: u32,
    pub screen: (u32, u32),
    pub title: String,
    pub url: String,
    pub cookie: String,
    pub timezone: String,
}

impl Realm {
    pub fn new(dom: Rc<RefCell<Dom>>, e: &Env, store: SessionStore) -> rquickjs::Result<Self> {
        let rt = Runtime::new()?;
        rt.set_memory_limit(128 * 1024 * 1024);
        rt.set_max_stack_size(4 * 1024 * 1024);
        // A real interrupt handler: QuickJS calls it periodically during eval;
        // returning true stops it. This is what actually enforces the step/time
        // budget — MAX_STEPS used to be a constant hanging on nothing.
        let deadline_ms = Arc::new(AtomicU64::new(now_ms() + 10_000));
        let steps = Arc::new(AtomicUsize::new(0));
        {
            let dl = deadline_ms.clone();
            let st = steps.clone();
            rt.set_interrupt_handler(Some(Box::new(move || {
                st.fetch_add(1, Ordering::Relaxed) > MAX_STEPS || now_ms() > dl.load(Ordering::Relaxed)
            })));
        }
        let ctx = Context::full(&rt)?;

        let console = Rc::new(RefCell::new(Vec::new()));
        let errors = Rc::new(RefCell::new(Vec::new()));
        let timers = Rc::new(RefCell::new(0usize));

        // Copy out of `e` so the closures inside `with` do not borrow `e`.
        // (Previously the caller Box::leak the strings — a permanent leak per navigation.)
        let (ua, platform, conc, mem, sw, sh, title, url, cookie, tz) = (
            e.ua.clone(), e.platform.clone(), e.concurrency, e.device_memory,
            e.screen.0 as f64, e.screen.1 as f64,
            e.title.clone(), e.url.clone(), e.cookie.clone(), e.timezone.clone(),
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
                    d.borrow_mut().set_text_content(id as usize, &v);
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

            // Storage: do not return an Object from a function (rquickjs lifetime
            // invariant). Expose 4 primitive functions; dom.js wraps them into
            // localStorage/sessionStorage.
            host.set("storageGet", Function::new(ctx.clone(), {
                let s = store.clone();
                move |k: String| s.borrow().get(&k).cloned()
            })?)?;
            host.set("storageSet", Function::new(ctx.clone(), {
                let s = store.clone();
                move |k: String, v: String| { s.borrow_mut().insert(k, v); }
            })?)?;
            host.set("storageRemove", Function::new(ctx.clone(), {
                let s = store.clone();
                move |k: String| { s.borrow_mut().remove(&k); }
            })?)?;
            host.set("storageClear", Function::new(ctx.clone(), {
                let s = store.clone();
                move || s.borrow_mut().clear()
            })?)?;

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
            deadline_ms: deadline_ms.clone(),
            steps: steps.clone(),
        })
    }

    /// Reset the JS budget (ms from now) for both the Instant field and the interrupt handler.
    /// Used to wire in the client `budget_ms` — the previous hard 10s deadline ignored it.
    pub fn set_deadline_ms(&mut self, budget_ms: u64) {
        let budget_ms = budget_ms.clamp(500, 120_000);
        self.deadline = std::time::Instant::now() + std::time::Duration::from_millis(budget_ms);
        self.deadline_ms.store(now_ms() + budget_ms, Ordering::Relaxed);
    }

    /// Run a script. Errors are collected with the real message+stack (via String()),
    /// it does not crash — a broken page stays readable for the rest.
    pub fn run(&self, src: &str, tag: &str) {
        let r: rquickjs::Result<()> = self.ctx.with(|c| c.eval::<Value, _>(src).map(|_| ()));
        if r.is_err() {
            let msg = self.ctx.with(|c| {
                let ex = c.catch();
                if c.globals().set("__f1ex", ex).is_err() {
                    return None;
                }
                c.eval::<String, _>("String((__f1ex && __f1ex.message ? __f1ex.message + '\\n' : '') + ((__f1ex && (__f1ex.stack || __f1ex.message)) || __f1ex))").ok()
            });
            match msg {
                Some(m) => self.errors.borrow_mut().push(format!("{tag}: {m}")),
                None => self.errors.borrow_mut().push(format!("{tag}: {r:?}")),
            }
        }
    }

    /// Run a script and return JSON. The script must `JSON.stringify` itself.
    /// Runs an expression, preserving the JS type (number/bool/array/object).
    /// Throw → Err(message + stack), no longer swallowed into null.
    pub fn eval_json(&self, src: &str) -> Result<serde_json::Value, String> {
        // `src` is an expression (like the DevTools console). The try/catch wrapper
        // makes that safe; a statement with no value returns Null.
        let arg = serde_json::to_string(src).unwrap_or_default();
        let wrapped = format!(
            "JSON.stringify((function(__s){{ try {{ return {{ok:(0,eval(__s))}}; }} catch(e) {{ return {{err:String((e&&e.message?e.message+'\\n':'')+((e&&e.stack)||e))}}; }} }})({arg}))"
        );
        let s: Result<String, _> = self.ctx.with(|c| c.eval(wrapped));
        let s = match s {
            Ok(s) => s,
            // Distinguish interrupt/timeout from "the expression has no value":
            // stringify(undefined) also errors, but blowing the budget is a real error.
            Err(e) => {
                if self.expired() || self.steps.load(Ordering::Relaxed) > MAX_STEPS {
                    return Err(format!("JS exceeded the budget (infinite loop or too heavy): {e}"));
                }
                return Ok(serde_json::Value::Null);
            }
        };
        let v: serde_json::Value = serde_json::from_str(&s).map_err(|e| e.to_string())?;
        if let Some(msg) = v.get("err").and_then(|m| m.as_str()) {
            return Err(msg.to_string());
        }
        Ok(v.get("ok").cloned().unwrap_or(serde_json::Value::Null))
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

pub const DOM_JS: &str = include_str!("../assets/dom.js");
pub const MAX_SCRIPT_STEPS: usize = MAX_STEPS;
