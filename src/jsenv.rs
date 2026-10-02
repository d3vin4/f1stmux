//! Realm QuickJS: cài `__f1host` (bridge sang DOM của Rust), nạp lớp vờ DOM,
//! rồi chạy script của trang và script của plugin.

use crate::dom::Dom;
use rquickjs::{Context, Ctx, Function, Object, Runtime, Value};
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

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
    deadline_ms: Arc<AtomicU64>,
    steps: Arc<AtomicUsize>,
}

/// Storage của đúng một session — không còn global thread-local dùng chung.
/// Session sở hữu map này và truyền clone vào mỗi Realm nó tạo.
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

/// Thông tin môi trường JS — owned String, không Box::leak.
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
        // Interrupt handler thật: QuickJS gọi định kỳ trong eval; trả true là dừng.
        // Đây mới là ngân sách bước/thời gian có răng — MAX_STEPS trước đây chỉ là hằng số treo.
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

        // Copy ra khỏi `e` để closure trong `with` không mượn `e`.
        // (Trước đây Box::leak chuỗi ở caller — rò rỉ vĩnh viễn mỗi navigation.)
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

    /// Đặt lại ngân sách JS (ms kể từ giờ) cho cả Instant field lẫn interrupt handler.
    /// Dùng để nối `budget_ms` của client vào — deadline cứng 10s trước đây bỏ qua nó.
    pub fn set_deadline_ms(&mut self, budget_ms: u64) {
        let budget_ms = budget_ms.clamp(500, 120_000);
        self.deadline = std::time::Instant::now() + std::time::Duration::from_millis(budget_ms);
        self.deadline_ms.store(now_ms() + budget_ms, Ordering::Relaxed);
    }

    /// Chạy script. Lỗi được thu thập kèm message+stack thật (qua String()),
    /// không làm sập — trang hỏng vẫn đọc được phần còn lại.
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

    /// Chạy script, trả về JSON. Script phải tự `JSON.stringify`.
    /// Chạy expression, giữ nguyên kiểu JS (number/bool/array/object).
    /// Throw → Err(message + stack), không nuốt thành null nữa.
    pub fn eval_json(&self, src: &str) -> Result<serde_json::Value, String> {
        // `src` là expression (giống DevTools console). try/catch bọc trong nên
        // an toàn với expression; statement không giá trị trả về Null.
        let arg = serde_json::to_string(src).unwrap_or_default();
        let wrapped = format!(
            "JSON.stringify((function(__s){{ try {{ return {{ok:(0,eval(__s))}}; }} catch(e) {{ return {{err:String((e&&e.message?e.message+'\\n':'')+((e&&e.stack)||e))}}; }} }})({arg}))"
        );
        let s: Result<String, _> = self.ctx.with(|c| c.eval(wrapped));
        let s = match s {
            Ok(s) => s,
            // Phân biệt interrupt/timeout với "expression không giá trị":
            // stringify(undefined) cũng Err, nhưng ngân sách vượt là lỗi thật.
            Err(e) => {
                if self.expired() || self.steps.load(Ordering::Relaxed) > MAX_STEPS {
                    return Err(format!("JS vượt ngân sách (vòng lặp vô hạn hoặc quá nặng): {e}"));
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
