// Lớp vờ API cho plugin, phía JS.
//
// Rust cài `__plugin` trước rồi mới chạy file này. `__plugin` là nơi DUY NHẤT quyền
// được kiểm tra — nếu plugin đi đường khác (đụng `__f1host` trực tiếp) thì host không
// kiểm được, nên lớp vờ này không bao giờ chạm vào `__f1host`.
//
// Cấu trúc file plugin:
//     plugin.log('xin chào');
//     plugin.on('onDOMReady', (ctx) => { plugin.dom.query('h1'); });
//     module.exports = { onDOMReady() {} };   // hoặc gán thẳng vào plugin.exports
(function () {
  'use strict';

  var B = globalThis.__plugin;
  if (!B) throw new Error('f1stmux: thiếu bridge __plugin — lỗi host');
  if (globalThis.plugin) return; // đã cài rồi (nạp lại cùng realm)

  var HOOKS = [
    'onRequest', 'onResponse', 'onDOMReady', 'onToolCall', 'onPageScript',
    'onSessionCreate', 'onSessionEnd',
  ];

  var state = { hooks: {} };
  globalThis.__pluginState = state;

  // Quyền thiếu thì ném lỗi ngay tại chỗ gọi: plugin tự thấy mình không có quyền
  // thay vì âm thầm nhận kết quả rỗng rồi tưởng là bug của trang.
  function need(perm, what) {
    if (!B.permitted(perm)) {
      throw new Error('f1stmux: thiếu quyền ' + perm + ' cho ' + what +
        ' (đã ghi vi phạm — host sẽ báo)');
    }
  }

  var plugin = {
    id: B.id,
    api: B.api,
    hostApi: B.hostApi,
    hooks: HOOKS,
    // Mảng quyền đang có — tiện cho `plugin.log(JSON.stringify(plugin.perms))`.
    perms: B.permissions(),

    // Hook và export của plugin. Không cần biết trước tên: `plugin.on` ghi vào đây.
    exports: {},

    // Đăng ký tool cho agent. `schema` là JSON Schema — host giữ nguyên, không validate.
    tool: function (name, schema) {
      need('tool.register', 'plugin.tool()');
      B.tool(String(name), JSON.stringify(schema || {}));
      return plugin;
    },

    // Đăng ký handler cho một hook. Handler nhận payload của host (xem doc của hook).
    on: function (hook, fn) {
      if (HOOKS.indexOf(hook) < 0) {
        throw new Error('f1stmux: hook lạ "' + hook + '"; có: ' + HOOKS.join(', '));
      }
      if (typeof fn !== 'function') {
        throw new Error('f1stmux: handler của ' + hook + ' phải là hàm');
      }
      state.hooks[hook] = fn;
      return plugin;
    },

    log: function () {
      var n = arguments.length;
      var parts = [];
      for (var i = 0; i < n; i++) {
        var a = arguments[i];
        parts.push(typeof a === 'string' ? a : safeJson(a));
      }
      B.log(parts.join(' '));
      return plugin;
    },

    dom: {
      // Trả về mảng id node. `plugin.dom.wrap(id)` để lấy text/html gọn.
      query: function (sel) {
        need('dom.read', 'plugin.dom.query()');
        return B.domQuery(String(sel));
      },
      text: function (id) {
        need('dom.read', 'plugin.dom.text()');
        return B.domText(num(id));
      },
      html: function (id) {
        need('dom.read', 'plugin.dom.html()');
        return B.domHtml(num(id));
      },
      setText: function (id, text) {
        need('dom.write', 'plugin.dom.setText()');
        return B.domWrite(num(id), String(text));
      },
    },

    request: {
      // Chặn một URL. `false` = không có quyền hoặc host từ chối.
      block: function (url) {
        need('net.intercept', 'plugin.request.block()');
        return B.block(String(url));
      },
    },
  };

  function num(v) {
    var n = Number(v);
    if (!isFinite(n) || n < 0) throw new Error('f1stmux: id node không hợp lệ: ' + v);
    return Math.floor(n);
  }

  // Log object mà không ném lỗi vì circular — log là đường gỡ lỗi, không phải chỗ để crash.
  function safeJson(v) {
    try {
      return JSON.stringify(v);
    } catch (e) {
      return String(v);
    }
  }

  globalThis.plugin = plugin;
  // Cho plugin viết kiểu CommonJS quen thuộc. Host sẽ gộp `module.exports` vào
  // `plugin.exports` sau khi entry chạy xong, nên cả hai cách viết đều được.
  globalThis.module = { exports: plugin.exports };
})();
