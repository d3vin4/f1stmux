// JS-side API shim for plugins.
//
// Rust installs `__plugin` before running this file. `__plugin` is the ONLY
// place permissions are checked — if a plugin goes around it (touching
// `__f1host` directly) the host cannot check, so this shim never touches
// `__f1host`.
//
// Plugin file structure:
//     plugin.log('hello');
//     plugin.on('onDOMReady', (ctx) => { plugin.dom.query('h1'); });
//     module.exports = { onDOMReady() {} };   // or assign to plugin.exports directly
(function () {
  'use strict';

  var B = globalThis.__plugin;
  if (!B) throw new Error('f1stmux: missing __plugin bridge — host bug');
  if (globalThis.plugin) return; // already installed (same-realm reload)

  var HOOKS = [
    'onRequest', 'onResponse', 'onDOMReady', 'onToolCall', 'onPageScript',
    'onSessionCreate', 'onSessionEnd',
  ];

  var state = { hooks: {} };
  globalThis.__pluginState = state;

  // Missing permission throws right at the call site: the plugin sees its own
  // lack of permission instead of silently getting empty results and blaming the page.
  function need(perm, what) {
    if (!B.permitted(perm)) {
      throw new Error('f1stmux: missing permission ' + perm + ' for ' + what +
        ' (violation recorded — the host will report it)');
    }
  }

  var plugin = {
    id: B.id,
    api: B.api,
    hostApi: B.hostApi,
    hooks: HOOKS,
    // Current permission list — handy for `plugin.log(JSON.stringify(plugin.perms))`.
    perms: B.permissions(),

    // Plugin hooks and exports. No need to know names upfront: `plugin.on` records here.
    exports: {},

    // Register a tool for the agent. `schema` is JSON Schema — the host keeps it as-is, no validation.
    tool: function (name, schema) {
      need('tool.register', 'plugin.tool()');
      B.tool(String(name), JSON.stringify(schema || {}));
      return plugin;
    },

    // Register a handler for a hook. The handler receives the host payload (see the hook docs).
    on: function (hook, fn) {
      if (HOOKS.indexOf(hook) < 0) {
        throw new Error('f1stmux: unknown hook "' + hook + '"; have: ' + HOOKS.join(', '));
      }
      if (typeof fn !== 'function') {
        throw new Error('f1stmux: handler for ' + hook + ' must be a function');
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
      // Returns an array of node ids. `plugin.dom.wrap(id)` for compact text/html.
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
      // Block a URL. `false` = no permission or host refused.
      block: function (url) {
        need('net.intercept', 'plugin.request.block()');
        return B.block(String(url));
      },
    },
  };

  function num(v) {
    var n = Number(v);
    if (!isFinite(n) || n < 0) throw new Error('f1stmux: invalid node id: ' + v);
    return Math.floor(n);
  }

  // Log objects without throwing on circular refs — logging is a debug path, not a place to crash.
  function safeJson(v) {
    try {
      return JSON.stringify(v);
    } catch (e) {
      return String(v);
    }
  }

  globalThis.plugin = plugin;
  // Lets plugins use the familiar CommonJS style. The host merges `module.exports`
  // into `plugin.exports` after the entry finishes, so both styles work.
  globalThis.module = { exports: plugin.exports };
})();
