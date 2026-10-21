// Shared behaviour for every live report page.
//
// This used to be copy-pasted into all eight pages, so a one-line fix meant
// eight regex edits and the copies had already drifted apart. Each page now
// supplies only what is genuinely its own: which endpoint to call and how to
// draw the result.

(function (global) {
  'use strict';

  var ESCAPES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

  function esc(v) {
    return String(v == null ? '' : v).replace(/[&<>"']/g, function (c) { return ESCAPES[c]; });
  }

  // These demo apps all carry the same prefix, which crowds out the part that matters.
  function shortApp(name) {
    return String(name == null ? '' : name).replace(/^SAML-cargocats-/, '');
  }

  // A frozen snapshot carries its own data, so it needs no server at all. The
  // fetch interceptor below means pages do not have to know about this.
  var FROZEN = global.FROZEN_DATA || null;

  if (FROZEN) {
    var realFetch = global.fetch ? global.fetch.bind(global) : null;
    global.fetch = function (url, opts) {
      if (String(url).indexOf('/api/') === 0) {
        return Promise.resolve(new Response(JSON.stringify(FROZEN.payload), {
          status: 200, headers: { 'Content-Type': 'application/json' },
        }));
      }
      return realFetch ? realFetch(url, opts) : Promise.reject(new Error('offline'));
    };
  }

  // Served from GitHub Pages there is no local server to call, unless the page
  // is a frozen snapshot, in which case it already has everything it needs.
  var HOSTED = !FROZEN && ['localhost', '127.0.0.1', ''].indexOf(global.location.hostname) === -1;

  function snapshotHref() {
    return global.location.pathname.split('/').pop().replace(/\.html$/, '_static.html');
  }

  function badge(text, kind) {
    var el = document.getElementById('sourceBadge');
    if (!el) return;
    el.textContent = text;
    el.className = 'source-badge ' + (kind || 'mock');
  }

  function banner(html, colour) {
    var el = document.getElementById('errorBanner');
    if (!el) return;
    el.style.display = 'block';
    el.style.background = colour === 'info' ? 'rgba(102, 126, 234, 0.15)' : 'rgba(255, 68, 68, 0.15)';
    el.style.borderColor = colour === 'info' ? '#667eea' : '#ff4444';
    el.innerHTML = html;
  }

  function clearBanner() {
    var el = document.getElementById('errorBanner');
    if (el) el.style.display = 'none';
  }

  function hostedNotice() {
    badge('SNAPSHOT', 'mock');
    banner('<strong>Hosted copy, so no live data.</strong> This page is served from GitHub Pages, '
      + 'which cannot reach a Contrast organization. Clone the repo and run <code>npm start</code> '
      + 'to see it live, or open the <a href="' + snapshotHref()
      + '" style="color:#8fa2ff; font-weight:bold;">static snapshot</a>.', 'info');
  }

  // Say what actually broke. An expired session is not the same problem as a
  // server that is not running, and telling someone to start a server that is
  // plainly already answering wastes their time.
  function failureBanner(err) {
    stopProgress();
    var msg = String((err && err.message) || err || '');
    var link = ' Or open the <a href="' + snapshotHref() + '" style="color:#8fa2ff;">static snapshot</a>.';
    badge('NO DATA', 'mock');

    if (/token expired|reauthorize|sign in/i.test(msg)) {
      banner('<strong>Contrast session expired.</strong> The server is running fine, it just has no '
        + 'valid token. If it signed in with <code>npm run login</code> it renews itself, so this '
        + 'usually means that session was revoked. Otherwise run a Contrast command in Claude Code, '
        + 'then press Refresh.' + link);
    } else if (msg === 'NOT_REPORT_SERVER') {
      banner('<strong>Something else is on port 3000.</strong> This page loaded, but the API returned '
        + 'a web page instead of data, so the process answering is not the report server. Stop it, '
        + 'then run <code>npm start</code> from the repo.' + link);
    } else if (/failed to fetch|networkerror|load failed/i.test(msg)) {
      banner('<strong>Cannot reach the local server.</strong> Start it with <code>npm start</code> and '
        + 'open this page at <code>http://localhost:3000</code>.' + link);
    } else {
      banner('<strong>Could not load live data.</strong> ' + esc(msg) + link);
    }
  }

  // One fetch path for every page, so source labelling and error handling cannot drift.
  function fetchData(endpoint) {
    return global.fetch(endpoint, { cache: 'no-store' }).then(function (res) {
      var ct = res.headers.get('content-type') || '';
      if (ct.indexOf('json') === -1) throw new Error('NOT_REPORT_SERVER');
      return res.json().then(function (d) {
        if (!res.ok) throw new Error(d.error || res.statusText);
        return d;
      });
    });
  }


  // ---- MCP call inspector -------------------------------------------------
  // The whole point of this demo is that an MCP server fetched the data. That
  // is invisible in a chart, so every page shows the calls it actually made.

  var PANEL_CSS = [
    '.mcp-panel{margin:0 0 28px;border:1px solid rgba(102,126,234,.35);border-radius:10px;overflow:hidden;background:rgba(102,126,234,.06);font-size:.9rem}',
    '.mcp-head{display:flex;align-items:center;gap:10px;width:100%;padding:11px 16px;background:none;border:0;color:inherit;font:inherit;cursor:pointer;text-align:left}',
    '.mcp-head:hover{background:rgba(102,126,234,.12)}',
    '.mcp-chev{transition:transform .15s;opacity:.7}',
    '.mcp-panel.open .mcp-chev{transform:rotate(90deg)}',
    '.mcp-title{font-weight:700;color:#8fa2ff}',
    '.mcp-sum{opacity:.72;margin-left:auto;font-variant-numeric:tabular-nums}',
    '.mcp-body{display:none;padding:4px 16px 16px;border-top:1px solid rgba(102,126,234,.25)}',
    '.mcp-panel.open .mcp-body{display:block}',
    '.mcp-call{padding:10px 0;border-bottom:1px solid rgba(255,255,255,.07)}',
    '.mcp-call:last-child{border-bottom:0}',
    '.mcp-tool{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:#fff;font-weight:700}',
    '.mcp-meta{opacity:.7;font-size:.85em;margin-left:8px;font-variant-numeric:tabular-nums}',
    '.mcp-args{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.82em;opacity:.8;margin-top:4px;word-break:break-word}',
    '.mcp-note{opacity:.7;margin-top:12px;line-height:1.55}',
    '.mcp-bar{height:3px;border-radius:2px;background:linear-gradient(90deg,#667eea,#764ba2);margin-top:6px}'
  ].join('');

  function injectPanelCss() {
    if (document.getElementById('mcp-panel-css')) return;
    var st = document.createElement('style');
    st.id = 'mcp-panel-css';
    st.textContent = PANEL_CSS;
    document.head.appendChild(st);
  }

  function renderMcpPanel(calls, source) {
    if (!Array.isArray(calls)) return;
    injectPanelCss();

    var host = document.getElementById('mcpPanel');
    if (!host) {
      host = document.createElement('div');
      host.id = 'mcpPanel';
      var anchor = document.getElementById('errorBanner');
      if (anchor && anchor.parentNode) anchor.parentNode.insertBefore(host, anchor.nextSibling);
      else document.querySelector('.container').prepend(host);
    }

    if (!calls.length) {
      host.innerHTML = '<div class="mcp-panel"><button class="mcp-head" type="button">'
        + '<span class="mcp-title">MCP calls</span>'
        + '<span class="mcp-sum">' + (source === 'mock' ? 'none, this page is showing sample data' : 'none recorded') + '</span></button></div>';
      return;
    }

    var total = calls.reduce(function (n, c) { return n + c.ms; }, 0);
    var slowest = calls.reduce(function (m, c) { return Math.max(m, c.ms); }, 1);
    var tools = {};
    calls.forEach(function (c) { tools[c.tool] = (tools[c.tool] || 0) + 1; });
    var toolList = Object.keys(tools).map(function (t) {
      return tools[t] > 1 ? t + ' x' + tools[t] : t;
    }).join(', ');

    var rows = calls.map(function (c) {
      var args = Object.keys(c.args || {}).length
        ? Object.keys(c.args).map(function (k) { return k + ': ' + JSON.stringify(c.args[k]); }).join(', ')
        : 'no arguments';
      var got = c.rows != null ? c.rows + (c.rows === 1 ? ' row' : ' rows') : Math.round(c.bytes / 102.4) / 10 + ' KB';
      return '<div class="mcp-call">'
        + '<span class="mcp-tool">' + esc(c.tool) + '</span>'
        + '<span class="mcp-meta">' + c.ms + ' ms &middot; ' + esc(got) + '</span>'
        + '<div class="mcp-args">' + esc(args) + '</div>'
        + '<div class="mcp-bar" style="width:' + Math.max(2, Math.round((c.ms / slowest) * 100)) + '%"></div>'
        + '</div>';
    }).join('');

    host.innerHTML = '<div class="mcp-panel"><button class="mcp-head" type="button">'
      + '<span class="mcp-chev">&#9656;</span><span class="mcp-title">MCP calls behind this page</span>'
      + '<span class="mcp-sum">' + calls.length + (calls.length === 1 ? ' call' : ' calls') + ' &middot; ' + total + ' ms</span>'
      + '</button><div class="mcp-body">' + rows
      + '<div class="mcp-note">Everything above came from the Contrast MCP server over HTTPS, using the same '
      + 'tools (<code>' + esc(toolList) + '</code>) an AI assistant calls in chat. No model ran, so refreshing '
      + 'this page costs nothing in AI usage.</div></div></div>';

    host.querySelector('.mcp-head').addEventListener('click', function () {
      host.querySelector('.mcp-panel').classList.toggle('open');
    });
  }

  function ageInDays(iso) {
    return Math.floor((Date.now() - new Date(iso).getTime()) / 86400000);
  }

  function frozenNotice() {
    var when = new Date(FROZEN.capturedAt);
    var days = ageInDays(FROZEN.capturedAt);
    banner('<strong>Frozen snapshot.</strong> This is real data from the Contrast organization, captured '
      + when.toLocaleDateString() + (days > 0 ? ', ' + days + (days === 1 ? ' day' : ' days') + ' ago' : ' today')
      + '. Nothing here updates, and controls that would fetch more data will keep showing this same capture. '
      + 'Run the project locally for the live version.', 'info');
  }

  function markLoaded(d) {
    if (FROZEN) {
      badge('SNAPSHOT', 'mock');
      var el0 = document.getElementById('updated');
      if (el0) el0.textContent = 'Captured ' + new Date(FROZEN.capturedAt).toLocaleDateString();
      frozenNotice();
      renderMcpPanel(d.mcp, 'frozen');
      return;
    }
    stopProgress();
    badge(d.source === 'live' ? 'LIVE' : 'MOCK DATA', d.source === 'live' ? 'live' : 'mock');
    truncationNotice(d);
    var el = document.getElementById('updated');
    if (el) {
      if (d.source === 'live') {
        el.textContent = 'Last refreshed ' + new Date(d.generatedAt).toLocaleTimeString();
      } else if (d.capturedAt) {
        // Sample data should always admit its age rather than pass as current.
        var days = ageInDays(d.capturedAt);
        el.textContent = 'Sample data captured ' + new Date(d.capturedAt).toLocaleDateString()
          + (days > 0 ? ', ' + days + (days === 1 ? ' day' : ' days') + ' ago' : ', today');
      } else {
        el.textContent = 'Sample data, capture date unknown';
      }
    }
    renderMcpPanel(d.mcp, d.source);
  }

  // Some endpoints fan out across every application, so on a large organization
  // they take tens of seconds. With no signal that is indistinguishable from a
  // hung page, so count the seconds out loud.
  var ticking = null;

  function startProgress(label) {
    stopProgress();
    var started = Date.now();
    var el = document.getElementById('updated');
    badge('LOADING', 'mock');
    ticking = setInterval(function () {
      var s = Math.round((Date.now() - started) / 1000);
      if (el) el.textContent = label + ' ' + s + 's';
    }, 1000);
    if (el) el.textContent = label;
  }

  function stopProgress() {
    if (ticking) { clearInterval(ticking); ticking = null; }
  }

  // A result that quietly stopped short is the failure this project exists to
  // expose, so say so where it cannot be missed.
  function truncationNotice(d) {
    if (!d || !d.truncated) return;
    banner('<strong>Showing the first ' + esc(String(d.limit)) + ' results.</strong> Your organization '
      + 'has more than this page fetched, so the totals below are a floor, not a count. Raise the ceiling '
      + 'with <code>CONTRAST_MAX_ITEMS</code> if you need all of it.', 'info');
  }

  // The loop every page runs: skip the call when hosted, fetch, render, and turn
  // any failure into an explanation rather than a page stuck on "Loading".
  function createLoader(endpoint, render) {
    return function load(query) {
      clearBanner();
      if (HOSTED) { hostedNotice(); return Promise.resolve(); }
      var url = typeof endpoint === 'function' ? endpoint(query) : endpoint;
      return fetchData(url).then(function (d) {
        markLoaded(d);
        render(d);
      }).catch(failureBanner);
    };
  }

  function onRefresh(handler) {
    var btn = document.getElementById('refreshBtn');
    if (btn) btn.addEventListener('click', function () { handler(); });
  }

  global.Reports = {
    esc: esc,
    shortApp: shortApp,
    HOSTED: HOSTED,
    FROZEN: FROZEN,
    badge: badge,
    banner: banner,
    clearBanner: clearBanner,
    hostedNotice: hostedNotice,
    failureBanner: failureBanner,
    fetchData: fetchData,
    markLoaded: markLoaded,
    startProgress: startProgress,
    stopProgress: stopProgress,
    renderMcpPanel: renderMcpPanel,
    createLoader: createLoader,
    onRefresh: onRefresh,
  };
}(window));
