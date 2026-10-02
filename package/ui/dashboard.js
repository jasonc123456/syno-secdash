/* SecDash UI. Plain JS, no build step. Talks to api.cgi (same directory). */
(function () {
  "use strict";
  // Only run on SecDash's own page (DSM may load third-party UI files elsewhere).
  if (!document.documentElement.classList.contains("sd") || !document.getElementById("view-overview")) return;

  var state = {
    tab: "overview",
    range: "7d",
    cc: null,
    ccName: null,
    mapMetric: "attacks",
    bl: { q: "", active: false, sort: "first_seen", dir: "desc", offset: 0, limit: 100 },
  };
  try {
    var saved = JSON.parse(localStorage.getItem("secdash") || "{}");
    if (saved.range) state.range = saved.range;
    if (saved.tab) state.tab = saved.tab;
  } catch (e) { /* storage unavailable */ }

  try { if (window.self !== window.top) document.documentElement.classList.add("embedded"); } catch (e) { document.documentElement.classList.add("embedded"); }
  var TABS = ["overview", "map", "blocks", "logins", "web", "setup"];
  if (TABS.indexOf(location.hash.slice(1)) >= 0) state.tab = location.hash.slice(1);

  function persist() {
    if (location.hash.slice(1) !== state.tab) history.replaceState(null, "", "#" + state.tab);
    try { localStorage.setItem("secdash", JSON.stringify({ range: state.range, tab: state.tab })); } catch (e) { /* ignore */ }
  }

  // ---------- helpers ----------
  var $ = function (id) { return document.getElementById(id); };
  function css(name) { return getComputedStyle(document.documentElement).getPropertyValue(name).trim(); }
  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }
  function fmt(n) { return (n || 0).toLocaleString(); }
  function compact(n) {
    n = n || 0;
    if (n < 10000) return n.toLocaleString();
    var u = [[1e9, "B"], [1e6, "M"], [1e3, "K"]];
    for (var i = 0; i < u.length; i++) if (n >= u[i][0]) return (n / u[i][0]).toFixed(n / u[i][0] < 100 ? 1 : 0).replace(/\.0$/, "") + u[i][1];
    return String(n);
  }
  function dt(ts) {
    if (!ts) return "—";
    var d = new Date(ts * 1000);
    return d.toLocaleDateString(undefined, { month: "short", day: "numeric" }) + " " +
      d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
  }
  function ago(ts) {
    if (!ts) return "never";
    var s = Math.max(0, Date.now() / 1000 - ts);
    if (s < 90) return "just now";
    if (s < 5400) return Math.round(s / 60) + " min ago";
    if (s < 129600) return Math.round(s / 3600) + " h ago";
    return Math.round(s / 86400) + " days ago";
  }
  // Windows has no flag emoji (it draws the letters), so detect colour flags once.
  // Country flags come from the bundled "SecDash Flags" font (Twemoji), so they
  // show on every OS, including Windows, which has no flag emoji of its own.
  function flag(cc) {
    if (!cc || !/^[a-z]{2}$/i.test(cc)) return "";
    cc = cc.toUpperCase();
    return '<span class="flag" role="img" aria-label="' + cc + '" title="' + cc + '">' +
      String.fromCodePoint(0x1f1a5 + cc.charCodeAt(0), 0x1f1a5 + cc.charCodeAt(1)) + "</span>";
  }
  function place(r) {
    if (!r || !r.cc) return '<span class="muted">unknown</span>';
    if (r.cc === "LAN") return '<span class="muted">Private network</span>';
    return flag(r.cc) + " " + esc(r.country || r.cc) + (r.city ? '<span class="muted"> · ' + esc(r.city) + "</span>" : "");
  }
  var ICONS = {
    good: '<svg viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><circle cx="8" cy="8" r="8"/><path d="M4.5 8.2l2.2 2.2 4.8-4.8" stroke="#fff" stroke-width="1.8" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    warning: '<svg viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M8 1l7.5 13.5H.5z"/><path d="M8 6v4M8 12v.5" stroke="#000" stroke-width="1.6" stroke-linecap="round"/></svg>',
    serious: '<svg viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M8 0l8 8-8 8-8-8z"/><path d="M8 4.5v4.5M8 11.3v.4" stroke="#fff" stroke-width="1.7" stroke-linecap="round"/></svg>',
    critical: '<svg viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><circle cx="8" cy="8" r="8"/><path d="M5.2 5.2l5.6 5.6M10.8 5.2l-5.6 5.6" stroke="#fff" stroke-width="1.8" stroke-linecap="round"/></svg>',
  };
  function statusBadge(level, label) {
    return '<span class="status ' + level + '">' + ICONS[level] + esc(label) + "</span>";
  }

  // DSM's CSRF protection wants the session's SynoToken with every request.
  // Inside the DSM window it lives on the desktop page that hosts our iframe.
  var tokenPromise = null;
  function synoToken() {
    if (tokenPromise) return tokenPromise;
    var t = "";
    try { t = window.parent.SYNO.SDS.Session.SynoToken || ""; } catch (e) { /* not embedded */ }
    if (t) { tokenPromise = Promise.resolve(t); return tokenPromise; }
    tokenPromise = fetch("/webman/login.cgi?enable_syno_token=yes", { credentials: "same-origin" })
      .then(function (r) { return r.json(); })
      .then(function (j) { return (j && j.SynoToken) || ""; })
      .catch(function () { return ""; });
    return tokenPromise;
  }

  function api(q, extra, method) {
    var p = new URLSearchParams(Object.assign({ q: q, range: state.range, tz: new Date().getTimezoneOffset() }, extra || {}));
    if (state.cc && !(extra && "cc" in extra)) p.set("cc", state.cc);
    return synoToken().then(function (token) {
      if (token) p.set("SynoToken", token);
      return fetch("api.cgi?" + p.toString(), { method: method || "GET", credentials: "same-origin", headers: token ? { "X-SYNO-TOKEN": token } : {} });
    }).then(function (r) {
      return r.json().catch(function () { return { error: "HTTP " + r.status }; }).then(function (body) {
        if (!r.ok) {
          var err = new Error(body.error || "HTTP " + r.status);
          err.diag = body.diag;
          throw err;
        }
        return body;
      });
    });
  }

  function banner(level, html) {
    var b = $("banner");
    if (!html) { b.hidden = true; return; }
    b.innerHTML = statusBadge(level, "") + "<div>" + html + "</div>";
    b.hidden = false;
  }

  // Generic table renderer. cols: [{key,label,num,render,sort}]
  function table(el, cols, rows, opts) {
    opts = opts || {};
    if (!rows || !rows.length) { el.innerHTML = '<div class="empty">' + esc(opts.empty || "Nothing in this range.") + "</div>"; return; }
    var h = '<div class="tbl-wrap"><table><thead><tr>';
    cols.forEach(function (c) {
      var cls = (c.num ? "num " : "") + (c.sort ? "sortable" : "");
      var arrow = opts.sort && c.sort === opts.sort.key ? (opts.sort.dir === "asc" ? " ↑" : " ↓") : "";
      h += '<th class="' + cls + '"' + (c.sort ? ' data-sort="' + c.sort + '"' : "") + ">" + esc(c.label) + arrow +
        '<span class="col-grip" title="Drag to resize, double-click to reset" aria-hidden="true"></span></th>';
    });
    h += "</tr></thead><tbody>";
    rows.forEach(function (r, i) {
      h += "<tr" + (opts.ipKey && r[opts.ipKey] ? ' class="click" data-ip="' + esc(r[opts.ipKey]) + '"' : "") + ">";
      cols.forEach(function (c) {
        var v = c.render ? c.render(r, i) : (c.num ? fmt(r[c.key]) : esc(r[c.key]));
        h += '<td class="' + (c.num ? "num" : "") + (c.wrap ? " wrap" : "") + '">' + v + "</td>";
      });
      h += "</tr>";
    });
    el.innerHTML = h + "</tbody></table></div>";
    if (opts.onSort) el.querySelectorAll("th[data-sort]").forEach(function (th) {
      th.addEventListener("click", function () { opts.onSort(th.getAttribute("data-sort")); });
    });
    resizable(el, cols.map(function (c) { return c.label; }));
  }

  // Column widths: drag a header edge to resize, double-click it to reset.
  // Kept per table (element id) and column label, so they survive refreshes.
  var COLW_KEY = "secdash-colwidths", colWidths = {};
  try { colWidths = JSON.parse(localStorage.getItem(COLW_KEY) || "{}") || {}; } catch (e) { /* storage unavailable */ }
  function saveColWidths() {
    try { localStorage.setItem(COLW_KEY, JSON.stringify(colWidths)); } catch (e) { /* ignore */ }
  }
  function fixWidths(tbl, widths) {
    var ths = tbl.tHead.rows[0].cells, total = 0;
    for (var i = 0; i < ths.length; i++) { ths[i].style.width = widths[i] + "px"; total += widths[i]; }
    tbl.style.width = total + "px";
    tbl.classList.add("fixed");
  }
  function resizable(el, labels) {
    var tbl = el.querySelector("table"), id = el.id;
    var saved = id && colWidths[id];
    if (saved && labels.every(function (l) { return saved[l] > 0; })) {
      fixWidths(tbl, labels.map(function (l) { return saved[l]; }));
    }
    // show the full text of a cell cut short by a narrow column
    tbl.addEventListener("mouseover", function (e) {
      var td = e.target.closest && e.target.closest("td");
      if (td && tbl.classList.contains("fixed") && !td.title && td.scrollWidth > td.clientWidth) td.title = td.textContent.trim();
    });
    tbl.querySelectorAll("th .col-grip").forEach(function (grip, i) {
      grip.addEventListener("click", function (e) { e.stopPropagation(); });  // don't sort
      grip.addEventListener("dblclick", function (e) {
        e.stopPropagation();
        if (id) { delete colWidths[id]; saveColWidths(); }
        tbl.classList.remove("fixed");
        tbl.style.width = "";
        Array.prototype.forEach.call(tbl.tHead.rows[0].cells, function (th) { th.style.width = ""; });
      });
      grip.addEventListener("pointerdown", function (e) {
        e.preventDefault();
        e.stopPropagation();
        var widths = Array.prototype.map.call(tbl.tHead.rows[0].cells, function (th) { return Math.round(th.getBoundingClientRect().width); });
        fixWidths(tbl, widths);
        var x0 = e.clientX, w0 = widths[i];
        grip.setPointerCapture(e.pointerId);
        grip.classList.add("active");
        function move(ev) { widths[i] = Math.max(48, Math.round(w0 + ev.clientX - x0)); fixWidths(tbl, widths); }
        function up() {
          grip.removeEventListener("pointermove", move);
          grip.removeEventListener("pointerup", up);
          grip.removeEventListener("pointercancel", up);
          grip.classList.remove("active");
          if (id) {
            colWidths[id] = {};
            labels.forEach(function (l, k) { colWidths[id][l] = widths[k]; });
            saveColWidths();
          }
        }
        grip.addEventListener("pointermove", move);
        grip.addEventListener("pointerup", up);
        grip.addEventListener("pointercancel", up);
      });
    });
  }
  function barCell(value, max, color) {
    var w = max && value ? Math.max(2, Math.round(100 * value / max)) : 0;
    return '<div class="bar-cell"><span class="n">' + fmt(value) + '</span><span class="bar" style="width:' + w + "%;" + (color ? "background:" + color : "") + '"></span></div>';
  }
  function legend(el, items) {
    el.innerHTML = items.map(function (it) { return '<span><i style="background:' + it[1] + '"></i>' + esc(it[0]) + "</span>"; }).join("");
  }

  // ---------- charts ----------
  var charts = {};
  function chartBase() {
    Chart.defaults.font.family = 'system-ui, -apple-system, "Segoe UI", sans-serif';
    Chart.defaults.font.size = 12;
    Chart.defaults.color = css("--muted");
    Chart.defaults.borderColor = css("--grid");
  }
  function timeLabels(t, bucket) {
    return t.map(function (ts) {
      var d = new Date(ts * 1000);
      if (bucket < 86400) return d.toLocaleDateString(undefined, { month: "short", day: "numeric" }) + " " + d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
      return d.toLocaleDateString(undefined, { month: "short", day: "numeric", year: bucket >= 7 * 86400 ? "2-digit" : undefined });
    });
  }
  function commonOpts(stacked) {
    return {
      responsive: true, maintainAspectRatio: false, animation: false,
      interaction: { mode: "index", intersect: false },
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: css("--ink"), titleColor: css("--surface"), bodyColor: css("--surface"),
          padding: 8, cornerRadius: 6, boxPadding: 4, usePointStyle: true,
          callbacks: { label: function (c) { return " " + c.dataset.label + ": " + fmt(c.parsed.y); } },
        },
      },
      scales: {
        x: { stacked: !!stacked, grid: { display: false }, border: { color: css("--axis") }, ticks: { maxRotation: 0, autoSkipPadding: 16 } },
        y: { stacked: !!stacked, beginAtZero: true, border: { display: false }, grid: { color: css("--grid") }, ticks: { precision: 0, callback: function (v) { return compact(v); } } },
      },
    };
  }
  function draw(id, config) {
    if (charts[id]) charts[id].destroy();
    charts[id] = new Chart($(id), config);
  }
  function lineDs(label, data, color) {
    return {
      label: label, data: data, borderColor: color, backgroundColor: color, borderWidth: 2,
      pointRadius: 0, pointHoverRadius: 5, pointHoverBorderWidth: 2, pointHoverBorderColor: css("--surface"),
      cubicInterpolationMode: "monotone", borderCapStyle: "round", borderJoinStyle: "round", fill: false,
    };
  }
  function seriesTable(el, t, bucket, series) {
    var labels = timeLabels(t, bucket);
    var rows = t.map(function (_, i) {
      var r = { when: labels[i] };
      series.forEach(function (s) { r[s[0]] = s[1][i]; });
      return r;
    }).filter(function (r) { return series.some(function (s) { return r[s[0]]; }); }).reverse();
    table(el, [{ key: "when", label: "Period" }].concat(series.map(function (s) { return { key: s[0], label: s[0], num: true }; })), rows);
  }

  // ---------- views ----------
  function tile(label, value, cur, prev, upIsBad, hero) {
    var delta = "";
    if (prev != null) {
      var d = cur - prev;
      if (d === 0) delta = "no change vs previous period";
      else {
        var bad = upIsBad ? d > 0 : d < 0;
        delta = '<span class="' + (bad ? "bad" : "good") + '">' + (d > 0 ? "▲ " : "▼ ") + fmt(Math.abs(d)) + "</span> vs previous period";
      }
    }
    return '<div class="tile' + (hero ? " hero" : "") + '"><div class="label">' + esc(label) + '</div><div class="value">' + compact(value) + '</div><div class="delta">' + delta + "</div></div>";
  }

  function loadOverview() {
    return Promise.all([api("summary"), api("timeline"), api("geo"), api("blocks", { limit: 8 })]).then(function (res) {
      var s = res[0], tl = res[1], g = res[2], bl = res[3];
      var c = s.current, p = s.previous || {};
      $("tiles").innerHTML =
        tile("Failed logins", c.fails, c.fails, s.previous ? p.fails : null, true, true) +
        tile("Currently blocked IPs", s.active_blocks, 0, null) +
        tile("New blocks", c.new_blocks, c.new_blocks, s.previous ? p.new_blocks : null, true) +
        tile("Attacking IPs", c.attackers, c.attackers, s.previous ? p.attackers : null, true) +
        tile("Countries", s.countries, 0, null) +
        tile("Successful logins", c.successes, 0, null);

      var S = [["Failed logins", tl.series.fail, css("--s1"), "fail"], ["New blocks", tl.series.blocked, css("--s2"), "blocked"], ["Successful logins", tl.series.success, css("--s3"), "success"]];
      var labels = timeLabels(tl.t, tl.bucket);
      S.forEach(function (x, i) {
        var total = x[1].reduce(function (a, b) { return a + b; }, 0);
        $("tl-" + x[3] + "-total").textContent = fmt(total) + " in range";
        var ds = lineDs(x[0], x[1], x[2]);
        ds.fill = "origin";
        ds.backgroundColor = x[2] + "1a";
        var o = commonOpts(false);
        o.scales.y.ticks.maxTicksLimit = 3;
        o.scales.x.ticks.display = i === S.length - 1;
        draw("tl-" + x[3], { type: "line", data: { labels: labels, datasets: [ds] }, options: o });
      });
      seriesTable($("tl-table"), tl.t, tl.bucket, S);

      var countries = g.countries.filter(function (r) { return r.cc !== "LAN"; }).map(function (r) {
        r.attacks = (r.blocks || 0) + (r.fails || 0); return r;
      }).sort(function (a, b) { return b.attacks - a.attacks; }).slice(0, 10);
      var max = countries.length ? countries[0].attacks : 0;
      table($("ov-countries"), [
        { label: "Country", render: function (r) { return place(r); } },
        { label: "Blocks + failed logins", render: function (r) { return barCell(r.attacks, max); } },
      ], countries, { empty: "No attacks recorded in this range." });
      $("ov-countries").querySelectorAll("tbody tr").forEach(function (tr, i) {
        tr.classList.add("click");
        tr.addEventListener("click", function () { setCountry(countries[i].cc, countries[i].country); });
      });

      table($("ov-blocks"), [
        { label: "IP", render: function (r) { return '<span class="ip">' + esc(r.ip) + "</span>"; } },
        { label: "Location", render: place },
        { label: "Blocked", render: function (r) { return esc(dt(r.first_seen)); } },
      ], bl.rows, { ipKey: "ip", empty: "No new blocks in this range." });
    });
  }

  var map = null;
  function seqColors() { return [1, 2, 3, 4, 5].map(function (i) { return css("--seq-" + i); }); }
  function bins(values) {
    var max = Math.max.apply(null, values.concat([0]));
    if (!max) return [];
    // log-spaced upper bounds so a few heavy hitters don't wash out everyone else
    var out = [];
    for (var i = 1; i <= 5; i++) out.push(Math.max(1, Math.round(Math.pow(max, i / 5))));
    return out.filter(function (v, i, a) { return a.indexOf(v) === i; });
  }
  function loadMap() {
    return api("geo", { cc: "" }).then(function (g) {
      var metric = state.mapMetric;
      var rows = g.countries.filter(function (r) { return r.cc && r.cc !== "LAN"; }).map(function (r) {
        r.attacks = (r.blocks || 0) + (r.fails || 0); return r;
      });
      var byCc = {};
      rows.forEach(function (r) { byCc[r.cc] = r; });
      var upper = bins(rows.map(function (r) { return r[metric] || 0; }));
      var colors = seqColors().slice(5 - upper.length);
      var scale = {}, values = {};
      upper.forEach(function (_, i) { scale["b" + i] = colors[i]; });
      rows.forEach(function (r) {
        var v = r[metric] || 0;
        if (!v) return;
        for (var i = 0; i < upper.length; i++) if (v <= upper[i]) { values[r.cc] = "b" + i; return; }
        values[r.cc] = "b" + (upper.length - 1);
      });

      if (map) { try { map.destroy(); } catch (e) { /* ignore */ } $("map").innerHTML = ""; }
      var markers = (g.cities || []).filter(function (c) { return c.lat != null; }).slice(0, 150);
      map = new jsVectorMap({
        selector: "#map", map: "world", zoomButtons: true, zoomOnScroll: false,
        backgroundColor: "transparent",
        regionStyle: {
          initial: { fill: css("--seq-0"), stroke: css("--surface"), strokeWidth: 0.6, fillOpacity: 1 },
          hover: { fillOpacity: 0.8, cursor: "pointer" },
          selected: { fill: css("--s2") },
        },
        selectedRegions: state.cc ? [state.cc] : [],
        series: { regions: [{ attribute: "fill", scale: scale, values: values }] },
        markers: markers.map(function (c) { return { name: (c.city || "") + " (" + c.ips + " IPs)", coords: [c.lat, c.lon] }; }),
        markerStyle: { initial: { r: 4, fill: css("--s2"), stroke: css("--surface"), strokeWidth: 2, fillOpacity: 1 }, hover: { r: 6, cursor: "default" } },
        onRegionTooltipShow: function (ev, tip, code) {
          var r = byCc[code];
          tip.text(r ? "<b>" + esc(r.country || code) + "</b><br>Blocks: " + fmt(r.blocks) + "<br>Failed logins: " + fmt(r.fails) + "<br>Web errors: " + fmt(r.http_errors)
                     : esc(tip.text()) + "<br>No events", true);
        },
        onRegionClick: function (ev, code) { var r = byCc[code]; setCountry(code, r ? r.country : code); },
      });

      var ml = $("map-legend");
      if (!upper.length) ml.innerHTML = '<span class="muted">No located events in this range.</span>';
      else {
        var lo = 1;
        ml.innerHTML = '<span>Fewer</span>' + upper.map(function (u, i) {
          var label = lo === u ? fmt(u) : fmt(lo) + "–" + fmt(u); lo = u + 1;
          return '<i style="background:' + colors[i] + '" title="' + label + '"></i>';
        }).join("") + "<span>More</span>" + '<span class="muted" style="margin-left:10px">1 – ' + fmt(upper[upper.length - 1]) + " per country</span>";
      }

      var sorted = rows.slice().sort(function (a, b) { return (b[metric] || 0) - (a[metric] || 0); });
      var mx = { blocks: 0, fails: 0, http_errors: 0 };
      sorted.forEach(function (r) { ["blocks", "fails", "http_errors"].forEach(function (k) { mx[k] = Math.max(mx[k], r[k] || 0); }); });
      table($("map-table"), [
        { label: "Country", render: place },
        { label: "Blocks", render: function (r) { return barCell(r.blocks, mx.blocks, css("--s2")); } },
        { label: "Failed logins", render: function (r) { return barCell(r.fails, mx.fails, css("--s1")); } },
        { label: "Successful logins", key: "successes", num: true },
        { label: "Web errors", key: "http_errors", num: true },
      ], sorted);
      $("map-table").querySelectorAll("tbody tr").forEach(function (tr, i) {
        tr.classList.add("click");
        tr.addEventListener("click", function () { setCountry(sorted[i].cc, sorted[i].country); });
      });
    });
  }

  var lastBlocks = [];
  function loadBlocks() {
    var b = state.bl;
    return api("blocks", { search: b.q, active: b.active ? "1" : "0", sort: b.sort, dir: b.dir, limit: b.limit, offset: b.offset }).then(function (res) {
      lastBlocks = res.rows;
      var now = Date.now() / 1000;
      table($("bl-table"), [
        { label: "IP", sort: "ip", render: function (r) { return '<span class="ip">' + esc(r.ip) + "</span>"; } },
        { label: "Location", sort: "country", render: place },
        { label: "Network", sort: "org", render: function (r) { return r.org ? esc(r.org) + (r.asn ? ' <span class="muted">AS' + r.asn + "</span>" : "") : '<span class="muted">—</span>'; } },
        { label: "First blocked", sort: "first_seen", render: function (r) { return esc(dt(r.first_seen)); } },
        { label: "Expires", sort: "expire", render: function (r) { return r.expire ? esc(dt(r.expire)) : "never"; } },
        { label: "State", render: function (r) {
          return r.active && (!r.expire || r.expire > now) ? statusBadge("critical", "Blocked") : '<span class="muted">Released</span>';
        } },
        { label: "Blocked via", sort: "via", render: function (r) { return r.via ? esc(r.via) : '<span class="muted">—</span>'; } },
        { label: "Failed logins", sort: "attempts", num: true, key: "attempts" },
      ], res.rows, {
        ipKey: "ip", empty: "No blocked IPs match.",
        sort: { key: b.sort, dir: b.dir },
        onSort: function (k) { if (b.sort === k) b.dir = b.dir === "asc" ? "desc" : "asc"; else { b.sort = k; b.dir = k === "ip" || k === "country" || k === "org" ? "asc" : "desc"; } b.offset = 0; loadBlocks(); },
      });
      $("bl-count").textContent = fmt(res.total) + " IPs";
      var page = Math.floor(b.offset / b.limit) + 1, pages = Math.max(1, Math.ceil(res.total / b.limit));
      $("bl-page").textContent = "Page " + page + " of " + pages;
      $("bl-prev").disabled = page <= 1;
      $("bl-next").disabled = page >= pages;
      bindIpRows($("bl-table"));
    });
  }
  function exportCsv() {
    var b = state.bl;
    api("blocks", { search: b.q, active: b.active ? "1" : "0", sort: b.sort, dir: b.dir, limit: 5000, offset: 0 }).then(function (res) {
      var cols = ["ip", "cc", "country", "city", "asn", "org", "first_seen", "expire", "active", "via", "attempts"];
      var lines = [cols.join(",")].concat(res.rows.map(function (r) {
        return cols.map(function (c) {
          var v = r[c];
          if ((c === "first_seen" || c === "expire") && v) v = new Date(v * 1000).toISOString();
          v = v == null ? "" : String(v);
          return /[",\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v;
        }).join(",");
      }));
      var a = document.createElement("a");
      a.href = URL.createObjectURL(new Blob([lines.join("\n")], { type: "text/csv" }));
      a.download = "secdash-blocked-ips-" + new Date().toISOString().slice(0, 10) + ".csv";
      a.click();
      setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
    }).catch(showError);
  }

  var DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
  function loadLogins() {
    return api("logins").then(function (res) {
      // unusual successes
      var un = res.unusual;
      $("unusual-card").hidden = false;
      table($("lg-unusual"), [
        { label: "", render: function (r) { return statusBadge("serious", r.new_country ? "New country" : "New network"); } },
        { label: "When", render: function (r) { return esc(dt(r.ts)); } },
        { label: "User", key: "user" },
        { label: "Service", key: "service" },
        { label: "IP", render: function (r) { return '<span class="ip">' + esc(r.ip) + "</span>"; } },
        { label: "Location", render: place },
        { label: "Network", key: "org" },
      ], un, { ipKey: "ip", empty: "No successful sign-ins from new countries or IPs in this range." });

      // by service (grouped bars: failed vs successful)
      var svc = res.by_service;
      var S = [["Failed", svc.map(function (r) { return r.fails; }), css("--s1")], ["Successful", svc.map(function (r) { return r.successes; }), css("--s3")]];
      legend($("svc-legend"), S.map(function (x) { return [x[0], x[2]]; }));
      var o = commonOpts(false);
      o.indexAxis = "y";
      o.interaction = { mode: "index", axis: "y", intersect: false };
      o.plugins.tooltip.callbacks.label = function (c) { return " " + c.dataset.label + ": " + fmt(c.parsed.x); };
      o.scales = {
        y: { grid: { display: false }, border: { color: css("--axis") } },
        x: { beginAtZero: true, border: { display: false }, grid: { color: css("--grid") }, ticks: { precision: 0, callback: function (v) { return compact(v); } } },
      };
      draw("svc-chart", {
        type: "bar",
        data: { labels: svc.map(function (r) { return r.service; }), datasets: S.map(function (x) {
          return { label: x[0], data: x[1], backgroundColor: x[2], maxBarThickness: 16, borderRadius: { topRight: 4, bottomRight: 4 }, borderSkipped: "start", categoryPercentage: 0.7, barPercentage: 0.9 };
        }) },
        options: o,
      });
      table($("svc-table"), [{ key: "service", label: "Service" }, { key: "fails", label: "Failed", num: true }, { key: "successes", label: "Successful", num: true }, { key: "blocked", label: "Blocked", num: true }], svc);

      var umax = res.by_user.length ? res.by_user[0].fails : 0;
      table($("lg-users"), [
        { label: "Username", render: function (r) { return '<span class="ip">' + esc(r.user) + "</span>"; } },
        { label: "Failed attempts", render: function (r) { return barCell(r.fails, umax); } },
        { label: "From IPs", key: "ips", num: true },
      ], res.by_user, { empty: "No failed logins in this range." });

      // heatmap
      var hm = res.heatmap, max = 0;
      hm.forEach(function (row) { row.forEach(function (v) { max = Math.max(max, v); }); });
      var colors = seqColors();
      var h = "<div></div>";
      for (var hr = 0; hr < 24; hr++) h += '<div class="hl">' + (hr % 3 === 0 ? hr : "") + "</div>";
      for (var d = 0; d < 7; d++) {
        h += "<div>" + DAYS[d] + "</div>";
        for (var k = 0; k < 24; k++) {
          var v = hm[d][k];
          var bg = v ? colors[Math.min(4, Math.floor(4.999 * Math.sqrt(v / max)))] : "";
          h += '<div class="cell" data-tip="' + DAYS[d] + " " + String(k).padStart(2, "0") + ":00 – " + fmt(v) + ' failed" style="' + (bg ? "background:" + bg : "") + '"></div>';
        }
      }
      $("lg-heat").innerHTML = h;
      var hl = document.createElement("div");
      hl.className = "heat-legend";
      hl.innerHTML = "<span>0</span><i style=\"background:" + css("--seq-0") + "\"></i>" + colors.map(function (c) { return '<i style="background:' + c + '"></i>'; }).join("") + "<span>" + fmt(max) + " per hour</span>";
      $("lg-heat").appendChild(hl);
      hl.style.gridColumn = "1 / -1";

      table($("lg-recent"), [
        { label: "When", render: function (r) { return esc(dt(r.ts)); } },
        { label: "Result", render: function (r) {
          return r.result === "success" ? statusBadge("good", "Success") : r.result === "blocked" ? statusBadge("critical", "Blocked") : statusBadge("warning", "Failed");
        } },
        { label: "User", key: "user" },
        { label: "Service", key: "service" },
        { label: "IP", render: function (r) { return '<span class="ip">' + esc(r.ip) + "</span>"; } },
        { label: "Location", render: place },
        { label: "Source", key: "source" },
      ], res.recent, { ipKey: "ip", empty: "No login events in this range." });
      bindIpRows($("view-logins"));
    });
  }

  function loadWeb() {
    return api("web").then(function (res) {
      var total = Object.keys(res.totals).reduce(function (a, k) { return a + res.totals[k]; }, 0);
      $("web-empty").hidden = total > 0;
      $("web-body").hidden = total === 0;
      if (!total) return;
      // stack order validated for CVD/normal-vision separation: blue, aqua, orange, violet
      var S = [["2xx", res.status["2"], css("--s1")], ["3xx", res.status["3"], css("--s3")], ["4xx", res.status["4"], css("--s2")], ["5xx", res.status["5"], css("--s7")]];
      legend($("web-legend"), S.map(function (x) { return [x[0], x[2]]; }));
      var surface = css("--surface");
      draw("web-chart", {
        type: "bar",
        data: { labels: timeLabels(res.t, BUCKET[state.range]), datasets: S.map(function (x, i) {
          return { label: x[0], data: x[1], backgroundColor: x[2], borderColor: surface, borderWidth: { top: 2 }, borderSkipped: "bottom",
                   borderRadius: i === S.length - 1 ? { topLeft: 4, topRight: 4 } : 0, maxBarThickness: 24 };
        }) },
        options: commonOpts(true),
      });
      seriesTable($("web-table"), res.t, BUCKET[state.range], S);
      var m1 = res.top_ips.length ? res.top_ips[0].errors : 0;
      table($("web-ips"), [
        { label: "IP", render: function (r) { return '<span class="ip">' + esc(r.ip) + "</span>"; } },
        { label: "Location", render: place },
        { label: "Errors", render: function (r) { return barCell(r.errors, m1); } },
        { label: "Paths", key: "paths", num: true },
      ], res.top_ips, { ipKey: "ip" });
      var m2 = res.top_paths.length ? res.top_paths[0].hits : 0;
      table($("web-paths"), [
        { label: "Path", wrap: true, render: function (r) { return '<span class="ip">' + esc(r.path) + "</span>"; } },
        { label: "Hits", render: function (r) { return barCell(r.hits, m2); } },
        { label: "IPs", key: "ips", num: true },
      ], res.top_paths);
      table($("web-ua"), [
        { label: "User agent", wrap: true, key: "ua" },
        { label: "Hits", key: "hits", num: true },
        { label: "IPs", key: "ips", num: true },
      ], res.top_ua);
      bindIpRows($("view-web"));
    });
  }
  var BUCKET = { "24h": 3600, "7d": 21600, "30d": 86400, "90d": 86400, "1y": 604800, "all": 604800 };

  function loadSetup() {
    return api("status").then(function (s) {
      var last = s.collector_last_run, age = last ? Date.now() / 1000 - last : Infinity;
      var level = age < 900 ? "good" : age < 3600 ? "warning" : "critical";
      var label = last ? "Last batch " + ago(last) : "Collector has not run yet";
      $("st-status").innerHTML = '<dl class="kv">' +
        "<dt>Collector</dt><dd>" + statusBadge(level, label) + "</dd>" +
        "<dt>Collector report</dt><dd><pre>" + esc(s.collector_info || "—") + "</pre></dd>" +
        "<dt>GeoIP database</dt><dd>" + esc(s.geo_db_date || "—") + (s.geo_update_month ? " (City + ASN Lite, updated " + esc(s.geo_update_month) + ")" : ' <span class="muted">(bundled Country Lite; City/ASN download pending)</span>') + "</dd>" +
        "<dt>Stored</dt><dd>" + fmt(s.counts.blocks) + " blocked IPs · " + fmt(s.counts.auth_events) + " login events · " + fmt(s.counts.http_events) + " web requests · " + fmt(s.counts.geo) + " located IPs</dd>" +
        "<dt>Database size</dt><dd>" + (s.db_bytes != null ? (s.db_bytes / 1048576).toFixed(1) + " MB" : "—") + "</dd>" +
        "<dt>Retention</dt><dd>" + esc(retentionLabel(s.retention_days)) + "</dd>" +
        "</dl>";
      var sel = $("ret-days");
      if (!sel.dataset.dirty) {
        var choices = s.retention_choices || [s.retention_days];
        if (choices.indexOf(s.retention_days) < 0) choices = choices.concat([s.retention_days]);
        sel.innerHTML = choices.map(function (d) {
          return '<option value="' + d + '"' + (d === s.retention_days ? " selected" : "") + ">" + esc(retentionLabel(d)) + "</option>";
        }).join("");
        sel.dataset.saved = s.retention_days;
      }
      $("st-script").textContent = s.collector_script || "(collector script not found)";
      $("version").textContent = "SecDash " + s.version;
      return s;
    });
  }

  function retentionLabel(d) {
    if (!d) return "Forever";
    if (d % 365 === 0) return d / 365 + (d === 365 ? " year" : " years");
    if (d === 180) return "6 months";
    return fmt(d) + " days";
  }
  var TABLE_NAMES = { auth_events: "login events", http_events: "web requests", blocks: "released blocks" };
  function describeCounts(c) {
    return Object.keys(TABLE_NAMES).map(function (k) { return fmt(c[k] || 0) + " " + TABLE_NAMES[k]; }).join(", ");
  }
  function bindRetention() {
    var sel = $("ret-days"), save = $("ret-save"), msg = $("ret-msg");
    sel.addEventListener("change", function () {
      sel.dataset.dirty = sel.value !== sel.dataset.saved ? "1" : "";
      save.disabled = !sel.dataset.dirty;
      msg.textContent = "";
    });
    save.addEventListener("click", function () {
      save.disabled = true;
      api("settings", { retention_days: sel.value }, "POST").then(function (r) {
        sel.dataset.dirty = "";
        msg.textContent = r.retention_days ? "Saved. Older data is removed within a minute." : "Saved. Data is kept forever.";
        return loadSetup();
      }).catch(function (e) { save.disabled = false; msg.textContent = "Couldn't save: " + e.message; });
    });

    var box = $("prune-confirm"), input = $("prune-days");
    function close() { box.hidden = true; box.innerHTML = ""; }
    input.addEventListener("input", close);
    $("prune-check").addEventListener("click", function () {
      var days = parseInt(input.value, 10);
      if (!(days >= 1 && days <= 3650)) { box.hidden = false; box.textContent = "Enter a number of days from 1 to 3650."; return; }
      api("prune_preview", { days: days }).then(function (r) {
        var total = Object.keys(r.counts).reduce(function (a, k) { return a + r.counts[k]; }, 0);
        box.hidden = false;
        if (!total) { box.innerHTML = "Nothing is older than " + fmt(days) + " days."; return; }
        box.innerHTML = '<span class="grow">Permanently delete ' + esc(describeCounts(r.counts)) + " older than " + fmt(days) + " days? This can't be undone.</span>" +
          '<button class="btn danger" id="prune-go">Delete</button><button class="btn" id="prune-cancel">Cancel</button>';
        $("prune-cancel").addEventListener("click", close);
        $("prune-go").addEventListener("click", function () {
          this.disabled = true;
          api("prune", { days: days }, "POST").then(function (res) {
            box.innerHTML = "Deleted " + esc(describeCounts(res.deleted)) + ".";
            return loadSetup();
          }).catch(function (e) { box.textContent = "Couldn't delete: " + e.message; });
        });
      }).catch(function (e) { box.hidden = false; box.textContent = "Couldn't check: " + e.message; });
    });
  }

  // ---------- IP drawer ----------
  function bindIpRows(root) {
    root.querySelectorAll("tr.click[data-ip]").forEach(function (tr) {
      if (tr._bound) return;
      tr._bound = true;
      tr.addEventListener("click", function () { openIp(tr.getAttribute("data-ip")); });
    });
  }
  // ---------- WHOIS and abuse reports ----------
  // Looked up only when a section is opened: one HTTPS request from the NAS to the
  // registry that holds the address (ARIN, RIPE NCC, APNIC, LACNIC or AFRINIC).
  var whoisCache = {};
  function whoisFor(ip) {
    if (!whoisCache[ip]) {
      whoisCache[ip] = api("whois", { ip: ip, cc: "" });
      whoisCache[ip].catch(function () { delete whoisCache[ip]; });  // allow a retry
    }
    return whoisCache[ip];
  }
  function whoisOpenPref(v) {
    try {
      if (v === undefined) return localStorage.getItem("secdash-whois-open") === "1";
      localStorage.setItem("secdash-whois-open", v ? "1" : "0");
    } catch (e) { /* storage unavailable */ }
    return false;
  }
  function day(iso) {
    var d = iso && new Date(iso);
    return d && !isNaN(d) ? d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" }) : null;
  }
  function renderWhois(w) {
    var row = function (k, v) { return v ? "<dt>" + k + "</dt><dd>" + v + "</dd>" : ""; };
    var abuse = w.abuse.length ? w.abuse.map(esc).join(", ") +
      (w.abuse_source === "other" ? '<div class="muted small">No abuse contact is listed, so this is the network\'s technical contact.</div>' :
        w.abuse_source === "remarks" ? '<div class="muted small">Taken from the record\'s remarks.</div>' : "") : '<span class="muted">none listed</span>';
    var dates = [day(w.registered) && "registered " + day(w.registered), day(w.updated) && "updated " + day(w.updated)].filter(Boolean).join(" · ");
    var h = '<dl class="kv">' +
      row("Organisation", esc(w.org)) +
      row("Network", esc(w.name) + (w.handle && w.handle !== w.name && w.handle.indexOf(" - ") < 0 ? ' <span class="muted">' + esc(w.handle) + "</span>" : "")) +
      row("Range", esc(w.range) + (w.cidrs.length ? '<div class="muted small">' + w.cidrs.map(esc).join(", ") + "</div>" : "")) +
      row("Country", w.country ? flag(w.country) + " " + esc(w.country) : "") +
      row("Abuse contact", abuse) +
      row("Dates", esc(dates)) +
      row("Registry", esc(w.registry) + (w.link ? ' · <a href="' + esc(w.link) + '" target="_blank" rel="noopener">full record</a>' : "")) +
      "</dl>";
    var contacts = w.contacts.filter(function (c) { return c.emails.length || c.phones.length; });
    if (contacts.length) {
      h += '<h4>Contacts</h4><ul class="contacts">' + contacts.map(function (c) {
        return "<li><b>" + esc(c.name || c.handle) + '</b> <span class="muted">' + esc(c.roles.join(", ")) + "</span>" +
          (c.emails.length ? "<div>" + c.emails.map(esc).join(", ") + "</div>" : "") +
          (c.phones.length ? '<div class="muted">' + c.phones.map(esc).join(", ") + "</div>" : "") + "</li>";
      }).join("") + "</ul>";
    }
    if (w.remarks.length) {
      h += "<h4>Remarks</h4>" + w.remarks.map(function (r) {
        return '<pre class="remark">' + (r.title ? esc(r.title) + ": " : "") + esc(r.text) + "</pre>";
      }).join("");
    }
    return h;
  }

  function utc(ts) { return new Date(ts * 1000).toISOString().replace("T", " ").slice(0, 19) + " UTC"; }
  // Plain-text report built from what SecDash recorded for this IP. Usernames and
  // your own host names are left out: the ISP only needs the source, times and type.
  function abuseReport(r, w) {
    var ip = r.ip;
    var ev = r.auth.filter(function (e) { return e.result !== "success"; }).map(function (e) {
      var svc = e.service || "a service";
      return { ts: e.ts, text: e.result === "fail" ? "failed sign-in attempt (" + svc + ")" : "address blocked after failed sign-ins (" + svc + ")" };
    }).concat(r.http.filter(function (e) { return e.status >= 400; }).map(function (e) {
      return { ts: e.ts, text: "HTTP " + e.method + " " + e.path + " -> " + e.status };
    })).sort(function (a, b) { return a.ts - b.ts; });
    var fails = r.counts.fail || 0;
    var web = r.http.filter(function (e) { return e.status >= 400; }).length;
    var services = [];
    r.auth.forEach(function (e) { if (e.result !== "success" && e.service && services.indexOf(e.service) < 0) services.push(e.service); });
    var what = [];
    if (fails) what.push(fails + " failed sign-in attempt" + (fails === 1 ? "" : "s") + (services.length ? " (" + services.join(", ") + ")" : ""));
    if (web) what.push(web + " malicious or probing web request" + (web === 1 ? "" : "s"));
    if (!what.length && r.block) what.push("blocked by my server after failed sign-ins");
    var shown = ev.slice(-30);
    var lines = [
      "Hello,", "",
      "I'm reporting abusive traffic from an IP address on your network" + (w.org ? " (" + w.org + ")" : "") + ". " +
        "It looks like automated password guessing, typically from a compromised device or a rented server.", "",
      "Source IP:   " + ip,
      w.range ? "Network:     " + (w.name ? w.name + ", " : "") + w.range : null,
      "Activity:    " + (what.join("; ") || "see log below"),
      ev.length ? "First seen:  " + utc(ev[0].ts) : null,
      ev.length ? "Last seen:   " + utc(ev[ev.length - 1].ts) : null,
      r.block ? "The address was automatically blocked by my server's firewall on " + utc(r.block.first_seen) + "." : null,
    ].filter(function (x) { return x !== null; });
    if (shown.length) {
      lines.push("", "Log excerpt (times in UTC):");
      if (ev.length > shown.length) lines.push("(" + (ev.length - shown.length) + " earlier events omitted)");
      shown.forEach(function (e) { lines.push(utc(e.ts) + "  " + ip + "  " + e.text); });
    }
    lines.push("", "Please investigate and take appropriate action. Full logs are available on request.", "", "Thank you.");
    return {
      subject: "Abuse report: " + (fails || r.block ? "password-guessing attempts" : "malicious web requests") + " from " + ip,
      body: lines.join("\n"),
    };
  }
  // The link opens in the top DSM page (target="_top"): DSM's Content-Security-Policy
  // doesn't allow mailto: inside frames, and the dashboard frame would be replaced by
  // a "This content is blocked" page.
  var MAILTO_MAX = 1900;  // longer mailto: links get cut off by some mail apps (Outlook)
  function mailtoHref(to, subject, body) {
    var base = "mailto:" + encodeURIComponent(to).replace(/%40/g, "@") + "?subject=" + encodeURIComponent(subject) + "&body=";
    var full = base + encodeURIComponent(body);
    if (full.length <= MAILTO_MAX) return { href: full, cut: false };
    var lines = body.split("\n"), note = "\n\n[Message shortened. Full log available on request.]";
    while (lines.length > 1 && (base + encodeURIComponent(lines.join("\n") + note)).length > MAILTO_MAX) lines.pop();
    return { href: base + encodeURIComponent(lines.join("\n") + note), cut: true };
  }
  function copyText(text, btn, label, fallbackEl) {
    var done = function () { btn.textContent = "Copied"; setTimeout(function () { btn.textContent = label; }, 1500); };
    if (navigator.clipboard && window.isSecureContext) { navigator.clipboard.writeText(text).then(done); return; }
    if (fallbackEl.select) fallbackEl.select();
    else { var rg = document.createRange(); rg.selectNodeContents(fallbackEl); var sel = getSelection(); sel.removeAllRanges(); sel.addRange(rg); }
    document.execCommand("copy");
    done();
  }
  function renderAbuse(box, r, w) {
    var to = w.abuse.slice();
    w.contacts.forEach(function (c) { c.emails.forEach(function (m) { if (to.indexOf(m) < 0) to.push(m); }); });
    if (!to.length) {
      box.innerHTML = '<div class="empty">The registry record has no email contact for this network.' +
        (w.link ? ' <a href="' + esc(w.link) + '" target="_blank" rel="noopener">Check the full record</a>.' : "") + "</div>";
      return;
    }
    var rep = abuseReport(r, w);
    box.innerHTML =
      (r.counts.success ? '<div class="note">' + statusBadge("warning", "") + "<div>This IP also has <b>successful</b> sign-ins. Make sure it isn't you or someone you know before reporting it.</div></div>" : "") +
      '<div class="form">' +
      '<label for="ab-to">To</label><select id="ab-to">' + to.map(function (m) {
        return '<option value="' + esc(m) + '">' + esc(m) + (w.abuse.indexOf(m) >= 0 && w.abuse_source === "abuse" ? " (abuse contact)" : "") + "</option>";
      }).join("") + "</select>" +
      '<label for="ab-subj">Subject</label><input id="ab-subj" type="text">' +
      '<label for="ab-body">Message</label><textarea id="ab-body" rows="14" spellcheck="false"></textarea>' +
      "</div>" +
      '<div class="actions"><a class="btn primary" id="ab-mail" href="#" target="_top">Open in email app</a><button class="btn" id="ab-copy" type="button">Copy message</button></div>' +
      '<p class="muted small" id="ab-note">Opens a draft in your own email app, so you can review it before sending. Nothing is sent from the NAS. Usernames that were tried aren\'t included.</p>';
    $("ab-subj").value = rep.subject;
    $("ab-body").value = rep.body;
    var sync = function () {
      var m = mailtoHref($("ab-to").value, $("ab-subj").value, $("ab-body").value);
      $("ab-mail").href = m.href;
      $("ab-note").innerHTML = m.cut
        ? "This message is too long for an email link, so the draft is shortened. Use <b>Copy message</b> to paste the full text instead."
        : "Opens a draft in your own email app, so you can review it before sending. Nothing is sent from the NAS. Usernames that were tried aren't included.";
    };
    ["ab-to", "ab-subj", "ab-body"].forEach(function (id) { $(id).addEventListener("input", sync); });
    sync();
    $("ab-copy").addEventListener("click", function () {
      copyText("To: " + $("ab-to").value + "\nSubject: " + $("ab-subj").value + "\n\n" + $("ab-body").value, $("ab-copy"), "Copy message", $("ab-body"));
    });
  }
  function bindLookups(r) {
    var ip = r.ip, wBox = $("dr-whois-box"), aBox = $("dr-abuse-box");
    if (!wBox) return;
    var load = function (target, render) {
      if (target.dataset.loaded) return;
      target.dataset.loaded = "1";
      target.innerHTML = '<div class="empty">Looking up ' + esc(ip) + "…</div>";
      whoisFor(ip).then(function (w) {
        if ($("dr-title").textContent === ip) render(w);
      }).catch(function (e) {
        delete target.dataset.loaded;
        target.innerHTML = '<div class="empty">WHOIS lookup failed: ' + esc(e.message) + "</div>";
      });
    };
    wBox.addEventListener("toggle", function () {
      whoisOpenPref(wBox.open);
      if (wBox.open) load($("dr-whois"), function (w) { $("dr-whois").innerHTML = renderWhois(w); });
    });
    aBox.addEventListener("toggle", function () {
      if (aBox.open) load($("dr-abuse"), function (w) { renderAbuse($("dr-abuse"), r, w); });
    });
    if (whoisOpenPref()) wBox.open = true;
  }

  function openIp(ip) {
    $("drawer").hidden = false;
    $("dr-title").textContent = ip;
    $("dr-body").innerHTML = '<div class="empty">Loading…</div>';
    api("ip", { ip: ip, cc: "" }).then(function (r) {
      var g = r.geo || {}, b = r.block;
      var h = '<dl class="kv">' +
        "<dt>Location</dt><dd>" + place(g) + (g.region ? '<span class="muted"> · ' + esc(g.region) + "</span>" : "") + "</dd>" +
        "<dt>Network</dt><dd>" + (g.org ? esc(g.org) + (g.asn ? " (AS" + g.asn + ")" : "") : "—") + "</dd>" +
        "<dt>Block</dt><dd>" + (b ? (b.active ? statusBadge("critical", "Blocked") : "Released") + " · first " + esc(dt(b.first_seen)) + (b.expire ? " · expires " + esc(dt(b.expire)) : " · no expiry") : "Never blocked") + "</dd>" +
        "<dt>Logins</dt><dd>" + fmt(r.counts.fail) + " failed · " + fmt(r.counts.success) + " successful · " + fmt(r.counts.blocked) + " blocked</dd>" +
        "</dl>";
      if (g.cc !== "LAN") {
        h += '<details class="sect" id="dr-whois-box"><summary>WHOIS</summary><div id="dr-whois"></div></details>' +
          '<details class="sect" id="dr-abuse-box"><summary>Report abuse</summary><div id="dr-abuse"></div></details>';
      }
      h += "<h3>Login events</h3><div id='dr-auth'></div><h3>Web requests</h3><div id='dr-http'></div>";
      $("dr-body").innerHTML = h;
      bindLookups(r);
      table($("dr-auth"), [
        { label: "When", render: function (e) { return esc(dt(e.ts)); } },
        { label: "Result", key: "result" }, { label: "User", key: "user" }, { label: "Service", key: "service" },
      ], r.auth, { empty: "None recorded." });
      table($("dr-http"), [
        { label: "When", render: function (e) { return esc(dt(e.ts)); } },
        { label: "Status", key: "status", num: true }, { label: "Method", key: "method" },
        { label: "Path", wrap: true, render: function (e) { return '<span class="ip">' + esc(e.path) + "</span>"; } },
      ], r.http, { empty: "None recorded." });
    }).catch(function (e) { $("dr-body").innerHTML = '<div class="empty">' + esc(e.message) + "</div>"; });
  }

  // ---------- wiring ----------
  var LOADERS = { overview: loadOverview, map: loadMap, blocks: loadBlocks, logins: loadLogins, web: loadWeb, setup: loadSetup };

  function showError(e) {
    var msg = e && e.message || String(e);
    if (/not signed in|administrators only/.test(msg)) {
      banner("critical", esc(msg) + ". Open SecDash from the DSM main menu as an administrator." +
        (e.diag ? '<div class="muted small">Details for a bug report: ' + esc(JSON.stringify(e.diag)) + "</div>" : ""));
    }
    else if (/no data yet/.test(msg)) banner("warning", "No data yet. Set up the collector task on the <b>Setup</b> tab, then click <b>Run</b> in Task Scheduler.");
    else banner("critical", "Couldn't load data: " + esc(msg));
  }

  function refresh() {
    document.querySelectorAll(".tabs button").forEach(function (b) { b.setAttribute("aria-selected", String(b.dataset.tab === state.tab)); });
    document.querySelectorAll(".view").forEach(function (v) { v.hidden = v.id !== "view-" + state.tab; });
    document.querySelectorAll("#range button").forEach(function (b) { b.setAttribute("aria-pressed", String(b.dataset.range === state.range)); });
    $("filters").hidden = state.tab === "setup";
    $("cc-chip").hidden = !state.cc;
    $("cc-label").innerHTML = state.cc ? "Country: " + flag(state.cc) + " " + esc(state.ccName || state.cc) : "";
    banner(null);
    chartBase();
    if (state.tab !== "setup") loadFreshness();
    var p = LOADERS[state.tab]();
    if (state.tab === "map" && map) setTimeout(function () { try { map.updateSize(); } catch (e) { /* ignore */ } }, 0);
    return p.catch(showError);
  }

  function setCountry(cc, name) {
    state.cc = cc;
    state.ccName = name;
    state.bl.offset = 0;
    refresh();
  }

  document.querySelectorAll(".tabs button").forEach(function (b) {
    b.addEventListener("click", function () { state.tab = b.dataset.tab; persist(); refresh(); });
  });
  document.querySelectorAll("#range button").forEach(function (b) {
    b.addEventListener("click", function () { state.range = b.dataset.range; state.bl.offset = 0; persist(); refresh(); });
  });
  document.querySelectorAll("#map-metric button").forEach(function (b) {
    b.addEventListener("click", function () {
      state.mapMetric = b.dataset.metric;
      document.querySelectorAll("#map-metric button").forEach(function (x) { x.setAttribute("aria-pressed", String(x === b)); });
      loadMap().catch(showError);
    });
  });
  $("cc-clear").addEventListener("click", function () { setCountry(null, null); });
  var qTimer;
  $("bl-q").addEventListener("input", function (e) {
    clearTimeout(qTimer);
    qTimer = setTimeout(function () { state.bl.q = e.target.value; state.bl.offset = 0; loadBlocks().catch(showError); }, 250);
  });
  $("bl-active").addEventListener("change", function (e) { state.bl.active = e.target.checked; state.bl.offset = 0; loadBlocks().catch(showError); });
  $("bl-prev").addEventListener("click", function () { state.bl.offset = Math.max(0, state.bl.offset - state.bl.limit); loadBlocks().catch(showError); });
  $("bl-next").addEventListener("click", function () { state.bl.offset += state.bl.limit; loadBlocks().catch(showError); });
  $("bl-csv").addEventListener("click", exportCsv);
  $("dr-close").addEventListener("click", function () { $("drawer").hidden = true; });
  document.addEventListener("keydown", function (e) { if (e.key === "Escape") $("drawer").hidden = true; });
  bindRetention();
  $("st-copy").addEventListener("click", function () {
    copyText($("st-script").textContent, $("st-copy"), "Copy script", $("st-script"));
  });
  bindIpRows(document);
  document.addEventListener("click", function (e) {
    var tr = e.target.closest && e.target.closest("tr.click[data-ip]");
    if (tr && !tr._bound) openIp(tr.getAttribute("data-ip"));
  });

  // heatmap tooltip
  var tip = document.createElement("div");
  tip.className = "tip"; tip.hidden = true;
  document.body.appendChild(tip);
  document.addEventListener("mousemove", function (e) {
    var c = e.target.closest && e.target.closest("[data-tip]");
    if (!c) { tip.hidden = true; return; }
    tip.textContent = c.getAttribute("data-tip");
    tip.hidden = false;
    tip.style.left = Math.min(e.clientX + 12, innerWidth - tip.offsetWidth - 8) + "px";
    tip.style.top = (e.clientY + 14) + "px";
  });

  // appearance: follow the computer (auto) or force light/dark
  function applyTheme(t) {
    if (t === "light" || t === "dark") document.documentElement.setAttribute("data-theme", t);
    else document.documentElement.removeAttribute("data-theme");
    document.querySelectorAll("#theme button").forEach(function (b) { b.setAttribute("aria-pressed", String(b.dataset.theme === (t || "auto"))); });
  }
  var theme = "auto";
  try { theme = localStorage.getItem("secdash-theme") || "auto"; } catch (e) { /* ignore */ }
  applyTheme(theme);
  document.querySelectorAll("#theme button").forEach(function (b) {
    b.addEventListener("click", function () {
      try { localStorage.setItem("secdash-theme", b.dataset.theme); } catch (e) { /* ignore */ }
      applyTheme(b.dataset.theme);
      refresh();  // charts and map read colours when drawn
    });
  });

  // theme changes repaint charts
  if (window.matchMedia) {
    var mq = matchMedia("(prefers-color-scheme: dark)");
    (mq.addEventListener ? mq.addEventListener.bind(mq, "change") : mq.addListener.bind(mq))(function () { refresh(); });
  }

  function loadFreshness() {
    return api("status").then(function (s) {
      var last = s.collector_last_run;
      $("freshness").textContent = last ? "Data from collector " + ago(last) : "Collector has not run yet";
      $("version").textContent = "SecDash " + s.version;
      if (!last) banner("warning", "The collector hasn't delivered any data yet. See the <b>Setup</b> tab.");
    }).catch(function () { /* the tab's own request reports errors */ });
  }

  refresh();
  setInterval(function () { if (!document.hidden && state.tab !== "setup" && $("drawer").hidden) refresh(); }, 5 * 60 * 1000);
})();
