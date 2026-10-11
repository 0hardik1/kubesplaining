// Kubesplaining HTML report: tab routing, findings filters, attack-path graph
// highlights, and glossary hovers. No dependencies; the report must work as a
// single self-contained file opened from disk.
(function () {
  'use strict';

  function $$(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }
  function splitPaths(s) { return s ? s.split(' ') : []; }
  function intersects(list, set) {
    for (var i = 0; i < list.length; i++) if (set[list[i]]) return true;
    return false;
  }
  function toSet(list) { var o = {}; list.forEach(function (v) { o[v] = true; }); return o; }

  // --- Hash format -----------------------------------------------------------
  // #<anchor>?<params>. anchor is "tab-<name>", an element id (a finding rule,
  // a module, a target), or empty. params: q, severity, module, category,
  // resource (findings filters) and target (attack-paths target).
  function parseHash() {
    var raw = (window.location.hash || '').replace(/^#/, '');
    var q = raw.indexOf('?');
    var anchor = q >= 0 ? raw.slice(0, q) : raw;
    var params = {};
    (q >= 0 ? raw.slice(q + 1) : '').split('&').forEach(function (pair) {
      var eq = pair.indexOf('=');
      if (eq <= 0) return;
      try { params[decodeURIComponent(pair.slice(0, eq))] = decodeURIComponent(pair.slice(eq + 1)); } catch (_) { /* ignore malformed */ }
    });
    try { anchor = decodeURIComponent(anchor); } catch (_) { /* keep raw */ }
    return { anchor: anchor, params: params };
  }
  function setHash(hash, push) {
    if (hash === window.location.hash) return;
    try {
      if (push) history.pushState(null, '', hash || window.location.pathname);
      else history.replaceState(null, '', hash || window.location.pathname);
    } catch (_) {
      window.location.hash = hash; // some browsers refuse history edits on file:// URLs
    }
  }

  // --- Tabs ------------------------------------------------------------------
  var panels = {};
  $$('section.panel[data-tab]').forEach(function (p) { panels[p.getAttribute('data-tab')] = p; });
  var tabButtons = $$('.tab[data-tab]');
  // Old report links used these tab names; send them to where that content lives now.
  var ALIASES = { overview: 'summary', attack: 'paths', privesc: 'paths', graph: 'paths' };

  function resolveTab(name) {
    name = ALIASES[name] || name;
    if (panels[name]) return name;
    if (name === 'paths' && panels.summary) return 'summary';
    return null;
  }
  function defaultTab() {
    var d = resolveTab(document.body.getAttribute('data-active-tab') || '');
    if (d) return d;
    var keys = Object.keys(panels);
    return keys.length ? keys[0] : null;
  }
  function activate(name) {
    name = resolveTab(name) || defaultTab();
    if (!name) return;
    document.body.setAttribute('data-active-tab', name);
    Object.keys(panels).forEach(function (k) { panels[k].classList.toggle('is-active', k === name); });
    tabButtons.forEach(function (b) { b.setAttribute('aria-selected', b.getAttribute('data-tab') === name ? 'true' : 'false'); });
  }
  tabButtons.forEach(function (b) {
    b.addEventListener('click', function () {
      var name = b.getAttribute('data-tab');
      setHash('#tab-' + name, true);
      activate(name);
      window.scrollTo(0, 0);
    });
  });

  // --- Findings filters ------------------------------------------------------
  var FILTER_KEYS = ['severity', 'module', 'category', 'resource'];
  var FILTER_LABELS = { severity: 'Severity', module: 'Module', category: 'Type', resource: 'Resource' };
  var SEV_NAMES = { crit: 'Critical', high: 'High', med: 'Medium', low: 'Low', info: 'Info' };
  var filters = { severity: null, module: null, category: null, resource: null };
  var query = '';

  var instances = $$('.instance.finding');
  var ruleGroups = $$('.rule-group');
  var moduleSections = $$('.module-section');
  var statusEl = document.getElementById('f-status');
  var statusDefault = statusEl ? statusEl.textContent : '';
  var emptyEl = document.getElementById('f-empty');
  var searchInput = document.getElementById('findings-search-input');

  instances.forEach(function (el) {
    var sec = el.closest('.module-section');
    el.__module = sec ? sec.getAttribute('data-module') : '';
  });
  ruleGroups.forEach(function (g) {
    var c = g.querySelector('.rule-count');
    g.__countEl = c;
    g.__countText = c ? c.textContent : '';
    g.__instances = $$('.instance.finding', g);
  });

  function haystack(el) {
    if (el.__hay == null) {
      var parts = ['data-rule', 'data-subject', 'data-resource', 'data-namespace', 'data-category'].map(function (a) { return el.getAttribute(a) || ''; });
      ['.instance-title', '.finding-title'].forEach(function (sel) {
        var t = el.querySelector(sel);
        if (t) parts.push(t.textContent);
      });
      var group = el.closest('.rule-group');
      var rt = group && group.querySelector('.rule-title');
      if (rt) parts.push(rt.textContent);
      el.__hay = parts.join(' ').toLowerCase();
    }
    return el.__hay;
  }

  function anyFilter() {
    if (query) return true;
    for (var i = 0; i < FILTER_KEYS.length; i++) if (filters[FILTER_KEYS[i]] != null) return true;
    return false;
  }

  function matches(el) {
    if (query && haystack(el).indexOf(query) === -1) return false;
    for (var i = 0; i < FILTER_KEYS.length; i++) {
      var k = FILTER_KEYS[i], want = filters[k];
      if (want == null) continue;
      var got = k === 'module' ? el.__module : (el.getAttribute('data-' + k) || '');
      if (got !== want) return false;
    }
    return true;
  }

  function applyFilters() {
    if (!instances.length) return;
    var active = anyFilter();
    var shown = 0;
    instances.forEach(function (el) {
      var keep = matches(el);
      el.hidden = !keep;
      if (keep) shown++;
    });
    ruleGroups.forEach(function (g) {
      var visible = 0;
      g.__instances.forEach(function (el) { if (!el.hidden) visible++; });
      g.hidden = visible === 0;
      if (g.__countEl) g.__countEl.textContent = active && visible !== g.__instances.length ? visible + ' of ' + g.__countText : g.__countText;
      // Open matching rules while a filter narrows the list; close them again
      // when it is cleared, but leave rules the reader opened by hand alone.
      if (active && visible > 0 && !g.open) { g.open = true; g.__auto = true; }
      if (!active && g.__auto) { g.open = false; g.__auto = false; }
    });
    moduleSections.forEach(function (s) {
      s.hidden = !$$('.rule-group', s).some(function (g) { return !g.hidden; });
    });
    if (statusEl) statusEl.textContent = active ? 'Showing ' + shown + ' of ' + instances.length + ' findings.' : statusDefault;
    if (emptyEl) emptyEl.hidden = shown !== 0;

    $$('[data-sev-toggle]').forEach(function (b) {
      b.setAttribute('aria-pressed', b.getAttribute('data-sev-toggle') === filters.severity ? 'true' : 'false');
    });
    $$('[data-module-link]').forEach(function (a) {
      a.classList.toggle('active', a.getAttribute('data-module-link') === filters.module);
    });
    renderChips();
  }

  function renderChips() {
    var box = document.getElementById('fl-active');
    if (!box) return;
    var wrap = box.closest('.findings-filters');
    box.innerHTML = '';
    var any = false;
    FILTER_KEYS.forEach(function (k) {
      if (filters[k] == null) return;
      any = true;
      var chip = document.createElement('button');
      chip.type = 'button';
      chip.className = 'f-chip';
      chip.title = 'Remove this filter';
      var key = document.createElement('span');
      key.className = 'k';
      key.textContent = FILTER_LABELS[k] + ':';
      var val = document.createElement('span');
      val.textContent = k === 'severity' ? (SEV_NAMES[filters[k]] || filters[k]) : filters[k];
      var x = document.createElement('span');
      x.className = 'x';
      x.setAttribute('aria-hidden', 'true');
      x.textContent = '×';
      chip.appendChild(key); chip.appendChild(val); chip.appendChild(x);
      chip.addEventListener('click', function () { filters[k] = null; commit(); });
      box.appendChild(chip);
    });
    if (query) any = true;
    if (wrap) wrap.hidden = !any;
  }

  // commit applies the filters and mirrors them into the hash, so a filtered
  // view can be shared or survive a reload.
  function commit() {
    applyFilters();
    var parts = [];
    if (query) parts.push('q=' + encodeURIComponent(query));
    FILTER_KEYS.forEach(function (k) { if (filters[k] != null) parts.push(k + '=' + encodeURIComponent(filters[k])); });
    setHash(parts.length ? '#tab-findings?' + parts.join('&') : '#tab-findings', false);
  }

  function readFilters(params) {
    FILTER_KEYS.forEach(function (k) { filters[k] = params[k] != null ? params[k] : null; });
    query = params.q != null ? String(params.q).toLowerCase() : '';
    if (searchInput) searchInput.value = params.q || '';
    applyFilters();
  }

  // Summary-tab links ("12 critical", a bar row) set one filter and open Findings.
  document.addEventListener('click', function (ev) {
    var t = ev.target.closest && ev.target.closest('[data-fl-target]');
    if (!t) return;
    ev.preventDefault();
    FILTER_KEYS.forEach(function (k) { filters[k] = null; });
    query = '';
    if (searchInput) searchInput.value = '';
    t.getAttribute('data-fl-target').split('|').forEach(function (part) {
      var i = part.indexOf(':');
      if (i > 0 && filters.hasOwnProperty(part.slice(0, i))) filters[part.slice(0, i)] = part.slice(i + 1);
    });
    activate('findings');
    commit();
    window.scrollTo(0, 0);
  });
  $$('[data-sev-toggle]').forEach(function (b) {
    b.addEventListener('click', function () {
      var v = b.getAttribute('data-sev-toggle');
      filters.severity = filters.severity === v ? null : v;
      commit();
    });
  });
  var clearBtn = document.getElementById('fl-clear');
  if (clearBtn) clearBtn.addEventListener('click', function () {
    FILTER_KEYS.forEach(function (k) { filters[k] = null; });
    query = '';
    if (searchInput) searchInput.value = '';
    commit();
  });
  if (searchInput) {
    var debounce;
    searchInput.addEventListener('input', function () {
      clearTimeout(debounce);
      debounce = setTimeout(function () {
        query = searchInput.value.trim().toLowerCase();
        commit();
      }, 120);
    });
    searchInput.addEventListener('keydown', function (ev) {
      if (ev.key !== 'Escape') return;
      ev.preventDefault();
      if (searchInput.value) { searchInput.value = ''; query = ''; commit(); } else { searchInput.blur(); }
    });
    document.addEventListener('keydown', function (ev) {
      if (ev.key !== '/' || ev.metaKey || ev.ctrlKey) return;
      var tag = (ev.target.tagName || '').toUpperCase();
      if (tag === 'INPUT' || tag === 'TEXTAREA' || ev.target.isContentEditable) return;
      ev.preventDefault();
      activate('findings');
      searchInput.focus();
      searchInput.select();
    });
  }

  // Sidebar module links: mark the module being read.
  (function () {
    var links = {};
    $$('[data-module-link]').forEach(function (a) { links[a.getAttribute('data-module-link')] = a; });
    if (!moduleSections.length || typeof IntersectionObserver === 'undefined') return;
    var seen = {};
    var obs = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) { if (e.isIntersecting) seen[e.target.id] = true; else delete seen[e.target.id]; });
      if (filters.module) return;
      var first = null;
      moduleSections.forEach(function (s) { if (!first && seen[s.id]) first = s.id; });
      Object.keys(links).forEach(function (id) { links[id].classList.toggle('active', id === first); });
    }, { rootMargin: '-120px 0px -55% 0px' });
    moduleSections.forEach(function (s) { obs.observe(s); });
  })();

  // --- Attack paths ----------------------------------------------------------
  var views = {};
  var targetButtons = $$('.target-btn[data-target]');

  // One floating card shared by every graph: the full identity under the
  // pointer, where it lives, and how many paths run through it.
  var apTip = null;
  function ensureTip() {
    if (apTip) return apTip;
    apTip = document.createElement('div');
    apTip.className = 'ap-tip';
    apTip.hidden = true;
    document.body.appendChild(apTip);
    return apTip;
  }
  function line(parent, cls, text) {
    var el = document.createElement('span');
    el.className = cls;
    el.textContent = text;
    parent.appendChild(el);
    return el;
  }
  function showNodeTip(node) {
    var tip = ensureTip();
    tip.innerHTML = '';
    var t = document.createElement('strong');
    t.textContent = node.getAttribute('data-label') || '';
    tip.appendChild(t);
    var kind = node.getAttribute('data-kind');
    if (kind) line(tip, 'k', kind);
    var count = parseInt(node.getAttribute('data-count') || '0', 10);
    if (count && !node.classList.contains('target')) {
      var n = line(tip, 'n', count + (count === 1 ? ' path' : ' paths') + ' through it · worst ');
      var sev = node.getAttribute('data-sev') || 'info';
      var b = document.createElement('b');
      b.className = sev;
      b.textContent = (SEV_NAMES[sev] || sev).toLowerCase();
      n.appendChild(b);
    }
    var members = node.getAttribute('data-members');
    if (members) line(tip, 'm', members);
    var r = node.getBoundingClientRect();
    var x = Math.max(200, Math.min(window.innerWidth - 200, r.left + r.width / 2));
    // Above the box unless the sticky top bar would cover the card; then below it.
    var below = r.top < 200;
    tip.classList.toggle('below', below);
    tip.style.left = (x + window.pageXOffset) + 'px';
    tip.style.top = ((below ? r.bottom : r.top) + window.pageYOffset) + 'px';
    tip.hidden = false;
  }
  function hideTip() { if (apTip) apTip.hidden = true; }
  window.addEventListener('scroll', hideTip, true);

  $$('.target-view[data-target-view]').forEach(function (view) {
    var slug = view.getAttribute('data-target-view');
    var svg = view.querySelector('.ap-svg');
    var rows = $$('.path-row[data-path]', view);
    var countEl = view.querySelector('[data-path-count]');
    var countText = countEl ? countEl.textContent : '';
    var focusLabel = view.querySelector('[data-focus-label]');
    var items = svg ? $$('[data-paths]', svg).map(function (el) { return { el: el, paths: splitPaths(el.getAttribute('data-paths')) }; }) : [];
    var pinned = null; // { node, set }

    function light(set) {
      if (!svg) return;
      svg.classList.add('is-dim');
      items.forEach(function (it) { it.el.classList.toggle('lit', intersects(it.paths, set)); });
    }
    function unlight() {
      if (!svg) return;
      svg.classList.remove('is-dim');
      items.forEach(function (it) { it.el.classList.remove('lit'); });
    }
    function restore() { if (pinned) light(pinned.set); else unlight(); }

    // setFocus pins the paths through one element (a box or an arrow) and
    // filters the list under the graph to them.
    function setFocus(node) {
      if (pinned) pinned.node.classList.remove('pinned');
      if (!node) {
        pinned = null;
        view.classList.remove('has-focus');
        rows.forEach(function (r) { r.classList.remove('hidden-by-focus'); });
        if (countEl) countEl.textContent = countText;
        unlight();
        return;
      }
      var set = toSet(splitPaths(node.getAttribute('data-paths')));
      pinned = { node: node, set: set };
      node.classList.add('pinned');
      view.classList.add('has-focus');
      var shown = 0;
      rows.forEach(function (r) {
        var keep = !!set[r.getAttribute('data-path')];
        r.classList.toggle('hidden-by-focus', !keep);
        if (keep) shown++;
      });
      if (countEl) countEl.textContent = shown + ' of ' + rows.length + ' paths';
      if (focusLabel) focusLabel.textContent = node.getAttribute('data-label') || '';
      light(set);
    }

    if (svg) {
      // The floating card replaces the browser's own tooltip.
      $$('.ap-node > title, .ap-hit > title', svg).forEach(function (t) { t.parentNode.removeChild(t); });
      $$('.ap-node', svg).forEach(function (node) {
        var set = toSet(splitPaths(node.getAttribute('data-paths')));
        var isTarget = node.classList.contains('target');
        function enter() {
          // Every path ends at the target, so tracing it would light everything
          // and print every edge label on top of each other. Leave it inert.
          if (!isTarget) light(set);
          showNodeTip(node);
        }
        function leave() { restore(); hideTip(); }
        node.addEventListener('mouseenter', enter);
        node.addEventListener('mouseleave', leave);
        node.addEventListener('focus', enter);
        node.addEventListener('blur', leave);
        node.addEventListener('click', function (ev) {
          ev.stopPropagation();
          setFocus(isTarget || (pinned && pinned.node === node) ? null : node);
        });
        node.addEventListener('keydown', function (ev) {
          if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); node.dispatchEvent(new MouseEvent('click', { bubbles: true })); }
        });
      });
      $$('.ap-hit', svg).forEach(function (hit) {
        var set = toSet(splitPaths(hit.getAttribute('data-paths')));
        hit.addEventListener('mouseenter', function () { light(set); });
        hit.addEventListener('mouseleave', restore);
        hit.addEventListener('click', function (ev) {
          ev.stopPropagation();
          setFocus(pinned && pinned.node === hit ? null : hit);
        });
      });
      svg.addEventListener('click', function () { setFocus(null); });
    }
    var clear = view.querySelector('[data-clear-focus]');
    if (clear) clear.addEventListener('click', function () { setFocus(null); });
    rows.forEach(function (r) {
      var set = toSet([r.getAttribute('data-path')]);
      var sum = r.querySelector('summary');
      if (!sum) return;
      sum.addEventListener('mouseenter', function () { light(set); r.classList.add('is-hot'); });
      sum.addEventListener('mouseleave', function () { restore(); r.classList.remove('is-hot'); });
    });
    view.addEventListener('keydown', function (ev) { if (ev.key === 'Escape' && pinned) setFocus(null); });

    views[slug] = { el: view, clear: function () { setFocus(null); hideTip(); } };
  });

  function selectTarget(slug) {
    if (!views[slug]) return false;
    Object.keys(views).forEach(function (k) {
      var on = k === slug;
      views[k].el.classList.toggle('is-active', on);
      if (!on) views[k].clear();
    });
    targetButtons.forEach(function (b) { b.setAttribute('aria-selected', b.getAttribute('data-target') === slug ? 'true' : 'false'); });
    return true;
  }
  targetButtons.forEach(function (b) {
    b.addEventListener('click', function () {
      var slug = b.getAttribute('data-target');
      selectTarget(slug);
      setHash('#tab-paths?target=' + encodeURIComponent(slug), false);
    });
  });

  // --- Routing ---------------------------------------------------------------
  function flash(el) {
    el.classList.add('flash');
    setTimeout(function () { el.classList.remove('flash'); }, 1600);
  }

  function route() {
    var h = parseHash();
    var anchor = h.anchor;
    var tab = null;
    var el = null;
    var m = /^tab-(.+)$/.exec(anchor);
    if (m) {
      tab = m[1];
    } else if (anchor) {
      el = document.getElementById(anchor);
      var panel = el && el.closest('section.panel[data-tab]');
      if (panel) tab = panel.getAttribute('data-tab');
    }
    var hasFilter = h.params.q != null || FILTER_KEYS.some(function (k) { return h.params[k] != null; });
    if (!tab && hasFilter) tab = 'findings';
    activate(tab || defaultTab());
    readFilters(h.params);
    if (h.params.target) selectTarget(h.params.target);

    if (el) {
      // Open the enclosing disclosures so the target is visible, then scroll to it.
      var d = el.closest('details');
      while (d) { d.open = true; d = d.parentElement && d.parentElement.closest('details'); }
      if (el.tagName === 'DETAILS') el.open = true;
      var tv = el.closest('.target-view');
      if (tv) selectTarget(tv.getAttribute('data-target-view'));
      requestAnimationFrame(function () {
        el.scrollIntoView({ block: 'start' });
        if (el.classList.contains('rule-group')) flash(el);
      });
    } else if (m) {
      window.scrollTo(0, 0);
    }
  }

  // In-page links: route even when the hash does not change (a second click on
  // the same link), which the hashchange event would miss.
  document.addEventListener('click', function (ev) {
    if (ev.defaultPrevented || ev.button !== 0 || ev.metaKey || ev.ctrlKey || ev.shiftKey) return;
    var a = ev.target.closest && ev.target.closest('a[href^="#"]');
    if (!a) return;
    var href = a.getAttribute('href');
    if (href.length < 2) return;
    ev.preventDefault();
    setHash(href, true);
    route();
  });
  window.addEventListener('hashchange', route);
  window.addEventListener('popstate', route);
  route();
  // The browser jumps to a "#tab-..." panel on load, after route() ran; a tab
  // link should open the panel at the top of the page instead.
  window.addEventListener('load', function () {
    if (/^tab-/.test(parseHash().anchor)) window.scrollTo(0, 0);
  });

  // --- Glossary hovers -------------------------------------------------------
  (function () {
    var tip = document.getElementById('kp-tip');
    var data = document.getElementById('kp-glossary');
    if (!tip || !data) return;
    var glossary = {};
    try { glossary = JSON.parse(data.textContent || '{}') || {}; } catch (_) { return; }
    function term(ev) { return ev.target.closest && ev.target.closest('code.gloss[data-glossary-key]'); }
    function show(el) {
      var entry = glossary[el.getAttribute('data-glossary-key')];
      if (!entry) return;
      tip.innerHTML = '';
      var t = document.createElement('strong');
      t.textContent = entry.Title || '';
      tip.appendChild(t);
      if (entry.Short) tip.appendChild(document.createTextNode(entry.Short));
      var r = el.getBoundingClientRect();
      var x = Math.max(180, Math.min(window.innerWidth - 180, r.left + r.width / 2));
      tip.style.left = (x + window.pageXOffset) + 'px';
      tip.style.top = (r.top + window.pageYOffset) + 'px';
      tip.hidden = false;
    }
    function hide() { tip.hidden = true; }
    document.addEventListener('mouseover', function (ev) { var el = term(ev); if (el) show(el); });
    document.addEventListener('mouseout', function (ev) { if (term(ev)) hide(); });
    document.addEventListener('focusin', function (ev) { var el = term(ev); if (el) show(el); });
    document.addEventListener('focusout', function (ev) { if (term(ev)) hide(); });
    document.addEventListener('keydown', function (ev) { if (ev.key === 'Escape') hide(); });
    window.addEventListener('scroll', hide, true);
  })();
})();
