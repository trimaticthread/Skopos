"use strict";
// Skopos canlı arayüz — bağımlılıksız vanilla JS.
// Kullanıcı verisi (tool çıktısı) her zaman textContent ile basılır; innerHTML'e
// ham veri konmaz (HTML/JS injection'a karşı güvenli).

const CATS = [
  { key: "port",      label: "🔓 Açık Portlar & Servisler", explain: "Hedefte dışarı açık portlar ve üzerinde çalışan servis/sürümler." },
  { key: "web",       label: "🌐 Web Varlıkları",           explain: "Tespit edilen web sunucuları, teknolojiler ve sayfa başlıkları." },
  { key: "content",   label: "📁 İçerik Keşfi",             explain: "Fuzzing ile bulunan dizinler, dosyalar ve API uçları." },
  { key: "vuln",      label: "🛡️ Zafiyet İzleri",          explain: "Tarayıcıların işaret ettiği olası zayıf noktalar — doğrulanmalı." },
  { key: "subdomain", label: "🔗 Subdomainler",             explain: "Keşfedilen alt alan adları." },
  { key: "script",    label: "📜 Script Bulguları",         explain: "nmap NSE scriptlerinin çıktıları." },
  { key: "host",      label: "🖥️ Host Bilgisi",            explain: "İşletim sistemi ipuçları ve host detayları." },
  { key: "osint",     label: "🛰️ OSINT",                   explain: "Pasif kaynaklardan toplanan bilgiler." },
];
const SEVS = [
  { key: "critical", label: "kritik" }, { key: "high", label: "yüksek" },
  { key: "medium", label: "orta" }, { key: "low", label: "düşük" }, { key: "info", label: "bilgi" },
];

const state = {
  runId: null, summary: null, runMtime: null,
  search: "", cats: new Set(), sevs: new Set(),
  live: false, liveTimer: null,
};

// --- küçük DOM yardımcıları ---
function h(tag, attrs, children) {
  const el = document.createElement(tag);
  if (attrs) for (const k in attrs) {
    if (k === "class") el.className = attrs[k];
    else if (k === "text") el.textContent = attrs[k];
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), attrs[k]);
    else if (attrs[k] != null) el.setAttribute(k, attrs[k]);
  }
  if (children) for (const c of [].concat(children)) if (c != null) el.append(c);
  return el;
}
const $ = (id) => document.getElementById(id);
async function getJSON(url) { const r = await fetch(url); if (!r.ok) throw new Error(r.status); return r.json(); }

// --- tarama listesi ---
async function loadRuns(selectFirst) {
  let runs = [];
  try { runs = await getJSON("/api/runs"); } catch (e) { return; }
  const sel = $("runSelect");
  const prev = state.runId;
  sel.textContent = "";
  if (!runs.length) {
    sel.append(h("option", { value: "", text: "henüz tarama yok" }));
    renderEmpty("Henüz tarama yok. Bir tarama çalıştır, sonuçlar burada belirir.");
    return;
  }
  for (const r of runs) {
    const sc = r.severity_counts || {};
    const bits = ["critical", "high", "medium"].map(k => sc[k]).filter(Boolean);
    const extra = bits.length ? "  •  " + bits.join("/") + " önemli" : "";
    const label = `${r.target}  —  ${fmtTime(r.started)}  (${r.open_ports}p / ${r.findings}b)${extra}`;
    sel.append(h("option", { value: r.id, text: label }));
  }
  const stillExists = runs.some(r => r.id === prev);
  const chosen = (selectFirst || !stillExists) ? runs[0].id : prev;
  sel.value = chosen;
  // canlı modda seçili tarama değişmişse yeniden yükle
  if (chosen !== state.runId) { state.runId = chosen; await loadRun(chosen); }
  else { // mtime değiştiyse tazele
    const cur = runs.find(r => r.id === chosen);
    if (cur && cur.mtime !== state.runMtime) await loadRun(chosen);
  }
}

async function loadRun(id) {
  let summary;
  try { summary = await getJSON("/api/run?id=" + encodeURIComponent(id)); }
  catch (e) { renderEmpty("Tarama okunamadı."); return; }
  state.runId = id; state.summary = summary;
  const runs = await getJSON("/api/runs").catch(() => []);
  const meta = runs.find(r => r.id === id);
  state.runMtime = meta ? meta.mtime : null;
  render();
  loadLogs(id);
}

// --- filtreler ---
function matches(f) {
  if (state.cats.size && !state.cats.has(f.category)) return false;
  if (state.sevs.size && !state.sevs.has(f.severity)) return false;
  if (state.search) {
    const q = state.search.toLowerCase();
    const hay = [f.title, f.evidence, f.source, (f.tags || []).join(" "),
                 JSON.stringify(f.data || {})].join(" ").toLowerCase();
    if (!hay.includes(q)) return false;
  }
  return true;
}

// --- render ---
function fmtTime(ts) {
  if (!ts || ts.length < 15) return ts || "-";
  // 20261014_030735 -> 2026-10-14 03:07
  return `${ts.slice(0,4)}-${ts.slice(4,6)}-${ts.slice(6,8)} ${ts.slice(9,11)}:${ts.slice(11,13)}`;
}

function renderEmpty(msg) {
  $("summary").textContent = ""; $("sevBadges").textContent = "";
  $("content").textContent = ""; $("suggestions").textContent = "";
  $("content").append(h("div", { class: "empty" }, [
    h("div", { class: "big", text: "🛰️ Skopos" }), h("div", { text: msg }),
  ]));
  $("resultCount").textContent = "";
}

function render() {
  const s = state.summary; if (!s) return;
  const findings = s.findings || [];

  // özet başlık
  const sum = $("summary"); sum.textContent = "";
  sum.append(h("h1", {}, [document.createTextNode("Hedef: "), h("span", { class: "tgt", text: s.target || "?" })]));
  const pills = h("div", { class: "pills" });
  pills.append(h("span", { class: "pill" }, [document.createTextNode("profil "), h("b", { text: s.profile || "—" })]));
  pills.append(h("span", { class: "pill" }, [document.createTextNode("zaman "), h("b", { text: fmtTime(s.started) })]));
  pills.append(h("span", { class: "pill" }, [document.createTextNode("açık port "), h("b", { text: String((s.open_ports || []).length) })]));
  pills.append(h("span", { class: "pill" }, [document.createTextNode("web "), h("b", { text: String((s.web_assets || []).length) })]));
  if ((s.os || []).length) pills.append(h("span", { class: "pill" }, [document.createTextNode("OS "), h("b", { text: s.os.join(", ") })]));
  sum.append(pills);

  // severity rozetleri (tıklanınca filtre)
  const counts = s.severity_counts || {};
  const sb = $("sevBadges"); sb.textContent = "";
  for (const sv of SEVS) {
    const n = counts[sv.key] || 0;
    const badge = h("span", {
      class: "sev-badge sev-" + sv.key, "data-on": state.sevs.has(sv.key) ? "1" : "0",
      onclick: () => { toggle(state.sevs, sv.key); render(); },
    }, [h("span", { class: "swatch" }), document.createTextNode(sv.label + " "),
        h("span", { class: "cnt", text: String(n) })]);
    sb.append(badge);
  }

  // kategori çipleri
  const cc = $("catChips"); cc.textContent = "";
  for (const c of CATS) {
    const n = findings.filter(f => f.category === c.key).length;
    if (!n) continue;
    cc.append(h("span", {
      class: "chip", "data-on": state.cats.has(c.key) ? "1" : "0",
      onclick: () => { toggle(state.cats, c.key); render(); },
      text: `${c.label.replace(/^\S+\s/, "")} (${n})`,
    }));
  }

  // içerik: kategoriye göre gruplar
  const visible = findings.filter(matches);
  $("resultCount").textContent = `${visible.length} / ${findings.length} bulgu`;
  const content = $("content"); content.textContent = "";
  if (!findings.length) {
    content.append(h("div", { class: "empty" }, [
      h("div", { class: "big", text: "Bu taramada bulgu yok" }),
      h("div", { text: "Hedef yanıt vermemiş olabilir ya da seçtiğin modüller sonuç üretmedi." }),
    ]));
  } else if (!visible.length) {
    content.append(h("div", { class: "empty" }, [h("div", { text: "Filtreye uyan bulgu yok. “Hepsini göster”e bas." })]));
  } else {
    for (const c of CATS) {
      const group = visible.filter(f => f.category === c.key);
      if (!group.length) continue;
      content.append(renderSection(c, group));
    }
  }

  renderSuggestions(s.suggestions || []);
}

function renderSection(cat, items) {
  const sec = h("section", { class: "section" });
  sec.append(h("h2", {}, [document.createTextNode(cat.label + " "),
    h("span", { class: "count", text: `(${items.length})` })]));
  sec.append(h("p", { class: "explain", text: cat.explain }));
  const table = h("table");
  table.append(h("thead", {}, h("tr", {}, [
    h("th", { text: "Önem" }), h("th", { text: "Bulgu" }),
    h("th", { text: "Kanıt" }), h("th", { text: "Kaynak" }),
  ])));
  const tb = h("tbody");
  for (const f of items) tb.append(renderRow(f));
  table.append(tb);
  sec.append(h("div", { class: "card" }, table));
  return sec;
}

function renderRow(f) {
  const sevCell = h("td", { class: "sev-cell" }, h("span", { class: "sev-tag " + f.severity, text: f.severity }));

  // başlık + (url varsa link) + tags
  const titleCell = h("td", { class: "title-cell" });
  const url = f.data && f.data.url;
  if (url && /^https?:\/\//.test(url)) {
    const pre = f.title.split(url)[0];
    if (pre) titleCell.append(document.createTextNode(pre));
    titleCell.append(h("a", { href: url, target: "_blank", rel: "noopener", text: url }));
  } else {
    titleCell.append(document.createTextNode(f.title));
  }
  if (f.source) titleCell.append(h("div", { class: "src", text: f.source }));
  if ((f.tags || []).length) {
    const tags = h("div", { class: "tags" });
    for (const t of f.tags) tags.append(h("span", { class: "tag", text: t }));
    titleCell.append(tags);
  }

  const evCell = h("td", { class: "evidence", text: f.evidence || "" });
  const srcCell = h("td", { class: "mono", text: f.source || "" });
  return h("tr", { class: "row" }, [sevCell, titleCell, evCell, srcCell]);
}

function renderSuggestions(sugg) {
  const box = $("suggestions"); box.textContent = "";
  if (!sugg.length) return;
  const sec = h("section", { class: "section" });
  sec.append(h("h2", { text: "✅ Önerilen Sonraki Adımlar" }));
  sec.append(h("p", { class: "explain", text: "Bu sonuçlara göre mantıklı bir sonraki hamle." }));
  const ul = h("ul", { class: "steps" });
  for (const s of sugg) {
    const li = h("li", {}, document.createTextNode(s.text));
    if (s.cmd) li.append(h("code", { text: s.cmd }));
    ul.append(li);
  }
  sec.append(h("div", { class: "card" }, ul));
  box.append(sec);
}

// --- ham loglar ---
async function loadLogs(id) {
  const list = $("logsList"); list.textContent = "";
  let files = [];
  try { files = await getJSON("/api/logfiles?id=" + encodeURIComponent(id)); } catch (e) {}
  if (!files.length) { list.append(h("p", { class: "explain", text: "Log dosyası yok." })); return; }
  for (const fn of files) {
    const pre = h("pre", { text: "yükleniyor…" });
    const det = h("details", { class: "logs" }, [h("summary", { text: fn }), pre]);
    let loaded = false;
    det.addEventListener("toggle", async () => {
      if (det.open && !loaded) {
        loaded = true;
        try {
          const r = await fetch(`/api/log?id=${encodeURIComponent(id)}&file=${encodeURIComponent(fn)}`);
          pre.textContent = await r.text();
        } catch (e) { pre.textContent = "okunamadı"; }
      }
    });
    list.append(det);
  }
}

// --- yardımcı ---
function toggle(set, key) { if (set.has(key)) set.delete(key); else set.add(key); }
function setLive(on) {
  state.live = on;
  $("liveBox").classList.toggle("on", on);
  $("liveText").textContent = "canlı: " + (on ? "açık" : "kapalı");
  if (state.liveTimer) { clearInterval(state.liveTimer); state.liveTimer = null; }
  if (on) state.liveTimer = setInterval(() => loadRuns(false), 4000);
}

// --- olaylar ---
$("runSelect").addEventListener("change", (e) => { state.runId = e.target.value; loadRun(e.target.value); });
$("search").addEventListener("input", (e) => { state.search = e.target.value.trim(); render(); });
$("showAll").addEventListener("click", () => {
  state.cats.clear(); state.sevs.clear(); state.search = ""; $("search").value = ""; render();
});
$("refreshBtn").addEventListener("click", () => loadRuns(false));
$("liveBox").addEventListener("click", () => setLive(!state.live));

// --- başlat ---
loadRuns(true);
