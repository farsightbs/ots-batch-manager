const { invoke } = window.__TAURI__.core;
const { open } = window.__TAURI__.dialog;
const { revealItemInDir } = window.__TAURI__.opener;
const { getCurrentWebview } = window.__TAURI__.webview;

// ---------- settings (per-machine convenience, so localStorage is enough) ----------
const DEFAULTS = {
  lang: "en",
  sameDir: false,
  backup: false,
  calendars: [
    "https://a.pool.opentimestamps.org",
    "https://b.pool.opentimestamps.org",
    "https://a.pool.eternitywall.com",
    "https://ots.btc.catallaxy.com",
  ],
  explorers: ["https://mempool.space/api", "https://blockstream.info/api"],
};
let settings = { ...DEFAULTS };
try { Object.assign(settings, JSON.parse(localStorage.getItem("settings") || "{}")); } catch {}
const saveSettings = () => { try { localStorage.setItem("settings", JSON.stringify(settings)); } catch {} };
LANG = I18N[settings.lang] ? settings.lang : "en";

// ---------- helpers ----------
const $ = (s, root = document) => root.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
const norm = (p) => p.replace(/\\/g, "/");
const base = (p) => norm(p).split("/").pop();
const dir = (p) => norm(p).slice(0, -(base(p).length + 1));
const lower = (p) => p.toLowerCase();
const isOts = (p) => lower(p).endsWith(".ots");
const isOriginal = (p) => !isOts(p) && !lower(p).endsWith(".ots.bak") && !lower(p).endsWith(".ots.tmp");
const ext = (p) => { const b = base(p), i = b.lastIndexOf("."); return i > 0 ? b.slice(i + 1).toUpperCase() : "—"; };

async function pool(items, n, fn) {
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => {
    while (i < items.length) await fn(items[i++]);
  }));
}

const ICON_FOLDER = `<svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><path d="M10 4H4a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-8l-2-2z"/></svg>`;
const revealBtn = (path, kind) => path
  ? `<button class="reveal" data-reveal="${esc(path)}" title="${esc(t(kind === "ots" ? "reveal.ots" : "reveal.original"))}">${kind === "ots" ? `<img src="assets/ots.png" alt="OTS">` : ICON_FOLDER}</button>`
  : `<span class="reveal-placeholder"></span>`;
const badge = (tone, text, title = "") => `<span class="badge ${tone}" title="${esc(title)}">${esc(text)}</span>`;

// ---------- state ----------
const state = {
  create: new Map(), // path -> {path, status, ots, error}
  upgrade: new Map(), // path -> {path, status, error}
  verify: new Map(), // original path -> {path, ots, complete, digest, check, detail, busy}
  unassigned: new Set(), // .ots paths loaded in Verify with no original
};
let activeTab = "create";
const busy = { create: false, upgrade: false, verify: false };

// ---------- rendering ----------
let renderQueued = false;
function render() {
  if (renderQueued) return;
  renderQueued = true;
  requestAnimationFrame(() => { renderQueued = false; renderCreate(); renderUpgrade(); renderVerify(); });
}

function panel(name) { return $(`#panel-${name}`); }

function setRows(name, html, count) {
  const p = panel(name);
  p.classList.toggle("empty", count === 0);
  $("tbody", p).innerHTML = html;
  $(".summary", p).textContent = count ? t("summary", { n: count }) : "";
  p.querySelectorAll("[data-act=clear], .primary").forEach((b) => (b.disabled = busy[name]));
}

function setProgress(name, done, total) {
  const p = panel(name), bar = $("progress", p);
  bar.hidden = !total || done >= total;
  bar.max = total; bar.value = done;
  $(".progress-text", p).textContent = total && done < total ? t("progress", { done, total }) : "";
}

const CREATE_TONE = { checking: "muted", ready: "info", already: "ok", mismatch: "warn", stamping: "muted", created: "ok", error: "bad" };
function renderCreate() {
  const rows = [...state.create.values()];
  setRows("create", rows.map((r) => `<tr>
    <td class="c-icons">${revealBtn(r.path, "orig")}${revealBtn(r.ots, "ots")}</td>
    <td class="name" title="${esc(r.path)}">${esc(base(r.path))}</td>
    <td class="folder" title="${esc(dir(r.path))}">${esc(dir(r.path))}</td>
    <td>${badge(CREATE_TONE[r.status], t("st." + r.status), r.error)}</td></tr>`).join(""), rows.length);
}

const UPGRADE_TONE = { checking: "muted", pending: "info", upgrading: "muted", upgraded: "ok", complete: "ok", notyet: "warn", error: "bad" };
function renderUpgrade() {
  const rows = [...state.upgrade.values()];
  setRows("upgrade", rows.map((r) => `<tr>
    <td class="c-icons">${revealBtn(r.path, "ots")}</td>
    <td class="name" title="${esc(r.path)}">${esc(base(r.path))}</td>
    <td class="folder" title="${esc(dir(r.path))}">${esc(dir(r.path))}</td>
    <td>${badge(UPGRADE_TONE[r.status], t("st." + r.status), r.error)}</td></tr>`).join(""), rows.length);
}

const CHECK_TONE = { valid: "ok", pending: "warn", invalid: "bad", error: "bad", verifying: "muted" };
function renderVerify() {
  const rows = [...state.verify.values()];
  setRows("verify", rows.map((r) => {
    const detected = r.ots
      ? `<span title="${esc(r.ots)}">${esc(t("ots.yes"))}</span>`
      : `${esc(t("ots.notFound"))} <button class="plus" data-assign="${esc(r.path)}" title="${esc(t("assign.add"))}">+</button>`;
    const otsStatus = r.ots && r.complete !== undefined ? badge(r.complete ? "ok" : "warn", t(r.complete ? "ots.complete" : "ots.partial")) : "—";
    const title = r.check === "valid" && r.height !== undefined
      ? t("check.validAt", { height: r.height, date: new Date(r.time * 1000).toLocaleString(LANG) })
      : r.detail;
    const check = r.check ? badge(CHECK_TONE[r.check], t("check." + r.check), title) : "—";
    return `<tr>
      <td class="c-icons">${revealBtn(r.path, "orig")}${revealBtn(r.ots, "ots")}</td>
      <td class="name" title="${esc(r.path)}">${esc(base(r.path))}</td>
      <td>${esc(ext(r.path))}</td>
      <td class="nowrap">${detected}</td>
      <td>${otsStatus}</td>
      <td class="hash" title="${esc(r.digest)}">${esc(r.digest || "…")}</td>
      <td>${check}</td></tr>`;
  }).join(""), rows.length);
  const n = state.unassigned.size;
  $(".unassigned", panel("verify")).textContent = n ? t("unassigned.count", { n }) : "";
}

// ---------- Create ----------
async function addCreate(paths) {
  const files = (await invoke("expand_paths", { paths }))
    .filter((p) => isOriginal(p) && !norm(p).includes("/OTS-Files/") && !state.create.has(p));
  files.forEach((p) => state.create.set(p, { path: p, status: "checking" }));
  render();
  await pool(files, 4, async (p) => {
    const r = state.create.get(p);
    if (!r) return;
    try {
      const info = await invoke("inspect_original", { path: p });
      r.ots = info.matches ? info.existing : undefined;
      r.status = info.existing ? (info.matches ? "already" : "mismatch") : "ready";
      if (info.existing && !info.matches) r.error = info.existing;
    } catch (e) { r.status = "error"; r.error = String(e); }
    render();
  });
}

async function runCreate() {
  const todo = [...state.create.values()].filter((r) => r.status === "ready" || r.status === "mismatch");
  if (!todo.length || busy.create) return;
  busy.create = true;
  const BATCH = 200; // one calendar round-trip per batch
  for (let i = 0; i < todo.length; i += BATCH) {
    const chunk = todo.slice(i, i + BATCH);
    chunk.forEach((r) => (r.status = "stamping"));
    setProgress("create", i, todo.length); render();
    try {
      const res = await invoke("stamp_files", { paths: chunk.map((r) => r.path), sameDir: settings.sameDir, calendars: settings.calendars });
      res.forEach((x, j) => Object.assign(chunk[j], x.error ? { status: "error", error: x.error } : { status: "created", ots: x.otsPath, error: undefined }));
    } catch (e) { chunk.forEach((r) => Object.assign(r, { status: "error", error: String(e) })); }
  }
  busy.create = false;
  setProgress("create", 0, 0); render();
}

// ---------- Upgrade ----------
async function addUpgrade(paths) {
  const files = (await invoke("expand_paths", { paths })).filter((p) => isOts(p) && !state.upgrade.has(p));
  files.forEach((p) => state.upgrade.set(p, { path: p, status: "checking" }));
  render();
  await pool(files, 8, async (p) => {
    const r = state.upgrade.get(p);
    if (!r) return;
    try { r.status = (await invoke("ots_complete", { path: p })) ? "complete" : "pending"; }
    catch (e) { r.status = "error"; r.error = String(e); }
    render();
  });
}

async function runUpgrade() {
  const todo = [...state.upgrade.values()].filter((r) => ["pending", "notyet", "error"].includes(r.status));
  if (!todo.length || busy.upgrade) return;
  busy.upgrade = true;
  let done = 0;
  setProgress("upgrade", 0, todo.length); render();
  await pool(todo, 4, async (r) => {
    r.status = "upgrading"; r.error = undefined; render();
    try {
      const s = await invoke("upgrade_file", { path: r.path, backupOriginal: settings.backup, calendars: settings.calendars });
      r.status = s === "pending" ? "notyet" : s;
    } catch (e) { r.status = "error"; r.error = String(e); }
    setProgress("upgrade", ++done, todo.length); render();
  });
  busy.upgrade = false;
  render();
}

// ---------- Verify ----------
function assign(row, ots) {
  state.unassigned.delete(ots);
  Object.assign(row, { ots, check: undefined, complete: undefined, detail: undefined });
}

// Prefer an .ots with the same name in the same folder or its OTS-Files subfolder, then any same-name .ots.
function matchLoaded(orig) {
  const name = lower(base(orig)) + ".ots", d = dir(orig);
  const cands = [...state.unassigned].filter((o) => lower(base(o)) === name);
  return cands.find((o) => dir(o) === d || dir(o) === d + "/OTS-Files") || cands[0];
}

async function addVerify(paths) {
  const files = await invoke("expand_paths", { paths });
  for (const p of files) {
    if (isOts(p)) { if (![...state.verify.values()].some((r) => r.ots === p)) state.unassigned.add(p); }
    else if (isOriginal(p) && !state.verify.has(p)) state.verify.set(p, { path: p });
  }
  for (const r of state.verify.values()) if (!r.ots) { const m = matchLoaded(r.path); if (m) assign(r, m); }
  // Loaded .ots whose original was not dropped: look for the original on disk.
  for (const o of [...state.unassigned]) {
    const orig = await invoke("find_original", { ots: o });
    if (!orig) continue;
    if (!state.verify.has(orig)) state.verify.set(orig, { path: orig });
    const r = state.verify.get(orig);
    if (!r.ots) assign(r, o);
  }
  // Originals still without proof: look for the .ots on disk at the standard locations.
  for (const r of state.verify.values()) {
    if (r.ots || r.diskChecked) continue;
    r.diskChecked = true;
    const f = await invoke("find_ots", { path: r.path });
    if (f) assign(r, f);
  }
  render();
  verifyPending();
}

async function verifyPending() {
  const todo = [...state.verify.values()].filter((r) => !r.busy && (r.ots ? !r.check : !r.digest));
  if (!todo.length) return;
  let done = 0;
  busy.verify = true;
  setProgress("verify", 0, todo.length);
  await pool(todo, 4, async (r) => {
    r.busy = true;
    try {
      if (r.ots) {
        r.check = "verifying"; render();
        const res = await invoke("verify", { original: r.path, ots: r.ots, explorers: settings.explorers });
        Object.assign(r, { digest: res.digest, complete: res.complete, check: res.status, detail: res.detail, height: res.height ?? undefined, time: res.time ?? undefined });
      } else {
        r.digest = await invoke("hash_sha256", { path: r.path });
      }
    } catch (e) { Object.assign(r, { check: "error", detail: String(e) }); }
    r.busy = false;
    setProgress("verify", ++done, todo.length); render();
  });
  busy.verify = false;
  render();
  verifyPending(); // rows assigned while this run was in progress
}

// ---------- Assign dialog ----------
let assignRow = null;
const assignDialog = $("#assign-dialog");

function openAssign(path) {
  assignRow = state.verify.get(path);
  if (!assignRow) return;
  $("#assign-title").textContent = t("assign.title", { name: base(path) });
  const list = [...state.unassigned];
  $("#assign-list").innerHTML = list.map((o) => `<li><button data-pick="${esc(o)}"><img src="assets/ots.png" alt=""> <span>${esc(base(o))}</span> <small>${esc(dir(o))}</small></button></li>`).join("");
  $("#assign-none").hidden = list.length > 0;
  assignDialog.showModal();
}

function pickOts(ots) {
  if (!assignRow || !ots) return;
  assign(assignRow, ots);
  assignDialog.close();
  render();
  verifyPending();
}

// ---------- Settings dialog ----------
const settingsDialog = $("#settings-dialog");
function fillSettings(s) {
  $("#set-lang").innerHTML = Object.entries(LANGUAGES).map(([k, v]) => `<option value="${k}" ${k === s.lang ? "selected" : ""}>${esc(v)}</option>`).join("");
  $("#set-calendars").value = s.calendars.join("\n");
  $("#set-explorers").value = s.explorers.join("\n");
}
const lines = (v) => v.split(/\s+/).map((x) => x.trim()).filter((x) => /^https:\/\//.test(x));

// ---------- file pickers / drop routing ----------
const ADDERS = { create: addCreate, upgrade: addUpgrade, verify: addVerify };

async function pick(directory) {
  const filters = activeTab === "upgrade" && !directory ? [{ name: t("dialog.ots"), extensions: ["ots"] }] : undefined;
  const sel = await open({ multiple: true, directory, filters });
  if (sel) ADDERS[activeTab](Array.isArray(sel) ? sel : [sel]);
}

function handleDrop(paths) {
  if (assignDialog.open) {
    const ots = paths.filter(isOts);
    ots.slice(1).forEach((o) => state.unassigned.add(o));
    pickOts(ots[0]);
  } else if (!settingsDialog.open) {
    ADDERS[activeTab](paths);
  }
}

// ---------- wiring ----------
function switchTab(name) {
  activeTab = name;
  document.querySelectorAll("[data-tab]").forEach((b) => { b.classList.toggle("active", b.dataset.tab === name); b.setAttribute("aria-selected", b.dataset.tab === name); });
  document.querySelectorAll(".panel").forEach((p) => p.classList.toggle("active", p.id === `panel-${name}`));
}

document.addEventListener("click", (e) => {
  const el = e.target.closest("button");
  if (!el) return;
  if (el.dataset.tab) return switchTab(el.dataset.tab);
  if (el.dataset.reveal) return revealItemInDir(el.dataset.reveal).catch(console.error);
  if (el.dataset.assign) return openAssign(el.dataset.assign);
  if (el.dataset.pick) return pickOts(el.dataset.pick);
  switch (el.dataset.act) {
    case "add-files": return pick(false);
    case "add-folder": return pick(true);
    case "clear":
      if (busy[activeTab]) return;
      state[activeTab].clear();
      if (activeTab === "verify") state.unassigned.clear();
      return render();
  }
});

$("#run-create").onclick = runCreate;
$("#run-upgrade").onclick = runUpgrade;

const sameDir = $("#opt-same-dir"), backup = $("#opt-backup");
sameDir.checked = settings.sameDir;
backup.checked = settings.backup;
sameDir.onchange = () => { settings.sameDir = sameDir.checked; saveSettings(); };
backup.onchange = () => { settings.backup = backup.checked; saveSettings(); };

$("#assign-close").onclick = () => assignDialog.close();
$("#assign-load").onclick = async () => {
  const sel = await open({ multiple: false, filters: [{ name: t("dialog.ots"), extensions: ["ots"] }] });
  if (sel) pickOts(sel);
};

$("#open-settings").onclick = () => { fillSettings(settings); settingsDialog.showModal(); };
$("#settings-close").onclick = () => settingsDialog.close();
$("#settings-reset").onclick = () => fillSettings({ ...DEFAULTS, lang: settings.lang });
$("#settings-save").onclick = () => {
  const calendars = lines($("#set-calendars").value), explorers = lines($("#set-explorers").value);
  settings.lang = $("#set-lang").value;
  settings.calendars = calendars.length ? calendars : DEFAULTS.calendars;
  settings.explorers = explorers.length ? explorers : DEFAULTS.explorers;
  saveSettings();
  LANG = settings.lang;
  applyI18n(); render();
  settingsDialog.close();
};

getCurrentWebview().onDragDropEvent(({ payload }) => {
  document.body.classList.toggle("dragging", payload.type === "enter" || payload.type === "over");
  if (payload.type === "drop") handleDrop(payload.paths);
});

applyI18n();
render();
