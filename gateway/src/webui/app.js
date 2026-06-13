// hackamore policy studio — a dependency-light single-page app served from the admin
// listener. Talks to GET /catalogs, POST /policy/lint, POST /policy/test, POST /mint.
// State is one array of rules; every edit re-renders the JSON, re-lints, and the
// explorer/composer stay in sync.
"use strict";

const $ = (sel) => document.querySelector(sel);
const el = (tag, attrs = {}, kids = []) => {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") n.className = v;
    else if (k === "text") n.textContent = v;
    else n.setAttribute(k, v);
  }
  for (const kid of [].concat(kids)) n.append(kid);
  return n;
};

// --- state -----------------------------------------------------------------
let CATALOGS = []; // [{flavor, operations:[...]}]
let SERVICES = []; // [{name, flavor}]
let RULES = []; // [{effect, matches:{targets,verbs,resources,conditions}}]
let lintTimer = null;

const verbLabel = (v) =>
  v.type === "Crud" ? v.value.kind : v.value.id;
const crudVerb = (kind) => ({ type: "Crud", value: { kind } });

function policyDoc() {
  return { rules: RULES };
}

// --- explorer --------------------------------------------------------------
function renderExplorer() {
  const root = $("#catalogs");
  root.replaceChildren();
  for (const cat of CATALOGS) {
    const box = el("div", { class: "flavor" });
    box.append(el("div", { class: "fname", text: `flavor: ${cat.flavor}` }));
    if (!cat.operations.length) {
      box.append(el("div", { class: "muted", text: "(raw: no catalog — use path globs)" }));
      root.append(box);
      continue;
    }
    const table = el("table");
    table.append(el("tr", {}, [
      el("th", { text: "" }),
      el("th", { text: "operation" }),
      el("th", { text: "verb" }),
      el("th", { text: "route" }),
      el("th", { text: "fields" }),
    ]));
    for (const op of cat.operations) {
      const add = el("button", { class: "add-op", title: "add an allow rule for this operation", text: "+ allow" });
      add.onclick = () => addRuleForOp(cat.flavor, op);
      table.append(el("tr", {}, [
        el("td", {}, add),
        el("td", { text: op.id }),
        el("td", { class: `verb-${verbLabel(op.verb)}`, text: verbLabel(op.verb) }),
        el("td", { text: `${op.route.method} ${op.route.pathTemplate}` }),
        el("td", { class: "fields", text: op.fields.map((f) => f.name).join(", ") }),
      ]));
    }
    box.append(table);
    root.append(box);
  }
}

// Turn a catalog route template into a concrete-ish resource glob: {x} -> *,
// trailing {x+} -> ** so the rule matches the whole subtree.
function routeToGlob(template) {
  return template
    .split("/")
    .map((seg) => (seg.endsWith("+}") ? "**" : seg.startsWith("{") ? "*" : seg))
    .join("/");
}

function addRuleForOp(flavor, op) {
  const target = (SERVICES.find((s) => s.flavor === flavor) || {}).name;
  RULES.push({
    effect: "Allow",
    matches: {
      targets: target ? [target] : [],
      verbs: [op.verb],
      resources: [routeToGlob(op.route.pathTemplate)],
      conditions: [],
    },
  });
  syncFromRules();
}

// --- composer --------------------------------------------------------------
function renderRules() {
  const root = $("#rules");
  root.replaceChildren();
  RULES.forEach((rule, i) => root.append(ruleCard(rule, i)));
}

function ruleCard(rule, i) {
  const card = el("div", { class: "rule" });

  const effect = el("select", { class: `effect-${rule.effect}` });
  for (const e of ["Allow", "Deny"]) {
    const o = el("option", { text: e });
    if (e === rule.effect) o.setAttribute("selected", "");
    effect.append(o);
  }
  effect.onchange = () => { rule.effect = effect.value; syncFromRules(); };
  const del = el("button", { class: "del", title: "delete rule", text: "✕" });
  del.onclick = () => { RULES.splice(i, 1); syncFromRules(); };
  card.append(el("div", { class: "row" }, [
    el("b", { text: `rule ${i}` }), effect, del,
  ]));

  card.append(listEditor("targets", rule.matches.targets, "service name (blank = any)"));
  card.append(verbEditor(rule));
  card.append(listEditor("resources", rule.matches.resources, "path glob, e.g. repos/*/*/pulls"));
  card.append(conditionEditor(rule));
  return card;
}

// A comma-tolerant editor for a string list (targets, resources).
function listEditor(field, arr, placeholder) {
  const input = el("input", { placeholder, size: "46", value: arr.join(", ") });
  input.onchange = () => {
    const owner = RULES.find((r) => r.matches[field] === arr);
    const next = input.value.split(",").map((s) => s.trim()).filter(Boolean);
    if (owner) owner.matches[field] = next;
    syncFromRules();
  };
  return el("div", { class: "row" }, [el("label", { text: field }), input]);
}

function verbEditor(rule) {
  const row = el("div", { class: "row" });
  row.append(el("label", { text: "verbs" }));
  for (const kind of ["Read", "Create", "Update", "Delete"]) {
    const on = rule.matches.verbs.some((v) => v.type === "Crud" && v.value.kind === kind);
    const b = el("button", { class: on ? `verb-${kind}` : "muted", text: on ? `✓ ${kind}` : kind });
    b.onclick = () => {
      const idx = rule.matches.verbs.findIndex((v) => v.type === "Crud" && v.value.kind === kind);
      if (idx >= 0) rule.matches.verbs.splice(idx, 1);
      else rule.matches.verbs.push(crudVerb(kind));
      syncFromRules();
    };
    row.append(b);
  }
  row.append(el("span", { class: "muted", text: "(none = any)" }));
  return row;
}

// Conditions are a tagged union on the wire: {type, value:{field, ...}}. Equals carries
// {field, value}, OneOf {field, values}, Exists {field}. The editor keeps that nested
// shape so what mints is exactly what the composer shows.
function conditionEditor(rule) {
  const wrap = el("div");
  rule.matches.conditions.forEach((c, ci) => {
    c.value = c.value || {};
    const field = el("input", { value: c.value.field || "", placeholder: "field", size: "12" });
    field.onchange = () => { c.value.field = field.value; syncFromRules(); };
    const type = el("select");
    for (const t of ["Equals", "OneOf", "Exists"]) {
      const o = el("option", { text: t });
      if (t === c.type) o.setAttribute("selected", "");
      type.append(o);
    }
    type.onchange = () => {
      c.type = type.value;
      // Reshape the inner value struct for the new variant, preserving the field name.
      const f = c.value.field || "";
      if (c.type === "Equals") c.value = { field: f, value: "" };
      else if (c.type === "OneOf") c.value = { field: f, values: [] };
      else c.value = { field: f };
      syncFromRules();
    };
    const row = el("div", { class: "cond" }, [el("label", { text: "when" }), field, type]);
    if (c.type !== "Exists") {
      const val = el("input", {
        value: c.type === "OneOf" ? (c.value.values || []).join(", ") : jsonInline(c.value.value),
        placeholder: c.type === "OneOf" ? "v1, v2" : "value",
        size: "16",
      });
      val.onchange = () => {
        if (c.type === "OneOf") c.value.values = val.value.split(",").map((s) => parseVal(s.trim()));
        else c.value.value = parseVal(val.value.trim());
        syncFromRules();
      };
      row.append(val);
    }
    const del = el("button", { class: "del", text: "✕" });
    del.onclick = () => { rule.matches.conditions.splice(ci, 1); syncFromRules(); };
    row.append(del);
    wrap.append(row);
  });
  const add = el("button", { text: "+ condition" });
  add.onclick = () => {
    rule.matches.conditions.push({ type: "Equals", value: { field: "", value: "" } });
    syncFromRules();
  };
  wrap.append(el("div", { class: "row" }, [add]));
  return wrap;
}

const jsonInline = (v) => (typeof v === "string" ? v : JSON.stringify(v));
const parseVal = (s) => { try { return JSON.parse(s); } catch { return s; } };

// --- sync / lint -----------------------------------------------------------
function syncFromRules() {
  renderRules();
  $("#policy-json").value = JSON.stringify(policyDoc(), null, 2);
  scheduleLint();
}

function scheduleLint() {
  clearTimeout(lintTimer);
  lintTimer = setTimeout(lint, 250);
}

async function lint() {
  const status = $("#lint-status");
  let findings;
  try {
    const r = await fetch("/policy/lint", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify(policyDoc()),
    });
    findings = await r.json();
  } catch (e) {
    status.textContent = "lint unreachable"; status.className = "pill err"; return;
  }
  const box = $("#findings");
  box.replaceChildren();
  const errors = findings.filter((f) => f.severity === "Error").length;
  if (!findings.length) {
    status.textContent = "clean"; status.className = "pill ok";
    box.append(el("div", { class: "muted", text: "no findings" }));
  } else {
    status.textContent = `${errors} error(s), ${findings.length - errors} warning(s)`;
    status.className = errors ? "pill err" : "pill warn";
    for (const f of findings) {
      const sev = f.severity.toLowerCase();
      box.append(el("div", { class: sev, text: `${sev} rule ${f.ruleIndex}: ${f.message}` }));
    }
  }
}

// --- dry-run + mint --------------------------------------------------------
async function runTest() {
  const out = $("#test-result");
  let fields = {};
  const raw = $("#test-fields").value.trim();
  if (raw) {
    try { fields = JSON.parse(raw); }
    catch { out.textContent = "fields must be a JSON object"; return; }
  }
  const body = {
    policy: policyDoc(),
    target: $("#test-target").value,
    method: $("#test-method").value,
    path: $("#test-path").value || "/",
    query: "",
    fields,
  };
  const r = await fetch("/policy/test", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) { out.textContent = (await r.json()).error || `HTTP ${r.status}`; return; }
  const res = await r.json();
  const allow = res.verdict.type === "Allow";
  const where = res.matched.type === "Rule" ? `rule ${res.matched.value.index}` : "no rule matched";
  const reason = allow ? "Allow" : `Deny ${res.verdict.value.reason}`;
  out.replaceChildren(
    el("span", { class: allow ? "allow" : "deny", text: `${reason} (${where})` }),
    document.createTextNode("\n\n" + JSON.stringify(res.action, null, 2)),
  );
}

async function mint() {
  const out = $("#mint-result");
  const r = await fetch("/mint", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ policy: policyDoc(), ttlSeconds: Number($("#mint-ttl").value) }),
  });
  const body = await r.json();
  if (!r.ok) {
    out.replaceChildren(el("span", { class: "deny", text: body.error || `HTTP ${r.status}` }));
    if (body.findings) for (const f of body.findings)
      out.append(document.createTextNode(`\n${f.severity} rule ${f.ruleIndex}: ${f.message}`));
    return;
  }
  out.replaceChildren(el("span", { class: "allow", text: `token: ${body.token}` }),
    document.createTextNode(`\nexpires_at_ms: ${body.expiresAtMs}`));
}

// --- boot ------------------------------------------------------------------
async function boot() {
  const r = await fetch("/catalogs");
  const data = await r.json();
  CATALOGS = data.catalogs;
  SERVICES = data.services;
  renderExplorer();

  const sel = $("#test-target");
  for (const s of SERVICES) sel.append(el("option", { text: s.name }));

  $("#add-rule").onclick = () => {
    RULES.push({ effect: "Allow", matches: { targets: [], verbs: [], resources: [], conditions: [] } });
    syncFromRules();
  };
  $("#apply-json").onclick = () => {
    try { RULES = JSON.parse($("#policy-json").value).rules || []; syncFromRules(); }
    catch { $("#lint-status").textContent = "invalid JSON"; $("#lint-status").className = "pill err"; }
  };
  $("#copy-json").onclick = () => navigator.clipboard?.writeText($("#policy-json").value);
  $("#run-test").onclick = runTest;
  $("#mint").onclick = mint;

  // Seed with a starter rule so the studio isn't empty.
  RULES = [{ effect: "Allow", matches: { targets: [], verbs: [crudVerb("Read")], resources: [], conditions: [] } }];
  syncFromRules();
}

boot();
