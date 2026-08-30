/* web/static/app.js
   AutoPatch Sentinel — Tactical Web Command Center
   Vanilla JS: polling, DOM updates, diff renderer
*/

"use strict";

// ── Constants ─────────────────────────────────────────────────────────────────

const POLL_INTERVAL_MS = 1000;

const STAGE_LABELS = [
  { label: "SAST\nScan",     short: "0" },
  { label: "ASan\nBuild",    short: "1" },
  { label: "Fuzzing",        short: "2" },
  { label: "Triage",         short: "3" },
  { label: "LLM\nPatch",     short: "4" },
  { label: "Rebuild",        short: "5" },
  { label: "Verify",         short: "6" },
  { label: "Report",         short: "7" },
];

const GATE_NAMES = [
  "Stage 1: Crash Invalidation",
  "Stage 2: Regression Suite",
  "Stage 3: Re-Fuzzing Burst",
];

// ── State ─────────────────────────────────────────────────────────────────────

let pollTimer = null;
let lastStatus = null;

// ── DOM helpers ───────────────────────────────────────────────────────────────

function el(id) { return document.getElementById(id); }

function setText(id, txt) {
  const e = el(id);
  if (e) e.textContent = txt ?? "";
}

function setHTML(id, html) {
  const e = el(id);
  if (e) e.innerHTML = html ?? "";
}

function show(id)   { const e = el(id); if (e) e.style.display = ""; }
function hide(id)   { const e = el(id); if (e) e.style.display = "none"; }
function setClass(id, cls) { const e = el(id); if (e) e.className = cls; }

// ── Initialise stage bar ──────────────────────────────────────────────────────

function initStages() {
  const container = el("stages");
  if (!container) return;
  container.innerHTML = STAGE_LABELS.map((s, i) =>
    `<div class="stage-item idle" id="stage-${i}">
       <div class="stage-dot">${s.short}</div>
       <div class="stage-label">${s.label.replace("\n", "<br>")}</div>
     </div>`
  ).join("");
}

function updateStages(stageIndex, running, finished, success) {
  STAGE_LABELS.forEach((_, i) => {
    const el2 = el(`stage-${i}`);
    if (!el2) return;
    if (i < stageIndex) {
      el2.className = "stage-item done";
      el2.querySelector(".stage-dot").textContent = "✓";
    } else if (i === stageIndex && running) {
      el2.className = "stage-item active";
      el2.querySelector(".stage-dot").textContent = STAGE_LABELS[i].short;
    } else if (finished && !success && i === stageIndex) {
      el2.className = "stage-item failed";
    } else {
      el2.className = "stage-item idle";
      el2.querySelector(".stage-dot").textContent = STAGE_LABELS[i].short;
    }
  });
}

// ── Status pill ────────────────────────────────────────────────────────────────

function updateStatusPill(state) {
  const pill = el("status-pill");
  if (!pill) return;
  if (state.running) {
    pill.className = "status-pill running";
    pill.querySelector(".pill-text").textContent = state.stage || "Running";
  } else if (state.finished && state.success) {
    pill.className = "status-pill success";
    pill.querySelector(".pill-text").textContent = "Fix Verified ✓";
  } else if (state.finished && !state.success) {
    pill.className = "status-pill failed";
    pill.querySelector(".pill-text").textContent = "Not Verified";
  } else {
    pill.className = "status-pill";
    pill.querySelector(".pill-text").textContent = "Idle";
  }
}

// ── SAST card ─────────────────────────────────────────────────────────────────

function updateSast(state) {
  const card = el("sast-card");
  const body = el("sast-body");
  if (!card || !body) return;

  const sast = state.sast_report;
  if (!sast || !sast.findings || sast.findings.length === 0) {
    if (state.stage_index < 1) {
      body.innerHTML = `<div class="empty-state"><div class="empty-icon">🔍</div>Awaiting Stage 0 SAST scan…</div>`;
    } else {
      body.innerHTML = `<div class="empty-state"><div class="empty-icon">✅</div>
        No static findings.<br><span class="text-muted">Install cppcheck for full coverage.</span></div>`;
      card.className = "card green-card";
    }
    return;
  }

  card.className = "card alert-card";
  const errCount  = sast.errors   || 0;
  const warnCount = sast.warnings || 0;

  let html = `<div class="section-gap">
    <span class="card-badge badge-critical">${errCount} error${errCount!==1?"s":""}</span>
    <span class="card-badge badge-warn" style="margin-left:6px">${warnCount} warning${warnCount!==1?"s":""}</span>
    <span class="text-muted" style="font-size:11px;margin-left:8px">via ${sast.tools_run?.join(", ")||"??"}</span>
  </div>`;

  sast.findings.slice(0, 8).forEach(f => {
    const cwe = f.cwe ? `<span class="mono" style="color:var(--amber);font-size:10px">[${f.cwe}]</span> ` : "";
    const sevCls = f.severity === "error" ? "sev-error" : f.severity === "warning" ? "sev-warning" : "sev-style";
    html += `<div class="sast-finding">
      <span class="sev ${sevCls}">${f.severity}</span>
      <div>
        <div class="msg">${cwe}${escHtml(f.message)}</div>
        <div class="loc">📄 ${f.file ? baseName(f.file) : "??"} : ${f.line ?? "?"}</div>
      </div>
    </div>`;
  });

  if (sast.findings.length > 8) {
    html += `<div class="text-muted" style="font-size:11px;text-align:center;margin-top:8px">+${sast.findings.length-8} more findings</div>`;
  }

  body.innerHTML = html;
}

// ── Crash card ────────────────────────────────────────────────────────────────

function updateCrash(state) {
  const card = el("crash-card");
  const body = el("crash-body");
  if (!card || !body) return;

  if (!state.crash_found) {
    card.className = "card";
    body.innerHTML = `<div class="empty-state"><div class="empty-icon">💥</div>Awaiting crash discovery…</div>`;
    return;
  }

  card.className = "card alert-card";

  const summary = state.crash_summary || "Unknown crash";
  const asnLog  = state.asan_log || "";

  // Extract key info from summary (format: [SEV] TYPE (ACCESS NB) in FN @ FILE:LINE)
  const typeMatch = summary.match(/\]\s+([^\s(]+)/);
  const sevMatch  = summary.match(/\[([A-Z]+)\]/);
  const locMatch  = summary.match(/@\s+(.+)$/);

  const cType = typeMatch ? typeMatch[1] : "heap-buffer-overflow";
  const sev   = sevMatch  ? sevMatch[1]  : "CRITICAL";
  const loc   = locMatch  ? locMatch[1]  : "unknown";

  const sevCls = sev === "CRITICAL" ? "critical" : sev === "HIGH" ? "high" : "";

  body.innerHTML = `
    <div class="crash-meta">
      <div class="meta-item">
        <div class="meta-label">Error Type</div>
        <div class="meta-value mono ${sevCls}">${escHtml(cType)}</div>
      </div>
      <div class="meta-item">
        <div class="meta-label">Severity</div>
        <div class="meta-value ${sevCls}">${sev}</div>
      </div>
      <div class="meta-item" style="grid-column:1/-1">
        <div class="meta-label">Location</div>
        <div class="meta-value mono">${escHtml(loc)}</div>
      </div>
    </div>
    ${asnLog ? `<div class="asan-log">${escHtml(asnLog.slice(0, 2000))}</div>` : ""}
  `;
}

// ── Diff card ─────────────────────────────────────────────────────────────────

function updatePatch(state) {
  const card  = el("patch-card");
  const diff  = el("patch-diff");
  const expl  = el("patch-explain");
  if (!card || !diff) return;

  if (!state.patch_diff) {
    card.className = "card";
    diff.innerHTML = `<div class="empty-state"><div class="empty-icon">🔧</div>Awaiting LLM patch…</div>`;
    if (expl) expl.textContent = "";
    return;
  }

  card.className = "card active-card";
  if (expl && state.patch_explain) {
    expl.textContent = state.patch_explain.slice(0, 300);
  }

  // Render diff with syntax highlighting
  const lines = state.patch_diff.split("\n");
  diff.innerHTML = lines.map(line => {
    if (line.startsWith("+") && !line.startsWith("+++")) {
      return `<span class="diff-line-add">${escHtml(line)}</span>`;
    } else if (line.startsWith("-") && !line.startsWith("---")) {
      return `<span class="diff-line-del">${escHtml(line)}</span>`;
    } else if (line.startsWith("@@")) {
      return `<span class="diff-line-hdr">${escHtml(line)}</span>`;
    } else {
      return `<span class="diff-line-ctx">${escHtml(line)}</span>`;
    }
  }).join("");
}

// ── Verification gates ────────────────────────────────────────────────────────

function updateVerification(state) {
  const container = el("gates-container");
  if (!container) return;

  const verif = state.verification;

  // Determine gate states
  const isVerifStage = state.stage_index >= 6;

  container.innerHTML = GATE_NAMES.map((name, i) => {
    let cls = "";
    let icon = "◯";
    let detail = "Waiting…";

    if (verif && verif[name] !== undefined) {
      const gateData = verif[name];
      if (gateData.passed) {
        cls = "gate pass"; icon = "✓"; detail = gateData.details || "Passed";
      } else {
        cls = "gate fail"; icon = "✗"; detail = gateData.details || "Failed";
      }
    } else if (isVerifStage && state.running) {
      // Active gate animation for the one currently running
      cls = "gate running"; icon = "↻"; detail = "Running…";
    } else {
      cls = "gate";
    }

    return `<div class="${cls}">
      <div class="gate-indicator">${icon}</div>
      <div class="gate-info">
        <div class="gate-name">${escHtml(name)}</div>
        <div class="gate-detail">${escHtml(detail)}</div>
      </div>
    </div>`;
  }).join("");
}

// ── Terminal log ──────────────────────────────────────────────────────────────

function updateLog(state) {
  const body = el("terminal-body");
  if (!body || !state.log_lines) return;
  const lines = state.log_lines.slice(-60);
  body.innerHTML = lines.map(line => {
    let cls = "log-line";
    if (line.includes("Step") || line.includes("[0/") || line.includes("[1/") ||
        line.includes("[2/") || line.includes("[3/") || line.includes("[4/") ||
        line.includes("[5/") || line.includes("[6/") || line.includes("[7/")) cls += " stage";
    else if (line.includes("[OK]") || line.includes("✓") || line.includes("PASS")) cls += " ok";
    else if (line.includes("[FAIL]") || line.includes("✗") || line.includes("FAIL")) cls += " fail";
    return `<span class="${cls}">${escHtml(line)}</span>`;
  }).join("\n");
  body.scrollTop = body.scrollHeight;
}

// ── Main update ───────────────────────────────────────────────────────────────

function applyState(state) {
  lastStatus = state;

  updateStatusPill(state);
  updateStages(state.stage_index || 0, state.running, state.finished, state.success);
  updateSast(state);
  updateCrash(state);
  updatePatch(state);
  updateVerification(state);
  updateLog(state);

  // Button states
  const btnRun   = el("btn-run");
  const btnReset = el("btn-reset");
  if (btnRun)   btnRun.disabled   = state.running;
  if (btnReset) btnReset.disabled = state.running;

  // Final state banner
  const banner = el("result-banner");
  if (banner) {
    if (state.finished && state.success) {
      banner.style.display = "";
      banner.className = "correlation-banner";
      banner.innerHTML = "🎉 <strong>Fix Verified!</strong> All 3 verification gates passed. Pipeline complete.";
    } else if (state.finished && !state.success) {
      banner.style.display = "";
      banner.className = "correlation-banner";
      banner.style.borderColor = "var(--red-dim)";
      banner.style.color = "var(--red)";
      banner.innerHTML = "❌ <strong>Fix not verified.</strong> Manual review required. Check the verification gates above.";
    } else {
      banner.style.display = "none";
    }
  }
}

// ── Polling ───────────────────────────────────────────────────────────────────

async function poll() {
  try {
    const res = await fetch("/api/status");
    if (!res.ok) return;
    const state = await res.json();
    applyState(state);
    // Stop polling once pipeline finishes
    if (state.finished && pollTimer) {
      // Poll one more second after finish to capture final state
      setTimeout(() => { clearInterval(pollTimer); pollTimer = null; }, 1500);
    }
  } catch(e) {
    // Network error — keep polling silently
  }
}

function startPolling() {
  if (!pollTimer) {
    pollTimer = setInterval(poll, POLL_INTERVAL_MS);
    poll(); // immediate first fetch
  }
}

function stopPolling() {
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
}

// ── Run pipeline ──────────────────────────────────────────────────────────────

async function runPipeline() {
  const target   = el("sel-target")?.value   || "telemetry_parser";
  const provider = el("sel-provider")?.value || "ollama";
  const mode     = el("sel-mode")?.value     || "seed_replay";
  const retries  = parseInt(el("inp-retries")?.value || "3");
  const noSast   = el("chk-nosast")?.checked || false;

  try {
    const res = await fetch("/api/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, provider, mode, max_retries: retries, no_sast: noSast }),
    });
    if (!res.ok) {
      const err = await res.json();
      alert("Could not start: " + (err.detail || res.statusText));
      return;
    }
    startPolling();
  } catch(e) {
    alert("Failed to connect to the server: " + e.message);
  }
}

// ── Reset ─────────────────────────────────────────────────────────────────────

async function resetPipeline() {
  stopPolling();
  try {
    await fetch("/api/reset", { method: "POST" });
  } catch(e) {}
  // Reload a clean initial state
  applyState({
    running: false, finished: false, success: false,
    stage: "idle", stage_index: 0, log_lines: [],
    sast_report: null, crash_found: false, asan_log: "",
    patch_diff: "", verification: null,
  });
}

// ── Reports list ──────────────────────────────────────────────────────────────

async function loadReports() {
  const container = el("reports-list");
  if (!container) return;
  try {
    const res = await fetch("/api/reports");
    const data = await res.json();
    if (!data.reports || data.reports.length === 0) {
      container.innerHTML = `<div class="text-muted" style="font-size:12px;padding:8px">No reports yet.</div>`;
      return;
    }
    container.innerHTML = data.reports.map(r =>
      `<div style="display:flex;align-items:center;justify-content:space-between;padding:6px 10px;
            border-bottom:1px solid var(--border);font-size:12px;">
        <span class="mono text-cyan">${escHtml(r.name)}</span>
        <div style="display:flex;gap:6px">
          <a href="/api/reports/${encodeURIComponent(r.md)}" target="_blank"
             style="color:var(--text-muted);font-size:11px;">MD</a>
          ${r.json ? `<a href="/api/reports/${encodeURIComponent(r.json)}" target="_blank"
             style="color:var(--text-muted);font-size:11px;">JSON</a>` : ""}
        </div>
      </div>`
    ).join("");
  } catch(e) {}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function escHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function baseName(path) {
  return path.split(/[/\\]/).pop() || path;
}

// ── Bootstrap ─────────────────────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", () => {
  initStages();

  // Wire buttons
  const btnRun   = el("btn-run");
  const btnReset = el("btn-reset");
  if (btnRun)   btnRun.addEventListener("click", runPipeline);
  if (btnReset) btnReset.addEventListener("click", resetPipeline);

  // Load initial state
  poll();

  // Start polling to check if a run is already in progress
  startPolling();

  // Load reports sidebar
  loadReports();
  setInterval(loadReports, 10000); // refresh every 10s
});
