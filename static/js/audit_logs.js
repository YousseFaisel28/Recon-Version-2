/**
 * Audit Logs — Admin Dashboard
 *
 * Fetches, displays, and filters audit log entries.
 * Computes a browser fingerprint hash and sends it as a header
 * on every API request so the backend can store it.
 */

const BASE_URL = "http://localhost:5000";

// ====================================================
// BROWSER FINGERPRINT
// ====================================================
function computeBrowserFingerprint() {
  const components = [
    navigator.userAgent,
    navigator.language,
    screen.width + "x" + screen.height,
    screen.colorDepth,
    new Date().getTimezoneOffset(),
    navigator.hardwareConcurrency || "unknown",
    navigator.platform || "unknown",
  ];

  // Simple hash (djb2)
  const raw = components.join("|");
  let hash = 5381;
  for (let i = 0; i < raw.length; i++) {
    hash = (hash * 33) ^ raw.charCodeAt(i);
  }
  return "fp_" + (hash >>> 0).toString(16);
}

const BROWSER_FP = computeBrowserFingerprint();

// ====================================================
// STATE
// ====================================================
let currentPage = 1;
const perPage = 50;

// ====================================================
// FETCH AUDIT LOGS
// ====================================================
async function fetchAuditLogs(page = 1) {
  currentPage = page;

  const params = new URLSearchParams();
  params.set("page", page);
  params.set("per_page", perPage);

  const user = document.getElementById("filterUser").value.trim();
  const domain = document.getElementById("filterDomain").value.trim();
  const action = document.getElementById("filterAction").value;
  const ip = document.getElementById("filterIP").value.trim();
  const dateFrom = document.getElementById("filterDateFrom").value;
  const dateTo = document.getElementById("filterDateTo").value;

  if (user) params.set("user", user);
  if (domain) params.set("domain", domain);
  if (action) params.set("action", action);
  if (ip) params.set("ip", ip);
  if (dateFrom) params.set("date_from", dateFrom);
  if (dateTo) params.set("date_to", dateTo);

  try {
    const response = await fetch(`${BASE_URL}/admin/get_audit_logs?${params}`, {
      headers: { "X-Browser-Fingerprint": BROWSER_FP },
    });
    if (!response.ok) throw new Error("Failed to fetch audit logs");
    const data = await response.json();

    renderTable(data.logs, data.page, data.per_page);
    renderPagination(data.total_pages, data.page);
  } catch (err) {
    console.error("Error loading audit logs:", err);
    document.getElementById("auditLogsTableBody").innerHTML =
      '<tr><td colspan="8" style="text-align:center;color:#ff4444;">Failed to load audit logs.</td></tr>';
  }
}

// ====================================================
// RENDER TABLE
// ====================================================
function renderTable(logs, page, perPage) {
  const tbody = document.getElementById("auditLogsTableBody");
  tbody.innerHTML = "";

  if (!logs || logs.length === 0) {
    tbody.innerHTML =
      '<tr><td colspan="8" style="text-align:center;color:#888;">No audit logs found.</td></tr>';
    return;
  }

  logs.forEach((log, index) => {
    const row = document.createElement("tr");
    const rowNum = (page - 1) * perPage + index + 1;

    // Truncate long user-agent
    const uaShort =
      log.user_agent && log.user_agent.length > 40
        ? log.user_agent.substring(0, 40) + "…"
        : log.user_agent || "—";

    // Action badge color
    const actionColor = getActionColor(log.action);

    row.innerHTML = `
      <td>${rowNum}</td>
      <td>
        <div style="font-weight:600;">${log.username || "Unknown"}</div>
        <div style="font-size:0.8rem;color:#aaa;">${log.email || ""}</div>
      </td>
      <td><span class="audit-action-badge" style="background:${actionColor};">${formatAction(log.action)}</span></td>
      <td>${log.domain || "—"}</td>
      <td style="font-family:monospace;font-size:0.85rem;">${log.ip_address || "—"}</td>
      <td title="${log.user_agent || ""}" style="font-size:0.8rem;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${uaShort}</td>
      <td style="font-size:0.85rem;">${log.timestamp || "—"}</td>
      <td>
        <button class="audit-verify-btn" onclick="verifyLog('${log._id}', this)" title="Verify HMAC integrity">
          🔒
        </button>
      </td>
    `;
    tbody.appendChild(row);
  });
}

// ====================================================
// ACTION FORMATTING
// ====================================================
function formatAction(action) {
  if (!action) return "unknown";
  return action
    .replace(/_/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

function getActionColor(action) {
  const colors = {
    login_success: "rgba(34,197,94,0.25)",
    login_failed: "rgba(239,68,68,0.25)",
    logout: "rgba(156,163,175,0.25)",
    scan_started: "rgba(59,130,246,0.25)",
    scan_completed: "rgba(16,185,129,0.25)",
    report_downloaded: "rgba(139,92,246,0.25)",
    admin_user_added: "rgba(245,158,11,0.25)",
    admin_user_deleted: "rgba(239,68,68,0.3)",
    admin_user_approved: "rgba(34,197,94,0.3)",
    admin_user_declined: "rgba(239,68,68,0.2)",
    admin_domains_updated: "rgba(59,130,246,0.2)",
    user_signup: "rgba(99,102,241,0.25)",
    password_changed: "rgba(245,158,11,0.2)",
    username_changed: "rgba(245,158,11,0.2)",
    domain_added: "rgba(16,185,129,0.2)",
  };
  return colors[action] || "rgba(255,255,255,0.08)";
}

// ====================================================
// PAGINATION
// ====================================================
function renderPagination(totalPages, currentPage) {
  const container = document.getElementById("auditPagination");
  container.innerHTML = "";

  if (totalPages <= 1) return;

  // Previous button
  if (currentPage > 1) {
    const prev = document.createElement("button");
    prev.className = "audit-page-btn";
    prev.textContent = "← Prev";
    prev.onclick = () => fetchAuditLogs(currentPage - 1);
    container.appendChild(prev);
  }

  // Page numbers
  const maxVisible = 5;
  let startPage = Math.max(1, currentPage - Math.floor(maxVisible / 2));
  let endPage = Math.min(totalPages, startPage + maxVisible - 1);
  if (endPage - startPage < maxVisible - 1) {
    startPage = Math.max(1, endPage - maxVisible + 1);
  }

  for (let i = startPage; i <= endPage; i++) {
    const btn = document.createElement("button");
    btn.className = "audit-page-btn" + (i === currentPage ? " active" : "");
    btn.textContent = i;
    btn.onclick = () => fetchAuditLogs(i);
    container.appendChild(btn);
  }

  // Next button
  if (currentPage < totalPages) {
    const next = document.createElement("button");
    next.className = "audit-page-btn";
    next.textContent = "Next →";
    next.onclick = () => fetchAuditLogs(currentPage + 1);
    container.appendChild(next);
  }
}

// ====================================================
// VERIFY HMAC INTEGRITY
// ====================================================
async function verifyLog(logId, btnEl) {
  btnEl.textContent = "⏳";
  btnEl.disabled = true;

  try {
    const response = await fetch(`${BASE_URL}/admin/verify_audit_log/${logId}`);
    if (!response.ok) throw new Error("Verification request failed");
    const data = await response.json();

    if (data.integrity_valid) {
      btnEl.textContent = "✅";
      btnEl.title = "Integrity VERIFIED — No tampering detected";
      btnEl.style.color = "#22c55e";
    } else {
      btnEl.textContent = "⚠️";
      btnEl.title = "TAMPERED — Integrity check FAILED";
      btnEl.style.color = "#ef4444";
    }
  } catch (err) {
    btnEl.textContent = "❌";
    btnEl.title = "Verification error";
    console.error("Verify error:", err);
  }

  btnEl.disabled = false;
}

// ====================================================
// LOAD ACTION TYPES FOR DROPDOWN
// ====================================================
async function loadActionTypes() {
  try {
    const response = await fetch(`${BASE_URL}/admin/get_audit_actions`);
    if (!response.ok) return;
    const data = await response.json();

    const select = document.getElementById("filterAction");
    (data.actions || []).forEach((action) => {
      const opt = document.createElement("option");
      opt.value = action;
      opt.textContent = formatAction(action);
      select.appendChild(opt);
    });
  } catch (err) {
    console.error("Failed to load action types:", err);
  }
}

// ====================================================
// EVENT LISTENERS
// ====================================================
document.addEventListener("DOMContentLoaded", () => {
  loadActionTypes();
  fetchAuditLogs(1);

  document.getElementById("btnApplyFilters").addEventListener("click", () => {
    fetchAuditLogs(1);
  });

  document.getElementById("btnClearFilters").addEventListener("click", () => {
    document.getElementById("filterUser").value = "";
    document.getElementById("filterDomain").value = "";
    document.getElementById("filterAction").value = "";
    document.getElementById("filterIP").value = "";
    document.getElementById("filterDateFrom").value = "";
    document.getElementById("filterDateTo").value = "";
    fetchAuditLogs(1);
  });

  // Allow Enter key to trigger search
  document.querySelectorAll(".audit-input").forEach((input) => {
    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter") fetchAuditLogs(1);
    });
  });
});
