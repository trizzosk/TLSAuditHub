const ui = {
  menuItems: document.querySelectorAll(".menu-item"),
  viewTitle: document.getElementById("viewTitle"),
  loginForm: document.getElementById("loginForm"),
  authUsername: document.getElementById("authUsername"),
  authPassword: document.getElementById("authPassword"),
  loginBtn: document.getElementById("loginBtn"),
  logoutBtn: document.getElementById("logoutBtn"),
  authState: document.getElementById("authState"),
  metricHostsTotal: document.getElementById("metricHostsTotal"),
  metricHostsEnabled: document.getElementById("metricHostsEnabled"),
  metricScansTotal: document.getElementById("metricScansTotal"),
  metricScansRunning: document.getElementById("metricScansRunning"),
  metricResultsTotal: document.getElementById("metricResultsTotal"),
  metricDiffsTotal: document.getElementById("metricDiffsTotal"),
  targetForm: document.getElementById("targetForm"),
  hostname: document.getElementById("hostname"),
  port: document.getElementById("port"),
  refreshTargetsBtn: document.getElementById("refreshTargetsBtn"),
  targetsBody: document.getElementById("targetsBody"),
  dnsPanel: document.getElementById("dnsPanel"),
  targetsPageSize: document.getElementById("targetsPageSize"),
  targetsPrevBtn: document.getElementById("targetsPrevBtn"),
  targetsNextBtn: document.getElementById("targetsNextBtn"),
  targetsPageInfo: document.getElementById("targetsPageInfo"),
  refreshSpoofableBtn: document.getElementById("refreshSpoofableBtn"),
  spoofableBody: document.getElementById("spoofableBody"),
  spoofablePageSize: document.getElementById("spoofablePageSize"),
  spoofablePrevBtn: document.getElementById("spoofablePrevBtn"),
  spoofableNextBtn: document.getElementById("spoofableNextBtn"),
  spoofablePageInfo: document.getElementById("spoofablePageInfo"),
  refreshJobsBtn: document.getElementById("refreshJobsBtn"),
  purgeJobsBtn: document.getElementById("purgeJobsBtn"),
  jobsBody: document.getElementById("jobsBody"),
  jobsPageSize: document.getElementById("jobsPageSize"),
  jobsPrevBtn: document.getElementById("jobsPrevBtn"),
  jobsNextBtn: document.getElementById("jobsNextBtn"),
  jobsPageInfo: document.getElementById("jobsPageInfo"),
  selectedResultScanId: document.getElementById("selectedResultScanId"),
  jobResultsPanel: document.getElementById("jobResultsPanel"),
  proxyForm: document.getElementById("proxyForm"),
  proxyEnabled: document.getElementById("proxyEnabled"),
  proxyHost: document.getElementById("proxyHost"),
  proxyPort: document.getElementById("proxyPort"),
  proxyUsername: document.getElementById("proxyUsername"),
  proxyPassword: document.getElementById("proxyPassword"),
  proxyNoProxyPatterns: document.getElementById("proxyNoProxyPatterns"),
  reloadProxyBtn: document.getElementById("reloadProxyBtn"),
  logPanel: document.getElementById("logPanel"),
};

let accessToken = "";
let currentUsername = "";
const jobIndex = new Map();
const SESSION_TOKEN_KEY = "tlsaudithub_access_token";
const SESSION_USER_KEY = "tlsaudithub_username";

const pagination = {
  targets: { page: 1, pageSize: 15, total: 0 },
  jobs: { page: 1, pageSize: 15, total: 0 },
  spoofable: { page: 1, pageSize: 15, total: 0 },
};

function baseUrl() {
  return "http://localhost:8000";
}

function log(message) {
  const now = new Date().toLocaleTimeString();
  ui.logPanel.textContent += `\n[${now}] ${message}`;
  ui.logPanel.scrollTop = ui.logPanel.scrollHeight;
}

function setAuthState(authenticated, label = "") {
  if (authenticated) {
    ui.authState.textContent = label || "Authenticated";
    ui.authState.style.color = "#88dc8f";
  } else {
    ui.authState.textContent = label || "Not authenticated";
    ui.authState.style.color = "";
  }
}

function setAuthenticatedUI(authenticated) {
  document.body.classList.toggle("unauth", !authenticated);
  ui.logoutBtn.classList.toggle("hidden", !authenticated);
  ui.authState.classList.toggle("hidden", !authenticated);
  ui.menuItems.forEach((item) => {
    item.disabled = !authenticated;
  });
}

function persistSession(token, username) {
  try {
    if (token) {
      localStorage.setItem(SESSION_TOKEN_KEY, token);
      localStorage.setItem(SESSION_USER_KEY, username || "");
    } else {
      localStorage.removeItem(SESSION_TOKEN_KEY);
      localStorage.removeItem(SESSION_USER_KEY);
    }
  } catch (_err) {
    // Ignore storage errors (private mode, disabled storage, etc.)
  }
}

function loadPersistedSession() {
  try {
    const token = localStorage.getItem(SESSION_TOKEN_KEY) || "";
    const username = localStorage.getItem(SESSION_USER_KEY) || "";
    return { token, username };
  } catch (_err) {
    return { token: "", username: "" };
  }
}

function setToken(token, username = "") {
  accessToken = token || "";
  currentUsername = accessToken ? username : "";
  persistSession(accessToken, currentUsername);
  setAuthState(
    Boolean(accessToken),
    accessToken ? `Welcome, ${currentUsername}` : "Not authenticated"
  );
  setAuthenticatedUI(Boolean(accessToken));
  activateView(accessToken ? "dashboardView" : "authView");
}

async function apiRequest(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (!headers.has("Content-Type") && options.body) {
    headers.set("Content-Type", "application/json");
  }
  if (accessToken) {
    headers.set("Authorization", `Bearer ${accessToken}`);
  }

  const response = await fetch(`${baseUrl()}${path}`, {
    ...options,
    headers,
  });

  if (!response.ok) {
    const body = await response.text();
    if (response.status === 401) {
      setToken("");
      setAuthState(false, "Session expired");
    }
    throw new Error(`${response.status} ${response.statusText}: ${body}`);
  }

  const text = await response.text();
  return text ? JSON.parse(text) : {};
}

async function login(event) {
  event.preventDefault();
  const username = ui.authUsername.value.trim();
  const password = ui.authPassword.value;
  const formData = new URLSearchParams();
  formData.set("username", username);
  formData.set("password", password);

  try {
    const data = await apiRequest("/auth/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: formData,
    });
    setToken(data.access_token, username);
    ui.authPassword.value = "";
    log(`Login successful for ${username}.`);
    await refreshAll();
  } catch (error) {
    setToken("");
    log(`Login failed: ${error.message}`);
  }
}

function logout() {
  setToken("");
  log("Logged out.");
}

function activateView(viewId) {
  const viewNames = {
    authView: "Login",
    dashboardView: "Dashboard",
    targetsView: "Hosts / Targets",
    spoofableView: "Spoofable",
    jobsView: "Jobs",
    resultsView: "Results",
    adminView: "Admin",
  };

  if (!accessToken && viewId !== "authView") {
    viewId = "authView";
  }

  document.querySelectorAll(".view").forEach((view) => {
    view.classList.toggle("active", view.id === viewId);
  });

  ui.menuItems.forEach((item) => {
    item.classList.toggle("active", item.dataset.view === viewId);
  });

  ui.viewTitle.textContent = viewNames[viewId] || "Dashboard";
}

function fmtDate(value) {
  if (!value) {
    return "-";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return String(value);
  }
  return date.toLocaleString();
}

function setMetric(node, value) {
  node.textContent = String(value ?? 0);
}

function clamp(value, min, max) {
  return Math.min(Math.max(value, min), max);
}

function getPageSize(node, fallback = 15) {
  const value = Number(node?.value);
  if (!Number.isFinite(value)) {
    return fallback;
  }
  return value;
}

function updatePaginationUI(section, controls) {
  const state = pagination[section];
  const pageSize = state.pageSize;
  const total = state.total || 0;
  const totalPages =
    pageSize > 0 ? Math.max(1, Math.ceil(total / pageSize)) : 1;
  state.page = clamp(state.page, 1, totalPages);

  controls.pageInfo.textContent = `Page ${state.page} of ${totalPages}`;
  const disabled = pageSize === 0 || totalPages <= 1;
  controls.prevBtn.disabled = disabled || state.page <= 1;
  controls.nextBtn.disabled = disabled || state.page >= totalPages;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function fmtBool(value) {
  return value ? "Yes" : "No";
}

function sevBadge(value, severity) {
  const sev = severity || "warn";
  return `<span class="sev-badge sev-${sev}">${escapeHtml(String(value))}</span>`;
}

function asDate(value) {
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? null : d;
}

function classifyCertNotBefore(value) {
  const d = asDate(value);
  if (!d) {
    return "warn";
  }
  return d > new Date() ? "bad" : "good";
}

function classifyCertNotAfter(value) {
  const d = asDate(value);
  if (!d) {
    return "warn";
  }
  const now = Date.now();
  const diffDays = Math.floor((d.getTime() - now) / 86400000);
  if (diffDays < 0) {
    return "bad";
  }
  if (diffDays < 30) {
    return "warn";
  }
  return "good";
}

function classifyRobotResult(value) {
  const v = String(value || "").toUpperCase();
  if (!v) {
    return "warn";
  }
  if (v.includes("NOT_VULNERABLE")) {
    return "good";
  }
  if (v.includes("VULNERABLE")) {
    return "bad";
  }
  return "warn";
}

function classifyCipherSuite(name) {
  const v = String(name || "").toUpperCase();
  if (!v) {
    return "warn";
  }
  if (
    v.includes("CHACHA20") ||
    v.includes("AES_128_GCM") ||
    v.includes("AES_256_GCM")
  ) {
    return "good";
  }
  if (
    v.includes("RC4") ||
    v.includes("3DES") ||
    v.includes("_DES_") ||
    v.includes("NULL") ||
    v.includes("EXPORT")
  ) {
    return "bad";
  }
  return "warn";
}

function normalizeResult(result) {
  let value = result;
  for (let i = 0; i < 4; i += 1) {
    if (typeof value !== "string") {
      break;
    }
    const trimmed = value.trim();
    if (!trimmed) {
      return {};
    }
    try {
      value = JSON.parse(trimmed);
    } catch (_err) {
      return { raw: value };
    }
  }
  return value ?? {};
}

function normalizePluginName(plugin) {
  const raw = String(plugin || "").trim();
  if (!raw) {
    return "unknown_plugin";
  }
  const normalized = raw.toLowerCase();
  if (normalized.startsWith("scancommand.")) {
    return normalized.slice("scancommand.".length);
  }
  return normalized;
}

const PROTOCOL_PLUGINS = [
  "ssl_2_0_cipher_suites",
  "ssl_3_0_cipher_suites",
  "tls_1_0_cipher_suites",
  "tls_1_1_cipher_suites",
  "tls_1_2_cipher_suites",
  "tls_1_3_cipher_suites",
];

const PROTOCOL_LABELS = {
  ssl_2_0_cipher_suites: "SSL 2.0",
  ssl_3_0_cipher_suites: "SSL 3.0",
  tls_1_0_cipher_suites: "TLS 1.0",
  tls_1_1_cipher_suites: "TLS 1.1",
  tls_1_2_cipher_suites: "TLS 1.2",
  tls_1_3_cipher_suites: "TLS 1.3",
};

function protocolSeverity(plugin, supported) {
  if (supported === null || supported === undefined) {
    return "warn";
  }
  if (plugin.startsWith("ssl_")) {
    return supported ? "bad" : "good";
  }
  if (plugin === "tls_1_3_cipher_suites") {
    return supported ? "good" : "bad";
  }
  return supported ? "warn" : "good";
}

function renderProtocolSupport(results) {
  const support = {};
  PROTOCOL_PLUGINS.forEach((plugin) => {
    support[plugin] = false;
  });

  results.forEach((row) => {
    const plugin = normalizePluginName(row.plugin);
    if (!PROTOCOL_PLUGINS.includes(plugin)) {
      return;
    }
    const result = normalizeResult(row.result);
    support[plugin] = Boolean(result?.is_protocol_supported);
  });

  const rows = PROTOCOL_PLUGINS.map((plugin) => {
    const supported = support[plugin];
    const label = PROTOCOL_LABELS[plugin] || plugin;
    const value = fmtBool(Boolean(supported));
    return {
      label,
      value,
      severity: protocolSeverity(plugin, supported),
    };
  });

  return `
    <article class="result-card">
      <h4>Protocol Support</h4>
      ${renderSecurityCheck({}, rows)}
    </article>
  `;
}

function renderCertificateInfo(result) {
  const cert = result?.certificate_chain?.[0];
  if (!cert) {
    return "<p class='muted'>No certificate chain data.</p>";
  }
  const sans = Array.isArray(cert.subject_alternative_name)
    ? cert.subject_alternative_name
    : [];
  return `
    <dl class="result-grid">
      <dt>Subject</dt><dd class="tiny-mono">${sevBadge(cert.subject || "-", "warn")}</dd>
      <dt>Issuer</dt><dd class="tiny-mono">${sevBadge(cert.issuer || "-", "warn")}</dd>
      <dt>Valid From</dt><dd>${sevBadge(fmtDate(cert.not_before), classifyCertNotBefore(cert.not_before))}</dd>
      <dt>Valid Until</dt><dd>${sevBadge(fmtDate(cert.not_after), classifyCertNotAfter(cert.not_after))}</dd>
      <dt>SAN</dt><dd>${sevBadge(sans.length ? `${sans.length} names` : "None", sans.length > 0 ? "good" : "bad")}</dd>
    </dl>
    ${
      sans.length
        ? `<ul class="result-list">${sans
            .map((name) => `<li class="tiny-mono result-item-good">${escapeHtml(name)}</li>`)
            .join("")}</ul>`
        : ""
    }
  `;
}

function renderCipherSuites(result, plugin) {
  const accepted = Array.isArray(result?.accepted_cipher_suites)
    ? result.accepted_cipher_suites
    : [];
  return `
    <dl class="result-grid">
      <dt>Plugin</dt><dd>${sevBadge(plugin, "warn")}</dd>
      <dt>Protocol Supported</dt><dd>${sevBadge(fmtBool(result?.is_protocol_supported), result?.is_protocol_supported ? "good" : "bad")}</dd>
      <dt>Accepted Suites</dt><dd>${sevBadge(accepted.length, accepted.length > 0 ? "good" : "bad")}</dd>
    </dl>
    ${
      accepted.length
        ? `<ul class="result-list">${accepted
            .map((suite) => `<li class="tiny-mono result-item-${classifyCipherSuite(suite)}">${escapeHtml(suite)}</li>`)
            .join("")}</ul>`
        : "<p class='muted'>No accepted cipher suites.</p>"
    }
  `;
}

function renderHttpHeaders(result) {
  const hsts = result?.strict_transport_security;
  const hstsPresent = Boolean(hsts);
  const maxAge = hsts?.max_age;
  const maxAgeSev =
    typeof maxAge !== "number" ? "bad" : maxAge >= 15552000 ? "good" : "warn";
  return `
    <dl class="result-grid">
      <dt>Redirect Path</dt><dd class="tiny-mono">${sevBadge(result?.http_path_redirected_to || "-", "warn")}</dd>
      <dt>HSTS Present</dt><dd>${sevBadge(fmtBool(hstsPresent), hstsPresent ? "good" : "bad")}</dd>
      <dt>HSTS max-age</dt><dd>${sevBadge(hsts ? `${hsts.max_age ?? "-"} seconds` : "-", maxAgeSev)}</dd>
      <dt>HSTS includeSubDomains</dt><dd>${sevBadge(hsts ? fmtBool(Boolean(hsts.include_subdomains)) : "-", hsts ? (hsts.include_subdomains ? "good" : "warn") : "bad")}</dd>
      <dt>HSTS preload</dt><dd>${sevBadge(hsts ? fmtBool(Boolean(hsts.preload)) : "-", hsts ? (hsts.preload ? "good" : "warn") : "bad")}</dd>
    </dl>
  `;
}

function renderSecurityCheck(result, rows) {
  return `
    <dl class="result-grid">
      ${rows
        .map(
          (row) =>
            `<dt>${escapeHtml(row.label)}</dt><dd>${sevBadge(String(row.value), row.severity || "warn")}</dd>`
        )
        .join("")}
    </dl>
  `;
}

function renderGenericResult(result) {
  const json = escapeHtml(JSON.stringify(result, null, 2));
  return `<pre>${json}</pre>`;
}

function renderJobResults(results) {
  if (!Array.isArray(results) || results.length === 0) {
    ui.jobResultsPanel.classList.add("muted");
    ui.jobResultsPanel.innerHTML = "No results for this job yet.";
    return;
  }

  ui.jobResultsPanel.classList.remove("muted");
  const protocolCard = renderProtocolSupport(results);

  ui.jobResultsPanel.innerHTML = [
    protocolCard,
    ...results.map((row) => {
      const plugin = normalizePluginName(row.plugin);
      const result = normalizeResult(row.result);

      let body = "";
      if (plugin === "certificate_info") {
        body = renderCertificateInfo(result);
      } else if (plugin.endsWith("_cipher_suites")) {
        body = renderCipherSuites(result, plugin);
      } else if (plugin === "http_headers") {
        body = renderHttpHeaders(result);
      } else if (plugin === "heartbleed") {
        body = renderSecurityCheck(result, [
          {
            label: "Vulnerable To Heartbleed",
            value: fmtBool(Boolean(result?.is_vulnerable_to_heartbleed)),
            severity: result?.is_vulnerable_to_heartbleed ? "bad" : "good",
          },
        ]);
      } else if (plugin === "robot") {
        body = renderSecurityCheck(result, [
          {
            label: "ROBOT Result",
            value: result?.robot_result || "-",
            severity: classifyRobotResult(result?.robot_result),
          },
        ]);
      } else if (plugin === "session_renegotiation") {
        body = renderSecurityCheck(result, [
          {
            label: "Supports Secure Renegotiation",
            value: fmtBool(Boolean(result?.supports_secure_renegotiation)),
            severity: result?.supports_secure_renegotiation ? "good" : "bad",
          },
          {
            label: "Client Renegotiation DoS Vulnerable",
            value: fmtBool(
              Boolean(result?.is_vulnerable_to_client_renegotiation_dos)
            ),
            severity: result?.is_vulnerable_to_client_renegotiation_dos
              ? "bad"
              : "good",
          },
          {
            label: "Successful Client Renegotiations",
            value: result?.client_renegotiations_success_count ?? 0,
            severity:
              (result?.client_renegotiations_success_count ?? 0) > 0
                ? "warn"
                : "good",
          },
        ]);
      } else if (plugin === "tls_compression") {
        body = renderSecurityCheck(result, [
          {
            label: "Supports TLS Compression",
            value: fmtBool(Boolean(result?.supports_compression)),
            severity: result?.supports_compression ? "bad" : "good",
          },
        ]);
      } else if (plugin === "tls_fallback_scsv") {
        body = renderSecurityCheck(result, [
          {
            label: "Supports TLS_FALLBACK_SCSV",
            value: fmtBool(Boolean(result?.supports_fallback_scsv)),
            severity: result?.supports_fallback_scsv ? "good" : "warn",
          },
        ]);
      } else {
        body = renderGenericResult(result);
      }

      return `
        <article class="result-card">
          <h4>${escapeHtml(plugin)}</h4>
          ${body}
        </article>
      `;
    }),
  ].join("");
}

async function loadDashboard() {
  try {
    const data = await apiRequest("/dashboard/summary", { method: "GET" });
    setMetric(ui.metricHostsTotal, data.targets_total);
    setMetric(ui.metricHostsEnabled, data.targets_enabled);
    setMetric(ui.metricScansTotal, data.scans_total);
    setMetric(ui.metricScansRunning, data.scans_running);
    setMetric(ui.metricResultsTotal, data.results_total);
    setMetric(ui.metricDiffsTotal, data.diffs_total);
    log("Dashboard summary loaded.");
  } catch (error) {
    log(`Dashboard load failed: ${error.message}`);
  }
}

function renderTargets(targets) {
  if (!Array.isArray(targets) || targets.length === 0) {
    ui.targetsBody.innerHTML =
      "<tr><td colspan='5' class='muted'>No targets found</td></tr>";
    return;
  }

  ui.targetsBody.innerHTML = targets
    .map(
      (target) => `
      <tr>
        <td>${target.hostname ?? ""}</td>
        <td>${target.port ?? ""}</td>
        <td>${target.enabled ? "Yes" : "No"}</td>
        <td>${target.scan_interval_minutes ?? "-"}</td>
        <td>
          <div class="target-actions">
            <button data-target-id="${target.id}" class="run-scan-btn">Run Scan</button>
            <button data-target-id="${target.id}" data-hostname="${target.hostname ?? ""}" class="dns-data-btn">DNS Data</button>
            <button data-target-id="${target.id}" class="delete-target-btn">Delete</button>
          </div>
        </td>
      </tr>
    `
    )
    .join("");
}

function renderDnsList(items, emptyLabel) {
  if (!Array.isArray(items) || items.length === 0) {
    return `<p class='muted'>${emptyLabel}</p>`;
  }
  return `<ul class="result-list">${items
    .map((item) => `<li class="tiny-mono">${escapeHtml(String(item))}</li>`)
    .join("")}</ul>`;
}

function renderDnsData(targetLabel, payload) {
  if (!payload || payload.status === "pending") {
    return `<p class='muted'>DNS data is still being collected for ${escapeHtml(
      targetLabel || "this target"
    )}.</p>`;
  }

  if (payload.status !== "ok") {
    return `<p class='muted'>DNS data unavailable.</p>`;
  }

  const data = payload.data || {};
  const whois = data.whois || {};
  const dmarc = data.dmarc || {};
  const spfPresent = Boolean(data.spf);
  const dmarcPresent = Boolean(dmarc.record);

  return `
    <article class="result-card">
      <h4>Overview</h4>
      <dl class="result-grid">
        <dt>Hostname</dt><dd class="tiny-mono">${sevBadge(data.hostname || targetLabel || "-", "warn")}</dd>
        <dt>Updated</dt><dd>${sevBadge(fmtDate(payload.updated_at), payload.updated_at ? "good" : "warn")}</dd>
        <dt>SPF Record</dt><dd>${sevBadge(spfPresent ? "Yes" : "No", spfPresent ? "good" : "warn")}</dd>
        <dt>DMARC Record</dt><dd>${sevBadge(dmarcPresent ? "Yes" : "No", dmarcPresent ? "good" : "warn")}</dd>
        <dt>DMARC Policy</dt><dd>${sevBadge(dmarc.policy || "-", dmarc.policy ? "good" : "warn")}</dd>
      </dl>
    </article>
    <article class="result-card">
      <h4>NS Records</h4>
      ${renderDnsList(data.ns, "No NS records found.")}
    </article>
    <article class="result-card">
      <h4>MX Records</h4>
      ${renderDnsList(
        (Array.isArray(data.mx) ? data.mx : []).map(
          (mx) =>
            `${mx.exchange ?? "-"} (pref ${mx.preference ?? "-"})`
        ),
        "No MX records found."
      )}
    </article>
    <article class="result-card">
      <h4>SPF Record</h4>
      ${spfPresent ? `<pre>${escapeHtml(data.spf)}</pre>` : "<p class='muted'>No SPF record found.</p>"}
    </article>
    <article class="result-card">
      <h4>DMARC Record</h4>
      <dl class="result-grid">
        <dt>Lookup Domain</dt><dd class="tiny-mono">${sevBadge(dmarc.domain || "-", "warn")}</dd>
        <dt>Policy</dt><dd>${sevBadge(dmarc.policy || "-", dmarc.policy ? "good" : "warn")}</dd>
      </dl>
      ${dmarcPresent ? `<pre>${escapeHtml(dmarc.record)}</pre>` : "<p class='muted'>No DMARC record found.</p>"}
    </article>
    <article class="result-card">
      <h4>WHOIS</h4>
      ${
        whois.error
          ? `<p class='muted'>WHOIS lookup failed: ${escapeHtml(whois.error)}</p>`
          : `
        <dl class="result-grid">
          <dt>Registrar</dt><dd>${sevBadge(whois.registrar || "-", whois.registrar ? "good" : "warn")}</dd>
          <dt>Domain Name</dt><dd class="tiny-mono">${sevBadge(
            Array.isArray(whois.domain_name) ? whois.domain_name.join(", ") : whois.domain_name || "-",
            "warn"
          )}</dd>
          <dt>Created</dt><dd>${sevBadge(
            Array.isArray(whois.creation_date) ? whois.creation_date.join(", ") : whois.creation_date || "-",
            "warn"
          )}</dd>
          <dt>Updated</dt><dd>${sevBadge(
            Array.isArray(whois.updated_date) ? whois.updated_date.join(", ") : whois.updated_date || "-",
            "warn"
          )}</dd>
          <dt>Expires</dt><dd>${sevBadge(
            Array.isArray(whois.expiration_date) ? whois.expiration_date.join(", ") : whois.expiration_date || "-",
            "warn"
          )}</dd>
          <dt>Name Servers</dt><dd class="tiny-mono">${sevBadge(
            Array.isArray(whois.name_servers) ? whois.name_servers.join(", ") : whois.name_servers || "-",
            "warn"
          )}</dd>
        </dl>
      `
      }
    </article>
  `;
}

async function loadDnsData(targetId, hostname) {
  ui.dnsPanel.classList.remove("muted");
  ui.dnsPanel.innerHTML = `<p class='muted'>Loading DNS data for ${escapeHtml(
    hostname || targetId
  )}...</p>`;
  try {
    const data = await apiRequest(`/targets/${targetId}/dns`, {
      method: "GET",
    });
    ui.dnsPanel.innerHTML = renderDnsData(hostname, data);
    log(`Loaded DNS data for target ${targetId}.`);
  } catch (error) {
    ui.dnsPanel.innerHTML = `<p class='muted'>DNS data load failed: ${escapeHtml(
      error.message
    )}</p>`;
    log(`DNS data load failed: ${error.message}`);
  }
}

function renderJobs(jobs) {
  if (!Array.isArray(jobs) || jobs.length === 0) {
    ui.jobsBody.innerHTML = "<tr><td colspan='6' class='muted'>No jobs found</td></tr>";
    return;
  }

  jobIndex.clear();
  jobs.forEach((job) => {
    if (job && job.id) {
      jobIndex.set(job.id, job);
    }
  });

  ui.jobsBody.innerHTML = jobs
    .map(
      (job) => `
      <tr>
        <td>${job.id ?? ""}</td>
        <td>${job.hostname ?? "Unknown"}:${job.port ?? "-"}</td>
        <td>${job.status ?? "-"}</td>
        <td>${fmtDate(job.started_at)}</td>
        <td>${fmtDate(job.finished_at)}</td>
        <td><button data-scan-id="${job.id}" class="view-job-btn">Results</button></td>
      </tr>
    `
    )
    .join("");
}

function evaluateSpoofable(spf, dmarcPolicy) {
  const spfValue = String(spf || "").trim().toLowerCase();
  const policy = String(dmarcPolicy || "").trim().toLowerCase();
  const spfStrict = spfValue.endsWith("-all");
  const dmarcReject = policy === "reject" || policy === "quarantine";
  const dmarcNone = policy === "" || policy === "none";

  if (!spfStrict && dmarcNone) {
    return { label: "Spoofable", severity: "bad" };
  }
  if (spfStrict && dmarcReject) {
    return { label: "Not spoofable", severity: "good" };
  }
  return { label: "Needs review", severity: "warn" };
}

function renderSpoofableList(items) {
  if (!Array.isArray(items) || items.length === 0) {
    ui.spoofableBody.innerHTML =
      "<tr><td colspan='4' class='muted'>No data available</td></tr>";
    return;
  }

  ui.spoofableBody.innerHTML = items
    .map((row) => {
      const spf = row.spf || "-";
      const dmarc = row.dmarc_policy || "-";
      const result = evaluateSpoofable(row.spf, row.dmarc_policy);
      return `
        <tr>
          <td>${escapeHtml(row.hostname || "-")}</td>
          <td class="tiny-mono">${escapeHtml(spf)}</td>
          <td>${sevBadge(dmarc, dmarc && dmarc !== "-" ? "good" : "warn")}</td>
          <td>${sevBadge(result.label, result.severity)}</td>
        </tr>
      `;
    })
    .join("");
}

async function refreshSpoofable() {
  try {
    pagination.spoofable.pageSize = getPageSize(ui.spoofablePageSize, 15);
    const limit = pagination.spoofable.pageSize;
    const offset =
      limit > 0 ? (pagination.spoofable.page - 1) * limit : 0;
    const query = new URLSearchParams({
      limit: String(limit),
      offset: String(offset),
    });
    const data = await apiRequest(`/dns/spoofable?${query.toString()}`, {
      method: "GET",
    });
    pagination.spoofable.total = data.total ?? 0;
    updatePaginationUI("spoofable", {
      prevBtn: ui.spoofablePrevBtn,
      nextBtn: ui.spoofableNextBtn,
      pageInfo: ui.spoofablePageInfo,
    });
    renderSpoofableList(data.items || []);
    log(
      `Loaded spoofable report (${Array.isArray(data.items) ? data.items.length : 0} targets).`
    );
  } catch (error) {
    ui.spoofableBody.innerHTML =
      "<tr><td colspan='4' class='muted'>Failed to load spoofable report</td></tr>";
    log(`Spoofable report load failed: ${error.message}`);
  }
}

async function refreshTargets() {
  try {
    pagination.targets.pageSize = getPageSize(ui.targetsPageSize, 15);
    const limit = pagination.targets.pageSize;
    const offset =
      limit > 0 ? (pagination.targets.page - 1) * limit : 0;
    const query = new URLSearchParams({
      limit: String(limit),
      offset: String(offset),
    });
    const data = await apiRequest(`/targets?${query.toString()}`, {
      method: "GET",
    });
    pagination.targets.total = data.total ?? 0;
    updatePaginationUI("targets", {
      prevBtn: ui.targetsPrevBtn,
      nextBtn: ui.targetsNextBtn,
      pageInfo: ui.targetsPageInfo,
    });
    renderTargets(data.items || []);
    log(
      `Loaded ${Array.isArray(data.items) ? data.items.length : 0} targets.`
    );
  } catch (error) {
    log(`Target refresh failed: ${error.message}`);
  }
}

async function removeTarget(targetId) {
  try {
    await apiRequest(`/targets/${targetId}`, { method: "DELETE" });
    log(`Target ${targetId} removed.`);
    await refreshTargets();
    await loadDashboard();
  } catch (error) {
    log(`Target delete failed: ${error.message}`);
  }
}

async function runScan(targetId) {
  try {
    const data = await apiRequest(`/targets/${targetId}/scan`, { method: "POST" });
    log(`Scan queued for target ${targetId}. Task ${data.task_id}.`);
    await Promise.all([refreshJobs(), loadDashboard()]);
    activateView("jobsView");
  } catch (error) {
    log(`Run scan failed: ${error.message}`);
  }
}

async function refreshJobs() {
  try {
    pagination.jobs.pageSize = getPageSize(ui.jobsPageSize, 15);
    const limit = pagination.jobs.pageSize;
    const offset =
      limit > 0 ? (pagination.jobs.page - 1) * limit : 0;
    const query = new URLSearchParams({
      limit: String(limit),
      offset: String(offset),
    });
    const data = await apiRequest(`/jobs?${query.toString()}`, {
      method: "GET",
    });
    pagination.jobs.total = data.total ?? 0;
    updatePaginationUI("jobs", {
      prevBtn: ui.jobsPrevBtn,
      nextBtn: ui.jobsNextBtn,
      pageInfo: ui.jobsPageInfo,
    });
    renderJobs(data.items || []);
    log(`Loaded ${Array.isArray(data.items) ? data.items.length : 0} jobs.`);
  } catch (error) {
    log(`Job refresh failed: ${error.message}`);
  }
}

async function purgeJobs() {
  try {
    await apiRequest("/jobs/purge", { method: "POST" });
    log("Jobs history purged.");
    await Promise.all([refreshJobs(), loadDashboard()]);
  } catch (error) {
    log(`Jobs purge failed: ${error.message}`);
  }
}

async function loadJobResults(scanId) {
  try {
    const data = await apiRequest(`/jobs/${scanId}/results`, { method: "GET" });
    const job = jobIndex.get(scanId);
    const hostLabel = job?.hostname
      ? `${job.hostname}${job.port ? `:${job.port}` : ""}`
      : "Unknown target";
    ui.selectedResultScanId.textContent = scanId
      ? `for ${hostLabel} (JOB ID:${scanId})`
      : "";
    renderJobResults(data);
    activateView("resultsView");
    log(`Loaded results for job ${scanId}.`);
  } catch (error) {
    log(`Load job results failed: ${error.message}`);
  }
}

async function loadProxyConfig() {
  try {
    const data = await apiRequest("/config/proxy", { method: "GET" });
    ui.proxyEnabled.checked = Boolean(data.enabled);
    ui.proxyHost.value = data.host || "";
    ui.proxyPort.value = data.port || 8080;
    ui.proxyUsername.value = data.username || "";
    ui.proxyPassword.value = "";
    ui.proxyNoProxyPatterns.value = data.no_proxy_patterns || "";
    ui.proxyPassword.placeholder = data.has_password
      ? "stored (leave empty to keep current)"
      : "optional";
    log("Proxy configuration loaded.");
  } catch (error) {
    log(`Proxy configuration load failed: ${error.message}`);
  }
}

async function saveProxyConfig(event) {
  event.preventDefault();

  const enabled = Boolean(ui.proxyEnabled.checked);
  const host = ui.proxyHost.value.trim();
  const port = Number(ui.proxyPort.value);
  const username = ui.proxyUsername.value.trim();
  const password = ui.proxyPassword.value;
  const noProxyPatterns = ui.proxyNoProxyPatterns.value.trim();

  if (enabled && !host) {
    log("Proxy save failed: host is required when proxy is enabled.");
    return;
  }
  if (enabled && (!Number.isFinite(port) || port < 1 || port > 65535)) {
    log("Proxy save failed: port must be in range 1-65535.");
    return;
  }

  try {
    const data = await apiRequest("/config/proxy", {
      method: "PUT",
      body: JSON.stringify({
        enabled,
        host,
        port: Number.isFinite(port) ? port : 8080,
        username,
        password,
        no_proxy_patterns: noProxyPatterns,
      }),
    });
    ui.proxyPassword.value = "";
    ui.proxyPassword.placeholder = data.has_password
      ? "stored (leave empty to keep current)"
      : "optional";
    log(
      `Proxy configuration saved (${data.enabled ? "enabled" : "disabled"}).`
    );
  } catch (error) {
    log(`Proxy save failed: ${error.message}`);
  }
}

async function addTarget(event) {
  event.preventDefault();
  const hostname = ui.hostname.value.trim();
  const port = Number(ui.port.value);
  const query = new URLSearchParams({ hostname, port: String(port) });

  try {
    await apiRequest(`/targets?${query.toString()}`, { method: "POST" });
    log(`Target added: ${hostname}:${port}`);
    ui.targetForm.reset();
    ui.port.value = "443";
    await refreshTargets();
    await loadDashboard();
  } catch (error) {
    log(`Add target failed: ${error.message}`);
  }
}

async function refreshAll() {
  if (!accessToken) {
    return;
  }
  await Promise.all([
    loadDashboard(),
    refreshTargets(),
    refreshSpoofable(),
    refreshJobs(),
    loadProxyConfig(),
  ]);
}

ui.targetForm.addEventListener("submit", addTarget);
ui.refreshTargetsBtn.addEventListener("click", refreshTargets);
ui.refreshSpoofableBtn.addEventListener("click", refreshSpoofable);
ui.refreshJobsBtn.addEventListener("click", refreshJobs);
ui.purgeJobsBtn.addEventListener("click", purgeJobs);
ui.loginForm.addEventListener("submit", login);
ui.logoutBtn.addEventListener("click", logout);
ui.proxyForm.addEventListener("submit", saveProxyConfig);
ui.reloadProxyBtn.addEventListener("click", loadProxyConfig);

ui.targetsPageSize.addEventListener("change", () => {
  pagination.targets.page = 1;
  refreshTargets();
});
ui.jobsPageSize.addEventListener("change", () => {
  pagination.jobs.page = 1;
  refreshJobs();
});
ui.spoofablePageSize.addEventListener("change", () => {
  pagination.spoofable.page = 1;
  refreshSpoofable();
});

ui.targetsPrevBtn.addEventListener("click", () => {
  pagination.targets.page = Math.max(1, pagination.targets.page - 1);
  refreshTargets();
});
ui.targetsNextBtn.addEventListener("click", () => {
  pagination.targets.page += 1;
  refreshTargets();
});
ui.jobsPrevBtn.addEventListener("click", () => {
  pagination.jobs.page = Math.max(1, pagination.jobs.page - 1);
  refreshJobs();
});
ui.jobsNextBtn.addEventListener("click", () => {
  pagination.jobs.page += 1;
  refreshJobs();
});
ui.spoofablePrevBtn.addEventListener("click", () => {
  pagination.spoofable.page = Math.max(1, pagination.spoofable.page - 1);
  refreshSpoofable();
});
ui.spoofableNextBtn.addEventListener("click", () => {
  pagination.spoofable.page += 1;
  refreshSpoofable();
});

ui.menuItems.forEach((item) => {
  item.addEventListener("click", () => activateView(item.dataset.view));
});

ui.targetsBody.addEventListener("click", (event) => {
  const runBtn = event.target.closest(".run-scan-btn");
  if (runBtn) {
    runScan(runBtn.dataset.targetId);
    return;
  }

  const dnsBtn = event.target.closest(".dns-data-btn");
  if (dnsBtn) {
    loadDnsData(dnsBtn.dataset.targetId, dnsBtn.dataset.hostname);
    return;
  }

  const deleteBtn = event.target.closest(".delete-target-btn");
  if (!deleteBtn) {
    return;
  }
  removeTarget(deleteBtn.dataset.targetId);
});

ui.jobsBody.addEventListener("click", (event) => {
  const btn = event.target.closest(".view-job-btn");
  if (!btn) {
    return;
  }
  loadJobResults(btn.dataset.scanId);
});

const persisted = loadPersistedSession();
setToken(persisted.token, persisted.username);
if (persisted.token) {
  refreshAll();
}
setInterval(() => {
  refreshAll();
}, 60000);
log("Prototype loaded.");
