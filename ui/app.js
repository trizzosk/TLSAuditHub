const ui = {
  menuItems: document.querySelectorAll(".menu-item"),
  viewTitle: document.getElementById("viewTitle"),
  loginForm: document.getElementById("loginForm"),
  authUsername: document.getElementById("authUsername"),
  authPassword: document.getElementById("authPassword"),
  loginBtn: document.getElementById("loginBtn"),
  loginOidcBtn: document.getElementById("loginOidcBtn"),
  loginOidcHint: document.getElementById("loginOidcHint"),
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
  editTargetPanel: document.getElementById("editTargetPanel"),
  editTargetForm: document.getElementById("editTargetForm"),
  editTargetId: document.getElementById("editTargetId"),
  editTargetHostname: document.getElementById("editTargetHostname"),
  editTargetPort: document.getElementById("editTargetPort"),
  editTargetStatus: document.getElementById("editTargetStatus"),
  cancelEditTargetBtn: document.getElementById("cancelEditTargetBtn"),
  dnsPanel: document.getElementById("dnsPanel"),
  targetsPageSize: document.getElementById("targetsPageSize"),
  targetsPrevBtn: document.getElementById("targetsPrevBtn"),
  targetsNextBtn: document.getElementById("targetsNextBtn"),
  targetsPageInfo: document.getElementById("targetsPageInfo"),
  refreshSpoofableBtn: document.getElementById("refreshSpoofableBtn"),
  exportSpoofableCsvBtn: document.getElementById("exportSpoofableCsvBtn"),
  exportSpoofablePdfBtn: document.getElementById("exportSpoofablePdfBtn"),
  spoofableBody: document.getElementById("spoofableBody"),
  spoofablePageSize: document.getElementById("spoofablePageSize"),
  spoofablePrevBtn: document.getElementById("spoofablePrevBtn"),
  spoofableNextBtn: document.getElementById("spoofableNextBtn"),
  spoofablePageInfo: document.getElementById("spoofablePageInfo"),
  runReportsBtn: document.getElementById("runReportsBtn"),
  refreshReportsBtn: document.getElementById("refreshReportsBtn"),
  sendReportsEmailBtn: document.getElementById("sendReportsEmailBtn"),
  reportEmailPanel: document.getElementById("reportEmailPanel"),
  reportEmailSelectionInfo: document.getElementById("reportEmailSelectionInfo"),
  reportEmailStatus: document.getElementById("reportEmailStatus"),
  reportEmailForm: document.getElementById("reportEmailForm"),
  reportEmailSubject: document.getElementById("reportEmailSubject"),
  cancelReportEmailBtn: document.getElementById("cancelReportEmailBtn"),
  exportReportsCsvBtn: document.getElementById("exportReportsCsvBtn"),
  exportReportsPdfBtn: document.getElementById("exportReportsPdfBtn"),
  reportTypeSelect: document.getElementById("reportTypeSelect"),
  reportDescription: document.getElementById("reportDescription"),
  reportsBody: document.getElementById("reportsBody"),
  reportsSelectAll: document.getElementById("reportsSelectAll"),
  reportsPageSize: document.getElementById("reportsPageSize"),
  reportsPrevBtn: document.getElementById("reportsPrevBtn"),
  reportsNextBtn: document.getElementById("reportsNextBtn"),
  reportsPageInfo: document.getElementById("reportsPageInfo"),
  refreshJobsBtn: document.getElementById("refreshJobsBtn"),
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
  schedulerForm: document.getElementById("schedulerForm"),
  schedulerEnabled: document.getElementById("schedulerEnabled"),
  schedulerFrequency: document.getElementById("schedulerFrequency"),
  schedulerDayOfWeek: document.getElementById("schedulerDayOfWeek"),
  schedulerTime: document.getElementById("schedulerTime"),
  schedulerIntervalMinutes: document.getElementById("schedulerIntervalMinutes"),
  schedulerDayWrap: document.getElementById("schedulerDayWrap"),
  schedulerTimeWrap: document.getElementById("schedulerTimeWrap"),
  schedulerIntervalWrap: document.getElementById("schedulerIntervalWrap"),
  schedulerLastRunInfo: document.getElementById("schedulerLastRunInfo"),
  reloadSchedulerBtn: document.getElementById("reloadSchedulerBtn"),
  smtpForm: document.getElementById("smtpForm"),
  smtpEnabled: document.getElementById("smtpEnabled"),
  smtpHost: document.getElementById("smtpHost"),
  smtpPort: document.getElementById("smtpPort"),
  smtpTimeoutSeconds: document.getElementById("smtpTimeoutSeconds"),
  smtpUseStarttls: document.getElementById("smtpUseStarttls"),
  smtpUseAuth: document.getElementById("smtpUseAuth"),
  smtpAuthWrap: document.getElementById("smtpAuthWrap"),
  smtpUsername: document.getElementById("smtpUsername"),
  smtpPassword: document.getElementById("smtpPassword"),
  smtpFromAddress: document.getElementById("smtpFromAddress"),
  smtpRecipient: document.getElementById("smtpRecipient"),
  smtpReplyTo: document.getElementById("smtpReplyTo"),
  smtpSubjectTemplate: document.getElementById("smtpSubjectTemplate"),
  reloadSmtpBtn: document.getElementById("reloadSmtpBtn"),
  refreshUsersBtn: document.getElementById("refreshUsersBtn"),
  bulkTargetsForm: document.getElementById("bulkTargetsForm"),
  targetsCsvFile: document.getElementById("targetsCsvFile"),
  purgeTargetsBtn: document.getElementById("purgeTargetsBtn"),
  purgeDnsBtn: document.getElementById("purgeDnsBtn"),
  purgeJobsAdminBtn: document.getElementById("purgeJobsAdminBtn"),
  userForm: document.getElementById("userForm"),
  userUsername: document.getElementById("userUsername"),
  userPassword: document.getElementById("userPassword"),
  userName: document.getElementById("userName"),
  userSurname: document.getElementById("userSurname"),
  userEmail: document.getElementById("userEmail"),
  usersBody: document.getElementById("usersBody"),
  editUserPanel: document.getElementById("editUserPanel"),
  editUserForm: document.getElementById("editUserForm"),
  editUserId: document.getElementById("editUserId"),
  editUserUsername: document.getElementById("editUserUsername"),
  editUserName: document.getElementById("editUserName"),
  editUserSurname: document.getElementById("editUserSurname"),
  editUserEmail: document.getElementById("editUserEmail"),
  editUserIsActive: document.getElementById("editUserIsActive"),
  cancelEditUserBtn: document.getElementById("cancelEditUserBtn"),
  authConfigForm: document.getElementById("authConfigForm"),
  reloadAuthBtn: document.getElementById("reloadAuthBtn"),
  authActiveMethod: document.getElementById("authActiveMethod"),
  authOidcEnabled: document.getElementById("authOidcEnabled"),
  authOidcIssuerUrl: document.getElementById("authOidcIssuerUrl"),
  authOidcClientId: document.getElementById("authOidcClientId"),
  authOidcClientSecret: document.getElementById("authOidcClientSecret"),
  authOidcRedirectUri: document.getElementById("authOidcRedirectUri"),
  authOidcUiRedirectUri: document.getElementById("authOidcUiRedirectUri"),
  authOidcScopes: document.getElementById("authOidcScopes"),
  authOidcUsernameClaim: document.getElementById("authOidcUsernameClaim"),
  authLdapEnabled: document.getElementById("authLdapEnabled"),
  authLdapHost: document.getElementById("authLdapHost"),
  authLdapPort: document.getElementById("authLdapPort"),
  authLdapUseSsl: document.getElementById("authLdapUseSsl"),
  authLdapValidateCert: document.getElementById("authLdapValidateCert"),
  authLdapBindDn: document.getElementById("authLdapBindDn"),
  authLdapBindPassword: document.getElementById("authLdapBindPassword"),
  authLdapUserBaseDn: document.getElementById("authLdapUserBaseDn"),
  authLdapUserFilter: document.getElementById("authLdapUserFilter"),
  adminShell: document.getElementById("adminShell"),
  adminNav: document.getElementById("adminNav"),
  adminNavToggleBtn: document.getElementById("adminNavToggleBtn"),
  adminPageTitle: document.getElementById("adminPageTitle"),
  adminNavItems: document.querySelectorAll(".admin-nav-item"),
  adminPages: document.querySelectorAll(".admin-page"),
  refreshEventLogBtn: document.getElementById("refreshEventLogBtn"),
  eventLogBody: document.getElementById("eventLogBody"),
  eventLogLevelFilter: document.getElementById("eventLogLevelFilter"),
  eventLogPageSize: document.getElementById("eventLogPageSize"),
  eventLogPrevBtn: document.getElementById("eventLogPrevBtn"),
  eventLogNextBtn: document.getElementById("eventLogNextBtn"),
  eventLogPageInfo: document.getElementById("eventLogPageInfo"),
  logPanel: document.getElementById("logPanel"),
};

let accessToken = "";
let currentUsername = "";
let oidcEnabled = false;
const jobIndex = new Map();
const userIndex = new Map();
const SESSION_TOKEN_KEY = "tlsaudithub_access_token";
const SESSION_USER_KEY = "tlsaudithub_username";

const pagination = {
  targets: { page: 1, pageSize: 10, total: 0 },
  jobs: { page: 1, pageSize: 10, total: 0 },
  spoofable: { page: 1, pageSize: 10, total: 0 },
  reports: { page: 1, pageSize: 10, total: 0 },
  eventLogs: { page: 1, pageSize: 15, total: 0 },
};
let currentReportMeta = null;
let currentReportItems = [];
let currentReportId = "";
const selectedReportTargetIds = new Set();
let activeAdminPage = "adminUsersPage";
const MOBILE_ADMIN_NAV_QUERY = "(max-width: 980px)";

function baseUrl() {
  return "http://localhost:8000";
}

function persistEventLog(message, level = "info", source = "ui") {
  if (!accessToken) {
    return;
  }
  apiRequest("/admin/event-logs", {
    method: "POST",
    body: JSON.stringify({ message, level, source }),
  }).catch(() => {
    // Avoid recursive logging if persistence fails.
  });
}

function log(message, options = {}) {
  const persist = options.persist !== false;
  const level = options.level || "info";
  const source = options.source || "ui";
  const now = new Date().toLocaleTimeString();
  ui.logPanel.textContent += `\n[${now}] ${message}`;
  ui.logPanel.scrollTop = ui.logPanel.scrollHeight;
  if (persist) {
    persistEventLog(message, level, source);
  }
}

function setAuthState(authenticated, label = "") {
  if (authenticated) {
    ui.authState.textContent = label || "Authenticated";
  } else {
    ui.authState.textContent = label || "Not authenticated";
  }
  ui.authState.classList.toggle("auth-state-authenticated", authenticated);
}

function setAuthenticatedUI(authenticated) {
  document.body.classList.toggle("unauth", !authenticated);
  ui.logoutBtn.classList.toggle("hidden", !authenticated);
  ui.authState.classList.toggle("hidden", !authenticated);
  ui.menuItems.forEach((item) => {
    item.disabled = !authenticated;
    item.setAttribute("aria-disabled", String(!authenticated));
  });
}

function isMobileAdminLayout() {
  return window.matchMedia(MOBILE_ADMIN_NAV_QUERY).matches;
}

function updateAdminNavToggleState() {
  if (!ui.adminShell || !ui.adminNavToggleBtn) {
    return;
  }
  const collapsed = ui.adminShell.classList.contains("admin-nav-collapsed");
  ui.adminNavToggleBtn.setAttribute("aria-expanded", String(!collapsed));
}

function updateModalBodyLock() {
  const hasOpenModal = [ui.editTargetPanel, ui.reportEmailPanel].some(
    (panel) => panel && !panel.classList.contains("hidden")
  );
  document.body.classList.toggle("modal-open", hasOpenModal);
}

function setEditTargetStatus(message = "", type = "") {
  if (!ui.editTargetStatus) {
    return;
  }
  ui.editTargetStatus.textContent = message;
  ui.editTargetStatus.classList.remove("form-hint-error", "form-hint-success");
  if (type === "error") {
    ui.editTargetStatus.classList.add("form-hint-error");
  } else if (type === "success") {
    ui.editTargetStatus.classList.add("form-hint-success");
  }
}

function setReportEmailStatus(message = "", type = "") {
  if (!ui.reportEmailStatus) {
    return;
  }
  ui.reportEmailStatus.textContent = message;
  ui.reportEmailStatus.classList.remove("form-hint-error", "form-hint-success");
  if (type === "error") {
    ui.reportEmailStatus.classList.add("form-hint-error");
  } else if (type === "success") {
    ui.reportEmailStatus.classList.add("form-hint-success");
  }
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
  const hasBody = Boolean(options.body);
  const isFormData =
    typeof FormData !== "undefined" && options.body instanceof FormData;
  if (!headers.has("Content-Type") && hasBody && !isFormData) {
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

function startOidcLogin() {
  const uiRedirect = `${window.location.origin}${window.location.pathname}`;
  const query = new URLSearchParams();
  query.set("ui_redirect", uiRedirect);
  window.location.assign(`${baseUrl()}/auth/oidc/login?${query.toString()}`);
}

function readAuthHashPayload() {
  const raw = window.location.hash || "";
  const hash = raw.startsWith("#") ? raw.slice(1) : raw;
  if (!hash) {
    return null;
  }
  const params = new URLSearchParams(hash);
  const appToken = String(params.get("app_token") || "").trim();
  const username = String(params.get("username") || "").trim();
  const oidcError = String(params.get("oidc_error") || "").trim();
  const oidcErrorDescription = String(
    params.get("oidc_error_description") || ""
  ).trim();
  if (!appToken && !oidcError) {
    return null;
  }
  if (window.history && window.history.replaceState) {
    window.history.replaceState(
      null,
      "",
      `${window.location.pathname}${window.location.search}`
    );
  } else {
    window.location.hash = "";
  }
  return { appToken, username, oidcError, oidcErrorDescription };
}

function applyPublicAuthConfig(data = {}) {
  const method = String(data.active_method || "local").toLowerCase();
  oidcEnabled = Boolean(data.oidc_enabled);
  const passwordEnabled = Boolean(data.password_login_enabled);
  ui.loginOidcBtn.classList.toggle("hidden", !oidcEnabled);
  ui.loginOidcHint.classList.toggle("hidden", !oidcEnabled);
  ui.loginBtn.disabled = !passwordEnabled;
  ui.authUsername.disabled = !passwordEnabled;
  ui.authPassword.disabled = !passwordEnabled;
  if (!passwordEnabled && method === "oidc") {
    ui.loginBtn.textContent = "Password Login Disabled";
  } else if (method === "ldap") {
    ui.loginBtn.textContent = "Login (LDAP)";
  } else {
    ui.loginBtn.textContent = "Login";
  }
}

async function loadAuthMethod() {
  try {
    const response = await fetch(`${baseUrl()}/auth/method`, {
      method: "GET",
    });
    if (!response.ok) {
      applyPublicAuthConfig({
        active_method: "local",
        password_login_enabled: true,
        oidc_enabled: false,
      });
      return;
    }
    const text = await response.text();
    const data = text ? JSON.parse(text) : {};
    applyPublicAuthConfig(data);
  } catch (_error) {
    applyPublicAuthConfig({
      active_method: "local",
      password_login_enabled: true,
      oidc_enabled: false,
    });
  }
}

function logout() {
  setToken("");
  log("Logged out.");
  loadAuthMethod();
}

function showResultsSelectionPrompt() {
  ui.selectedResultScanId.textContent = "";
  ui.jobResultsPanel.classList.add("muted");
  ui.jobResultsPanel.innerHTML = `
    <p class="mb-2">No job is selected yet.</p>
    <button type="button" class="open-jobs-btn btn btn-sm btn-outline-primary">
      Go to Jobs
    </button>
  `;
}

function activateView(viewId) {
  const viewNames = {
    authView: "Login",
    dashboardView: "Dashboard",
    targetsView: "Hosts / Targets",
    spoofableView: "Spoofable",
    reportsView: "Reports",
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
    const isActive = item.dataset.view === viewId;
    item.classList.toggle("active", isActive);
    if (isActive) {
      item.setAttribute("aria-current", "page");
    } else {
      item.removeAttribute("aria-current");
    }
  });

  ui.viewTitle.textContent = viewNames[viewId] || "Dashboard";

  if (
    viewId === "resultsView" &&
    !ui.selectedResultScanId.textContent.trim()
  ) {
    showResultsSelectionPrompt();
  }
  if (viewId === "reportsView") {
    refreshReports();
  }

  if (viewId === "adminView") {
    activateAdminPage(activeAdminPage);
  }
}

function activateAdminPage(pageId) {
  if (!ui.adminPages?.length) {
    return;
  }

  let resolvedPageId = pageId;
  const pageExists = Array.from(ui.adminPages).some(
    (page) => page.id === resolvedPageId
  );
  if (!pageExists) {
    resolvedPageId = "adminUsersPage";
  }
  activeAdminPage = resolvedPageId;

  ui.adminPages.forEach((page) => {
    page.classList.toggle("active", page.id === resolvedPageId);
  });
  ui.adminNavItems.forEach((item) => {
    const isActive = item.dataset.adminPage === resolvedPageId;
    item.classList.toggle("active", isActive);
    if (isActive) {
      item.setAttribute("aria-current", "page");
    } else {
      item.removeAttribute("aria-current");
    }
  });

  const activeNav = Array.from(ui.adminNavItems).find(
    (item) => item.dataset.adminPage === resolvedPageId
  );
  if (ui.adminPageTitle) {
    ui.adminPageTitle.textContent = activeNav
      ? activeNav.textContent.trim()
      : "Admin";
  }

  if (resolvedPageId === "adminProxyPage") {
    loadProxyConfig();
  } else if (resolvedPageId === "adminAuthPage") {
    loadAuthConfig();
  } else if (resolvedPageId === "adminSchedulerPage") {
    loadSchedulerConfig();
  } else if (resolvedPageId === "adminSmtpPage") {
    loadSmtpConfig();
  } else if (resolvedPageId === "adminUsersPage") {
    refreshUsers();
  } else if (resolvedPageId === "adminLogPage") {
    refreshEventLogs();
  }

  if (ui.adminShell && isMobileAdminLayout()) {
    ui.adminShell.classList.add("admin-nav-collapsed");
    updateAdminNavToggleState();
  }

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

function getPageSize(node, fallback = 10) {
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

function escapeCsv(value) {
  const str = String(value ?? "");
  if (
    str.includes(",") ||
    str.includes('"') ||
    str.includes("\n") ||
    str.includes("\r")
  ) {
    return `"${str.replaceAll('"', '""')}"`;
  }
  return str;
}

function downloadTextFile(content, filename, mimeType) {
  const blob = new Blob([content], {
    type: mimeType || "text/plain;charset=utf-8",
  });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function exportTimestamp() {
  const now = new Date();
  const y = now.getFullYear();
  const m = String(now.getMonth() + 1).padStart(2, "0");
  const d = String(now.getDate()).padStart(2, "0");
  const hh = String(now.getHours()).padStart(2, "0");
  const mm = String(now.getMinutes()).padStart(2, "0");
  const ss = String(now.getSeconds()).padStart(2, "0");
  return `${y}${m}${d}_${hh}${mm}${ss}`;
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

function classifyHttpStatusCode(code) {
  if (typeof code !== "number") {
    return "warn";
  }
  if (code === 200 || (code >= 300 && code < 400)) {
    return "good";
  }
  if (code === 401 || code === 403) {
    return "warn";
  }
  return "bad";
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

const RESULT_SECTION_LABELS = {
  certificate_info: "Certificate Information",
  http_headers: "HTTP Security Headers",
  heartbleed: "Heartbleed",
  robot: "ROBOT",
  session_renegotiation: "Session Renegotiation",
  tls_compression: "TLS Compression",
  tls_fallback_scsv: "TLS Fallback SCSV",
  ssl_2_0_cipher_suites: "SSL 2.0 Cipher Suites",
  ssl_3_0_cipher_suites: "SSL 3.0 Cipher Suites",
  tls_1_0_cipher_suites: "TLS 1.0 Cipher Suites",
  tls_1_1_cipher_suites: "TLS 1.1 Cipher Suites",
  tls_1_2_cipher_suites: "TLS 1.2 Cipher Suites",
  tls_1_3_cipher_suites: "TLS 1.3 Cipher Suites",
};

function humanizeResultSectionName(plugin) {
  if (RESULT_SECTION_LABELS[plugin]) {
    return RESULT_SECTION_LABELS[plugin];
  }

  return plugin
    .split("_")
    .map((part) => {
      const lower = String(part || "").toLowerCase();
      if (!lower) {
        return "";
      }
      if (lower === "tls" || lower === "ssl" || lower === "http" || lower === "hsts") {
        return lower.toUpperCase();
      }
      if (/^\d+$/.test(lower)) {
        return lower;
      }
      return `${lower[0].toUpperCase()}${lower.slice(1)}`;
    })
    .filter(Boolean)
    .join(" ");
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

const LEGACY_VULNERABLE_PROTOCOLS = new Set([
  "ssl_2_0_cipher_suites",
  "ssl_3_0_cipher_suites",
  "tls_1_0_cipher_suites",
  "tls_1_1_cipher_suites",
]);

function protocolSeverity(plugin, supported) {
  if (supported === null || supported === undefined) {
    return "warn";
  }
  if (LEGACY_VULNERABLE_PROTOCOLS.has(plugin)) {
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
  const isSupported = result?.is_protocol_supported;
  const acceptedSeverity =
    accepted.length === 0
      ? "good"
      : LEGACY_VULNERABLE_PROTOCOLS.has(plugin)
        ? "bad"
        : "warn";
  return `
    <dl class="result-grid">
      <dt>Plugin</dt><dd>${sevBadge(plugin, "warn")}</dd>
      <dt>Protocol Supported</dt><dd>${sevBadge(fmtBool(isSupported), protocolSeverity(plugin, isSupported))}</dd>
      <dt>Accepted Suites</dt><dd>${sevBadge(accepted.length, acceptedSeverity)}</dd>
    </dl>
    ${
      accepted.length
        ? `<ul class="result-list">${accepted
            .map((suite) => `<li class="tiny-mono result-item-${classifyCipherSuite(suite)}">${escapeHtml(suite)}</li>`)
            .join("")}</ul>`
        : `<p>${sevBadge("No accepted cipher suites.", "good")}</p>`
    }
  `;
}

function renderHttpHeaders(result) {
  const hsts = result?.strict_transport_security;
  const hstsPresent = Boolean(hsts);
  const maxAge = hsts?.max_age;
  const maxAgeSev =
    typeof maxAge !== "number" ? "bad" : maxAge >= 15552000 ? "good" : "warn";
  const statusCode = Number.isInteger(result?.http_status_code)
    ? result.http_status_code
    : null;
  return `
    <dl class="result-grid">
      <dt>HTTP Status Code</dt><dd>${sevBadge(
        statusCode ?? "-",
        classifyHttpStatusCode(statusCode)
      )}</dd>
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
      const sectionTitle = humanizeResultSectionName(plugin);
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
      } else if (plugin === "scan_error") {
        body = renderSecurityCheck(result, [
          {
            label: "Scan Status",
            value: String(result?.status || "failed"),
            severity: "bad",
          },
          {
            label: "Failure Reason",
            value: String(result?.error || "Unknown error"),
            severity: "warn",
          },
        ]);
      } else {
        body = renderGenericResult(result);
      }

      return `
        <article class="result-card">
          <h4>${escapeHtml(sectionTitle)}</h4>
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
      (target) => {
        const targetId = escapeHtml(String(target.id || ""));
        const hostname = escapeHtml(String(target.hostname || "unknown host"));
        const hostnameRaw = escapeHtml(String(target.hostname || ""));
        return `
      <tr>
        <td>${hostnameRaw}</td>
        <td>${target.port ?? ""}</td>
        <td>${target.enabled ? "Yes" : "No"}</td>
        <td>${target.scan_interval_minutes ?? "-"}</td>
        <td>
          <div class="target-actions">
            <button data-target-id="${targetId}" data-hostname="${hostnameRaw}" data-port="${target.port ?? 443}" class="edit-target-btn btn btn-sm btn-outline-secondary" aria-label="Edit target ${hostname}" title="Edit target ${hostname}">Edit</button>
            <button data-target-id="${targetId}" class="run-scan-btn btn btn-sm btn-outline-primary" aria-label="Run scan for ${hostname}" title="Run scan for ${hostname}">Run Scan</button>
            <button data-target-id="${targetId}" data-hostname="${hostnameRaw}" class="dns-data-btn btn btn-sm btn-outline-secondary" aria-label="View DNS data for ${hostname}" title="View DNS data for ${hostname}">DNS Data</button>
            <button data-target-id="${targetId}" class="delete-target-btn btn btn-sm btn-outline-danger" aria-label="Delete target ${hostname}" title="Delete target ${hostname}">Delete</button>
          </div>
        </td>
      </tr>
    `;
      }
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
  const dmarcPolicyRaw = String(dmarc.policy || "").trim();
  const dmarcPolicyMissing = !dmarcPolicyRaw;
  const dmarcPolicyNone = dmarcPolicyRaw.toLowerCase() === "none";
  const dmarcPolicySeverity =
    dmarcPolicyMissing || dmarcPolicyNone ? "bad" : "good";

  return `
    <article class="result-card">
      <h4>Overview</h4>
      <dl class="result-grid">
        <dt>Hostname</dt><dd class="tiny-mono">${sevBadge(data.hostname || targetLabel || "-", "warn")}</dd>
        <dt>Updated</dt><dd>${sevBadge(fmtDate(payload.updated_at), payload.updated_at ? "good" : "warn")}</dd>
        <dt>SPF Record</dt><dd>${sevBadge(spfPresent ? "Yes" : "No", spfPresent ? "good" : "warn")}</dd>
        <dt>DMARC Record</dt><dd>${sevBadge(dmarcPresent ? "Yes" : "No", dmarcPresent ? "good" : "warn")}</dd>
        <dt>DMARC Policy</dt><dd>${sevBadge(dmarc.policy || "-", dmarcPolicySeverity)}</dd>
      </dl>
    </article>
    <article class="result-card">
      <h4>NS Records</h4>
      ${renderDnsList(data.ns, "No NS records found.")}
    </article>
    <article class="result-card">
      <h4>SOA Records</h4>
      ${renderDnsList(data.soa, "No SOA records found.")}
    </article>
    <article class="result-card">
      <h4>A Records</h4>
      ${renderDnsList(data.a, "No A records found.")}
    </article>
    <article class="result-card">
      <h4>AAAA Records</h4>
      ${renderDnsList(data.aaaa, "No AAAA records found.")}
    </article>
    <article class="result-card">
      <h4>Resolved IP Addresses</h4>
      ${renderDnsList(data.resolved_ips, "No resolved IP addresses found.")}
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
        <dt>Policy</dt><dd>${sevBadge(dmarc.policy || "-", dmarcPolicySeverity)}</dd>
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
      (job) => {
        const jobId = escapeHtml(String(job.id || ""));
        const hostLabel = escapeHtml(
          `${job.hostname ?? "Unknown"}:${job.port ?? "-"}`
        );
        const status = escapeHtml(String(job.status || "-"));
        const errorMessage = String(job.error_message || "").trim();
        const errorNote = errorMessage
          ? `<div class="muted tiny-mono" title="${escapeHtml(errorMessage)}">${escapeHtml(errorMessage)}</div>`
          : "";
        return `
      <tr>
        <td>${jobId}</td>
        <td>${hostLabel}</td>
        <td>${status}${errorNote}</td>
        <td>${fmtDate(job.started_at)}</td>
        <td>${fmtDate(job.finished_at)}</td>
        <td><button data-scan-id="${jobId}" class="view-job-btn btn btn-sm btn-outline-primary" aria-label="View results for job ${jobId} on ${hostLabel}" title="View results for ${hostLabel}">Results</button></td>
      </tr>
    `;
      }
    )
    .join("");
}

function evaluateSpoofable(spf, dmarcPolicy, hasMx, hasA, hasAaaa) {
  const spfValue = String(spf || "").trim().toLowerCase();
  const policy = String(dmarcPolicy || "").trim().toLowerCase();
  const spfStrict = spfValue.endsWith("-all");
  const dmarcReject = policy === "reject" || policy === "quarantine";
  const dmarcNone = policy === "" || policy === "none";
  const hasMailRoute = Boolean(hasMx || hasA || hasAaaa);

  if (!hasMailRoute && !spfValue && dmarcNone) {
    return { label: "Not spoofable", severity: "good" };
  }

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
      const result = evaluateSpoofable(
        row.spf,
        row.dmarc_policy,
        row.has_mx,
        row.has_a,
        row.has_aaaa
      );
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

function reportSelectionKey(row) {
  return String(row?.target_id || "").trim();
}

function syncReportsSelectAll() {
  if (!ui.reportsSelectAll) {
    return;
  }
  const visibleKeys = currentReportItems
    .map((row) => reportSelectionKey(row))
    .filter(Boolean);
  if (!visibleKeys.length) {
    ui.reportsSelectAll.checked = false;
    ui.reportsSelectAll.indeterminate = false;
    ui.reportsSelectAll.disabled = true;
    return;
  }
  ui.reportsSelectAll.disabled = false;
  const selectedCount = visibleKeys.filter((key) =>
    selectedReportTargetIds.has(key)
  ).length;
  ui.reportsSelectAll.checked = selectedCount === visibleKeys.length;
  ui.reportsSelectAll.indeterminate =
    selectedCount > 0 && selectedCount < visibleKeys.length;
  if (ui.reportEmailSelectionInfo) {
    ui.reportEmailSelectionInfo.textContent = `Selected hosts: ${selectedReportTargetIds.size}`;
  }
}

function renderReportRows(items) {
  currentReportItems = Array.isArray(items) ? items : [];
  if (!Array.isArray(items) || items.length === 0) {
    ui.reportsBody.innerHTML =
      "<tr><td colspan='6' class='muted'>No findings for selected report.</td></tr>";
    syncReportsSelectAll();
    return;
  }

  ui.reportsBody.innerHTML = items
    .map(
      (row) => {
        const key = reportSelectionKey(row);
        const checked = key && selectedReportTargetIds.has(key) ? "checked" : "";
        return `
      <tr>
        <td>
          <input
            type="checkbox"
            class="report-row-select"
            data-target-id="${escapeHtml(key || "")}"
            ${checked}
            aria-label="Select ${escapeHtml(row.host_target || "row")}"
          >
        </td>
        <td class="tiny-mono">${escapeHtml(row.host_target || "-")}</td>
        <td>${escapeHtml(row.finding_id || "-")}</td>
        <td>${sevBadge(row.severity || "-", row.severity === "high" ? "bad" : row.severity === "medium" ? "warn" : "good")}</td>
        <td class="tiny-mono">${escapeHtml(row.finding_proof || "-")}</td>
        <td>${escapeHtml(fmtDate(row.scan_timestamp_utc))}</td>
      </tr>
    `;
      }
    )
    .join("");
  syncReportsSelectAll();
}

async function loadAllReportItems(reportId) {
  const query = new URLSearchParams({
    report_id: String(reportId || ""),
    limit: "0",
    offset: "0",
  });
  return apiRequest(`/reports/findings?${query.toString()}`, {
    method: "GET",
  });
}

async function refreshReports() {
  try {
    const reportId = String(ui.reportTypeSelect.value || "no_tls13");
    if (currentReportId !== reportId) {
      selectedReportTargetIds.clear();
      currentReportId = reportId;
    }
    pagination.reports.pageSize = getPageSize(ui.reportsPageSize, 10);
    const limit = pagination.reports.pageSize;
    const offset = limit > 0 ? (pagination.reports.page - 1) * limit : 0;
    const query = new URLSearchParams({
      report_id: reportId,
      limit: String(limit),
      offset: String(offset),
    });
    const data = await apiRequest(`/reports/findings?${query.toString()}`, {
      method: "GET",
    });
    currentReportMeta = data.report || null;
    if (ui.reportDescription) {
      ui.reportDescription.textContent =
        currentReportMeta?.description || "No report description available.";
    }
    pagination.reports.total = data.total ?? 0;
    if (
      pagination.reports.page > 1 &&
      pagination.reports.total > 0 &&
      Array.isArray(data.items) &&
      data.items.length === 0
    ) {
      pagination.reports.page = 1;
      return refreshReports();
    }
    updatePaginationUI("reports", {
      prevBtn: ui.reportsPrevBtn,
      nextBtn: ui.reportsNextBtn,
      pageInfo: ui.reportsPageInfo,
    });
    renderReportRows(data.items || []);
    log(
      `Loaded report '${reportId}' (${Array.isArray(data.items) ? data.items.length : 0} rows).`
    );
  } catch (error) {
    ui.reportsBody.innerHTML =
      "<tr><td colspan='6' class='muted'>Failed to load report.</td></tr>";
    currentReportItems = [];
    syncReportsSelectAll();
    log(`Report load failed: ${error.message}`);
  }
}

async function runReports() {
  pagination.reports.page = 1;
  await refreshReports();
}

async function exportReportsCsv() {
  try {
    const reportId = String(ui.reportTypeSelect.value || "no_tls13");
    const data = await loadAllReportItems(reportId);
    const items = Array.isArray(data.items) ? data.items : [];
    if (!items.length) {
      log("Report CSV export skipped: no findings.");
      return;
    }
    const title = data.report?.title || reportId;
    const lines = [];
    lines.push([`Report`, title, "", "", ""].map(escapeCsv).join(","));
    lines.push(
      ["Host / Target", "Finding ID", "Severity", "Finding Proof", "Scan Timestamp (UTC)"]
        .map(escapeCsv)
        .join(",")
    );
    items.forEach((row) => {
      lines.push(
        [
          row.host_target || "-",
          row.finding_id || "-",
          row.severity || "-",
          row.finding_proof || "-",
          row.scan_timestamp_utc || "-",
        ]
          .map(escapeCsv)
          .join(",")
      );
    });
    const filename = `${reportId}_report_${exportTimestamp()}.csv`;
    downloadTextFile(lines.join("\n"), filename, "text/csv;charset=utf-8");
    log(`Report CSV exported (${items.length} rows).`);
  } catch (error) {
    log(`Report CSV export failed: ${error.message}`);
  }
}

async function exportReportsPdf() {
  try {
    const reportId = String(ui.reportTypeSelect.value || "no_tls13");
    const data = await loadAllReportItems(reportId);
    const items = Array.isArray(data.items) ? data.items : [];
    if (!items.length) {
      log("Report PDF export skipped: no findings.");
      return;
    }
    const title = escapeHtml(data.report?.title || reportId);
    const description = escapeHtml(data.report?.description || "");
    const tableRows = items
      .map(
        (row) => `
          <tr>
            <td>${escapeHtml(row.host_target || "-")}</td>
            <td>${escapeHtml(row.finding_id || "-")}</td>
            <td>${escapeHtml(row.severity || "-")}</td>
            <td>${escapeHtml(row.finding_proof || "-")}</td>
            <td>${escapeHtml(row.scan_timestamp_utc || "-")}</td>
          </tr>
        `
      )
      .join("");

    const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>${title}</title>
  <style>
    @page { size: A4 landscape; margin: 10mm; }
    @media print {
      @page { size: A4 landscape; margin: 10mm; }
      html, body { width: 297mm; height: 210mm; }
    }
    body { font-family: Arial, sans-serif; margin: 0; color: #111; }
    h1 { margin: 0 0 6px; font-size: 18px; }
    .meta { margin: 0 0 10px; font-size: 12px; color: #333; }
    table { width: 100%; border-collapse: collapse; table-layout: fixed; }
    th, td { border: 1px solid #999; padding: 6px; text-align: left; font-size: 10px; vertical-align: top; word-break: break-word; }
    th { background: #f2f2f2; }
  </style>
</head>
<body>
  <h1>${title}</h1>
  <p class="meta">${description}</p>
  <p class="meta">Generated: ${escapeHtml(new Date().toLocaleString())} | Rows: ${items.length}</p>
  <table>
    <thead>
      <tr>
        <th scope="col">Host / Target</th>
        <th scope="col">Finding ID</th>
        <th scope="col">Severity</th>
        <th scope="col">Finding Proof</th>
        <th scope="col">Scan Timestamp (UTC)</th>
      </tr>
    </thead>
    <tbody>${tableRows}</tbody>
  </table>
</body>
</html>`;

    const printWindow = window.open("", "_blank");
    if (!printWindow) {
      log("Report PDF export failed: popup blocked by browser.");
      return;
    }
    printWindow.document.open();
    printWindow.document.write(html);
    printWindow.document.close();
    printWindow.focus();
    setTimeout(() => {
      printWindow.print();
    }, 250);
    log(`Report PDF prepared (${items.length} rows).`);
  } catch (error) {
    log(`Report PDF export failed: ${error.message}`);
  }
}

function closeReportEmailPanel() {
  if (!ui.reportEmailPanel || !ui.reportEmailForm) {
    return;
  }
  ui.reportEmailPanel.classList.add("hidden");
  ui.reportEmailForm.reset();
  setReportEmailStatus("");
  updateModalBodyLock();
}

function openReportEmailPanel() {
  const selectedCount = selectedReportTargetIds.size;
  if (!selectedCount) {
    log("Report email send skipped: select at least one host.");
    return;
  }
  if (ui.reportEmailSelectionInfo) {
    ui.reportEmailSelectionInfo.textContent = `Selected hosts: ${selectedCount}`;
  }
  setReportEmailStatus("");
  ui.reportEmailPanel.classList.remove("hidden");
  ui.reportEmailSubject.value = "";
  ui.reportEmailSubject.focus();
  updateModalBodyLock();
}

async function sendReportEmailFromPanel(event) {
  event.preventDefault();
  try {
    const reportId = String(ui.reportTypeSelect.value || "no_tls13");
    const selectedIds = Array.from(selectedReportTargetIds);
    if (!selectedIds.length) {
      setReportEmailStatus("Select at least one host.", "error");
      log("Report email send skipped: select at least one host.");
      return;
    }
    setReportEmailStatus("Sending email...", "");
    const data = await apiRequest("/reports/email", {
      method: "POST",
      body: JSON.stringify({
        report_id: reportId,
        selected_target_ids: selectedIds,
        subject: String(ui.reportEmailSubject.value || "").trim(),
      }),
    });
    setReportEmailStatus(
      `Success: email sent to ${data.recipient || "-"} (${data.rows ?? 0} rows).`,
      "success"
    );
    log(
      `Report email sent to ${data.recipient || "-"}; subject='${data.subject || "-"}'; rows=${data.rows ?? 0}.`
    );
  } catch (error) {
    setReportEmailStatus(`Error: ${error.message}`, "error");
    log(`Report email send failed: ${error.message}`);
  }
}

async function loadAllSpoofableItems() {
  const data = await apiRequest("/dns/spoofable?limit=0&offset=0", {
    method: "GET",
  });
  return Array.isArray(data.items) ? data.items : [];
}

async function exportSpoofableCsv() {
  try {
    const items = await loadAllSpoofableItems();
    if (!items.length) {
      log("Spoofable CSV export skipped: no data available.");
      return;
    }

    const header = ["Target / Host", "SPF Record", "DMARC Policy", "Result"];
    const lines = [header.map(escapeCsv).join(",")];
    items.forEach((row) => {
      const result = evaluateSpoofable(
        row.spf,
        row.dmarc_policy,
        row.has_mx,
        row.has_a,
        row.has_aaaa
      );
      lines.push(
        [
          row.hostname || "-",
          row.spf || "-",
          row.dmarc_policy || "-",
          result.label,
        ]
          .map(escapeCsv)
          .join(",")
      );
    });

    const filename = `spoofable_report_${exportTimestamp()}.csv`;
    downloadTextFile(lines.join("\n"), filename, "text/csv;charset=utf-8");
    log(`Spoofable CSV exported (${items.length} rows).`);
  } catch (error) {
    log(`Spoofable CSV export failed: ${error.message}`);
  }
}

async function exportSpoofablePdf() {
  try {
    const items = await loadAllSpoofableItems();
    if (!items.length) {
      log("Spoofable PDF export skipped: no data available.");
      return;
    }

    const tableRows = items
      .map((row) => {
        const result = evaluateSpoofable(
          row.spf,
          row.dmarc_policy,
          row.has_mx,
          row.has_a,
          row.has_aaaa
        );
        return `
          <tr>
            <td>${escapeHtml(row.hostname || "-")}</td>
            <td>${escapeHtml(row.spf || "-")}</td>
            <td>${escapeHtml(row.dmarc_policy || "-")}</td>
            <td>${escapeHtml(result.label)}</td>
          </tr>
        `;
      })
      .join("");

    const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Spoofable Report</title>
  <style>
    @page { size: A4 landscape; margin: 10mm; }
    @media print {
      @page { size: A4 landscape; margin: 10mm; }
      html, body { width: 297mm; height: 210mm; }
    }
    body { font-family: Arial, sans-serif; margin: 0; color: #111; }
    h1 { margin: 0 0 6px; font-size: 18px; }
    .meta { margin: 0 0 12px; font-size: 12px; color: #333; }
    table { width: 100%; border-collapse: collapse; table-layout: fixed; }
    th, td { border: 1px solid #999; padding: 6px; text-align: left; font-size: 10px; vertical-align: top; word-break: break-word; }
    th { background: #f2f2f2; }
  </style>
</head>
<body>
  <h1>Spoofable Domains Report</h1>
  <p class="meta">Generated: ${escapeHtml(new Date().toLocaleString())} | Rows: ${items.length}</p>
  <table>
    <thead>
      <tr>
        <th scope="col">Target / Host</th>
        <th scope="col">SPF Record</th>
        <th scope="col">DMARC Policy</th>
        <th scope="col">Result</th>
      </tr>
    </thead>
    <tbody>${tableRows}</tbody>
  </table>
</body>
</html>`;

    const printWindow = window.open("", "_blank");
    if (!printWindow) {
      log("Spoofable PDF export failed: popup blocked by browser.");
      return;
    }
    printWindow.document.open();
    printWindow.document.write(html);
    printWindow.document.close();
    printWindow.focus();
    setTimeout(() => {
      printWindow.print();
    }, 250);
    log(`Spoofable PDF prepared (${items.length} rows).`);
  } catch (error) {
    log(`Spoofable PDF export failed: ${error.message}`);
  }
}

async function refreshSpoofable() {
  try {
    pagination.spoofable.pageSize = getPageSize(ui.spoofablePageSize, 10);
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
    pagination.targets.pageSize = getPageSize(ui.targetsPageSize, 10);
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

function closeEditTargetPanel() {
  if (!ui.editTargetPanel || !ui.editTargetForm) {
    return;
  }
  ui.editTargetPanel.classList.add("hidden");
  ui.editTargetForm.reset();
  ui.editTargetId.value = "";
  setEditTargetStatus("");
  updateModalBodyLock();
}

function openEditTargetPanel(targetId, currentHostname, currentPort) {
  ui.editTargetId.value = String(targetId || "");
  ui.editTargetHostname.value = String(currentHostname || "");
  ui.editTargetPort.value = String(currentPort || 443);
  setEditTargetStatus("");
  ui.editTargetPanel.classList.remove("hidden");
  ui.editTargetHostname.focus();
  updateModalBodyLock();
}

async function saveTargetEdit(event) {
  event.preventDefault();
  const targetId = String(ui.editTargetId.value || "").trim();
  if (!targetId) {
    setEditTargetStatus("Edit target failed: missing target id.", "error");
    return;
  }
  const hostname = ui.editTargetHostname.value.trim();
  if (!hostname) {
    setEditTargetStatus("Edit target failed: hostname is required.", "error");
    return;
  }

  const port = Number(ui.editTargetPort.value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    setEditTargetStatus(
      "Edit target failed: port must be an integer in range 1-65535.",
      "error"
    );
    return;
  }

  setEditTargetStatus("Saving changes...", "");
  try {
    const data = await apiRequest(`/targets/${targetId}`, {
      method: "PUT",
      body: JSON.stringify({ hostname, port }),
    });
    const queueErrors = Array.isArray(data.queue_errors)
      ? data.queue_errors.filter(Boolean)
      : [];
    log(
      `Target ${targetId} updated to ${hostname}:${port}. Checks re-run queued (scan=${data.scan_task_id || "-"}, dns=${data.dns_task_id || "-"}).`
    );
    if (queueErrors.length > 0) {
      log(`Target ${targetId} updated, but queue warnings: ${queueErrors.join(" | ")}`);
    }
    setEditTargetStatus("Target saved successfully.", "success");
    closeEditTargetPanel();
    const refreshResults = await Promise.allSettled([
      refreshTargets(),
      refreshJobs(),
      refreshSpoofable(),
      loadDashboard(),
    ]);
    const refreshErrors = refreshResults
      .filter((item) => item.status === "rejected")
      .map((item) => item.reason?.message || String(item.reason || "unknown refresh error"));
    if (refreshErrors.length) {
      log(`Target updated, but post-save refresh had issues: ${refreshErrors.join(" | ")}`);
    }
  } catch (error) {
    log(`Edit target failed: ${error.message}`);
    setEditTargetStatus(`Edit target failed: ${error.message}`, "error");
    // Refresh anyway: backend may have committed the edit before queue errors.
    await Promise.all([refreshTargets(), refreshSpoofable(), loadDashboard()]);
  }
}

async function refreshJobs() {
  try {
    pagination.jobs.pageSize = getPageSize(ui.jobsPageSize, 10);
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

async function purgeJobsData() {
  if (
    !window.confirm(
      "Purge all jobs and results? This action cannot be undone."
    )
  ) {
    return;
  }
  try {
    const data = await apiRequest("/admin/purge/jobs", { method: "POST" });
    log(
      `Jobs purged. Deleted scans=${data.deleted_scans ?? 0}, results=${data.deleted_results ?? 0}, diffs=${data.deleted_diffs ?? 0}.`
    );
    await Promise.all([refreshJobs(), loadDashboard(), refreshTargets()]);
  } catch (error) {
    log(`Jobs purge failed: ${error.message}`);
  }
}

async function purgeTargetsData() {
  if (
    !window.confirm(
      "Purge all targets/hosts and all related scans, DNS data, and diffs? This action cannot be undone."
    )
  ) {
    return;
  }
  try {
    const data = await apiRequest("/admin/purge/targets", { method: "POST" });
    log(
      `Targets purged. Deleted targets=${data.deleted_targets ?? 0}, scans=${data.deleted_scans ?? 0}, dns=${data.deleted_dns ?? 0}, results=${data.deleted_results ?? 0}, diffs=${data.deleted_diffs ?? 0}.`
    );
    await Promise.all([refreshTargets(), refreshJobs(), loadDashboard(), refreshSpoofable()]);
    ui.dnsPanel.innerHTML = "<p class='muted'>Select a host to view DNS details.</p>";
  } catch (error) {
    log(`Targets purge failed: ${error.message}`);
  }
}

async function purgeDnsData() {
  if (
    !window.confirm(
      "Purge DNS data cache for all targets? Targets and scan jobs remain."
    )
  ) {
    return;
  }
  try {
    const data = await apiRequest("/admin/purge/dns", { method: "POST" });
    log(`DNS cache purged. Deleted dns records=${data.deleted_dns ?? 0}.`);
    await Promise.all([refreshSpoofable(), refreshTargets(), loadDashboard()]);
    ui.dnsPanel.innerHTML = "<p class='muted'>DNS data purged. Select a host to trigger fresh lookup.</p>";
  } catch (error) {
    log(`DNS purge failed: ${error.message}`);
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

async function loadAuthConfig() {
  try {
    const data = await apiRequest("/config/auth", { method: "GET" });
    ui.authActiveMethod.value = String(data.active_method || "local").toLowerCase();
    ui.authOidcEnabled.checked = Boolean(data.oidc_enabled);
    ui.authOidcIssuerUrl.value = data.oidc_issuer_url || "";
    ui.authOidcClientId.value = data.oidc_client_id || "";
    ui.authOidcClientSecret.value = "";
    ui.authOidcClientSecret.placeholder = data.oidc_has_client_secret
      ? "stored (leave empty to keep current)"
      : "optional";
    ui.authOidcRedirectUri.value =
      data.oidc_redirect_uri || "http://localhost:8000/auth/oidc/callback";
    ui.authOidcUiRedirectUri.value = data.oidc_ui_redirect_uri || `${window.location.origin}/`;
    ui.authOidcScopes.value = data.oidc_scopes || "openid profile email";
    ui.authOidcUsernameClaim.value = data.oidc_username_claim || "preferred_username";
    ui.authLdapEnabled.checked = Boolean(data.ldap_enabled);
    ui.authLdapHost.value = data.ldap_host || "";
    ui.authLdapPort.value = data.ldap_port || 636;
    ui.authLdapUseSsl.checked = Boolean(data.ldap_use_ssl);
    ui.authLdapValidateCert.checked = Boolean(data.ldap_validate_cert);
    ui.authLdapBindDn.value = data.ldap_bind_dn || "";
    ui.authLdapBindPassword.value = "";
    ui.authLdapBindPassword.placeholder = data.ldap_has_bind_password
      ? "stored (leave empty to keep current)"
      : "optional";
    ui.authLdapUserBaseDn.value = data.ldap_user_base_dn || "";
    ui.authLdapUserFilter.value = data.ldap_user_filter || "(uid={username})";
    log("Authentication configuration loaded.");
  } catch (error) {
    log(`Authentication configuration load failed: ${error.message}`);
  }
}

async function saveAuthConfig(event) {
  event.preventDefault();
  const payload = {
    active_method: String(ui.authActiveMethod.value || "local").toLowerCase(),
    oidc_enabled: Boolean(ui.authOidcEnabled.checked),
    oidc_issuer_url: ui.authOidcIssuerUrl.value.trim(),
    oidc_client_id: ui.authOidcClientId.value.trim(),
    oidc_client_secret: ui.authOidcClientSecret.value,
    oidc_redirect_uri: ui.authOidcRedirectUri.value.trim(),
    oidc_ui_redirect_uri: ui.authOidcUiRedirectUri.value.trim(),
    oidc_scopes: ui.authOidcScopes.value.trim(),
    oidc_username_claim: ui.authOidcUsernameClaim.value.trim(),
    ldap_enabled: Boolean(ui.authLdapEnabled.checked),
    ldap_host: ui.authLdapHost.value.trim(),
    ldap_port: Number(ui.authLdapPort.value),
    ldap_use_ssl: Boolean(ui.authLdapUseSsl.checked),
    ldap_validate_cert: Boolean(ui.authLdapValidateCert.checked),
    ldap_bind_dn: ui.authLdapBindDn.value.trim(),
    ldap_bind_password: ui.authLdapBindPassword.value,
    ldap_user_base_dn: ui.authLdapUserBaseDn.value.trim(),
    ldap_user_filter: ui.authLdapUserFilter.value.trim(),
  };

  try {
    const data = await apiRequest("/config/auth", {
      method: "PUT",
      body: JSON.stringify(payload),
    });
    ui.authOidcClientSecret.value = "";
    ui.authOidcClientSecret.placeholder = data.oidc_has_client_secret
      ? "stored (leave empty to keep current)"
      : "optional";
    ui.authLdapBindPassword.value = "";
    ui.authLdapBindPassword.placeholder = data.ldap_has_bind_password
      ? "stored (leave empty to keep current)"
      : "optional";
    ui.authActiveMethod.value = String(data.active_method || payload.active_method);
    log(`Authentication configuration saved (active=${data.active_method}).`);
    await loadAuthMethod();
  } catch (error) {
    log(`Authentication configuration save failed: ${error.message}`);
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

function applySmtpAuthVisibility(useAuth) {
  ui.smtpAuthWrap.classList.toggle("hidden", !Boolean(useAuth));
}

async function loadSmtpConfig() {
  try {
    const data = await apiRequest("/config/smtp", { method: "GET" });
    ui.smtpEnabled.checked = Boolean(data.enabled);
    ui.smtpHost.value = data.host || "";
    ui.smtpPort.value = data.port || 25;
    ui.smtpTimeoutSeconds.value = data.timeout_seconds || 15;
    ui.smtpUseStarttls.checked = Boolean(data.use_starttls);
    ui.smtpUseAuth.checked = Boolean(data.use_auth);
    ui.smtpUsername.value = data.username || "";
    ui.smtpPassword.value = "";
    ui.smtpPassword.placeholder = data.has_password
      ? "stored (leave empty to keep current)"
      : "enter password";
    ui.smtpFromAddress.value = data.from_address || "";
    ui.smtpRecipient.value = data.recipient || "";
    ui.smtpReplyTo.value = data.reply_to || "";
    ui.smtpSubjectTemplate.value = data.subject_template || "{finding_name}";
    applySmtpAuthVisibility(Boolean(data.use_auth));
    log("SMTP configuration loaded.");
  } catch (error) {
    log(`SMTP configuration load failed: ${error.message}`);
  }
}

async function saveSmtpConfig(event) {
  event.preventDefault();
  const payload = {
    enabled: Boolean(ui.smtpEnabled.checked),
    host: ui.smtpHost.value.trim(),
    port: Number(ui.smtpPort.value),
    timeout_seconds: Number(ui.smtpTimeoutSeconds.value),
    use_starttls: Boolean(ui.smtpUseStarttls.checked),
    use_auth: Boolean(ui.smtpUseAuth.checked),
    username: ui.smtpUsername.value.trim(),
    password: ui.smtpPassword.value,
    from_address: ui.smtpFromAddress.value.trim(),
    recipient: ui.smtpRecipient.value.trim(),
    reply_to: ui.smtpReplyTo.value.trim(),
    subject_template: ui.smtpSubjectTemplate.value.trim() || "{finding_name}",
  };

  try {
    const data = await apiRequest("/config/smtp", {
      method: "PUT",
      body: JSON.stringify(payload),
    });
    ui.smtpPassword.value = "";
    ui.smtpPassword.placeholder = data.has_password
      ? "stored (leave empty to keep current)"
      : "enter password";
    applySmtpAuthVisibility(Boolean(data.use_auth));
    log(
      `SMTP configuration saved (${data.enabled ? "enabled" : "disabled"}, ${data.host}:${data.port}).`
    );
  } catch (error) {
    log(`SMTP save failed: ${error.message}`);
  }
}

function applySchedulerFrequencyVisibility(frequency) {
  const value = String(frequency || "daily").toLowerCase();
  const isInterval = value === "interval";
  const isWeekly = value === "weekly";
  const isHourly = value === "hourly";

  ui.schedulerIntervalWrap.classList.toggle("hidden", !isInterval);
  ui.schedulerDayWrap.classList.toggle("hidden", !isWeekly);
  ui.schedulerTimeWrap.classList.toggle("hidden", isInterval || isHourly);
}

function splitTimeParts(value) {
  const text = String(value || "").trim();
  const match = /^(\d{1,2}):(\d{2})$/.exec(text);
  if (!match) {
    return { hour: 2, minute: 0 };
  }
  const hour = Number(match[1]);
  const minute = Number(match[2]);
  return {
    hour: Number.isFinite(hour) ? hour : 2,
    minute: Number.isFinite(minute) ? minute : 0,
  };
}

function toTimeValue(hour, minute) {
  const h = clamp(Number(hour) || 0, 0, 23);
  const m = clamp(Number(minute) || 0, 0, 59);
  return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}`;
}

async function loadSchedulerConfig() {
  try {
    const data = await apiRequest("/config/scheduler", { method: "GET" });
    const frequency = String(data.frequency || "daily").toLowerCase();
    ui.schedulerEnabled.checked = Boolean(data.enabled);
    ui.schedulerFrequency.value = frequency;
    ui.schedulerDayOfWeek.value = String(data.day_of_week ?? 1);
    ui.schedulerTime.value = toTimeValue(data.hour ?? 2, data.minute ?? 0);
    ui.schedulerIntervalMinutes.value = String(data.interval_minutes ?? 1440);
    ui.schedulerLastRunInfo.textContent = `Last run: ${fmtDate(
      data.last_run_at
    )}`;
    applySchedulerFrequencyVisibility(frequency);
    log("Scheduler configuration loaded.");
  } catch (error) {
    log(`Scheduler configuration load failed: ${error.message}`);
  }
}

async function saveSchedulerConfig(event) {
  event.preventDefault();
  const frequency = String(ui.schedulerFrequency.value || "daily").toLowerCase();
  const dayOfWeek = Number(ui.schedulerDayOfWeek.value);
  const intervalMinutes = Number(ui.schedulerIntervalMinutes.value);
  const { hour, minute } = splitTimeParts(ui.schedulerTime.value);

  if (frequency === "interval") {
    if (
      !Number.isFinite(intervalMinutes) ||
      intervalMinutes < 1 ||
      intervalMinutes > 10080
    ) {
      log("Scheduler save failed: interval must be 1 to 10080 minutes.");
      return;
    }
  }

  if (frequency === "weekly" && (!Number.isFinite(dayOfWeek) || dayOfWeek < 0 || dayOfWeek > 6)) {
    log("Scheduler save failed: day of week must be 0-6.");
    return;
  }

  if (frequency !== "interval") {
    if (!Number.isFinite(hour) || hour < 0 || hour > 23) {
      log("Scheduler save failed: hour must be 0-23.");
      return;
    }
    if (!Number.isFinite(minute) || minute < 0 || minute > 59) {
      log("Scheduler save failed: minute must be 0-59.");
      return;
    }
  }

  try {
    const data = await apiRequest("/config/scheduler", {
      method: "PUT",
      body: JSON.stringify({
        enabled: Boolean(ui.schedulerEnabled.checked),
        frequency,
        day_of_week: Number.isFinite(dayOfWeek) ? dayOfWeek : 1,
        hour: Number.isFinite(hour) ? hour : 2,
        minute: Number.isFinite(minute) ? minute : 0,
        interval_minutes: Number.isFinite(intervalMinutes)
          ? intervalMinutes
          : 1440,
      }),
    });
    const persistedFrequency = String(data.frequency || frequency).toLowerCase();
    ui.schedulerEnabled.checked = Boolean(data.enabled);
    ui.schedulerFrequency.value = persistedFrequency;
    ui.schedulerDayOfWeek.value = String(data.day_of_week ?? 1);
    ui.schedulerTime.value = toTimeValue(data.hour ?? 2, data.minute ?? 0);
    ui.schedulerIntervalMinutes.value = String(data.interval_minutes ?? 1440);
    ui.schedulerLastRunInfo.textContent = `Last run: ${fmtDate(
      data.last_run_at
    )}`;
    applySchedulerFrequencyVisibility(persistedFrequency);
    log(
      `Scheduler configuration saved (${data.enabled ? "enabled" : "disabled"}, ${data.frequency}).`
    );
  } catch (error) {
    log(`Scheduler save failed: ${error.message}`);
  }
}

function renderUsers(users) {
  userIndex.clear();
  if (!Array.isArray(users) || users.length === 0) {
    ui.usersBody.innerHTML =
      "<tr><td colspan='6' class='muted'>No users found</td></tr>";
    return;
  }

  ui.usersBody.innerHTML = users
    .map((row) => {
      const userId = String(row.id || "");
      const username = String(row.username || "");
      const canDelete = Boolean(username) && username !== currentUsername;
      userIndex.set(userId, row);
      return `
      <tr>
        <td>${escapeHtml(username)}</td>
        <td>${escapeHtml(row.name || "")}</td>
        <td>${escapeHtml(row.surname || "")}</td>
        <td>${escapeHtml(row.email || "")}</td>
        <td>${row.is_active ? "Active" : "Disabled"}</td>
        <td class="users-actions">
          <button type="button" class="edit-user-btn btn btn-sm btn-outline-primary" data-user-id="${escapeHtml(
            userId
          )}" aria-label="Edit user ${escapeHtml(username)}" title="Edit user ${escapeHtml(username)}">Edit</button>
          ${
            canDelete
              ? `<button type="button" class="delete-user-btn btn btn-sm btn-outline-danger" data-user-id="${escapeHtml(
                  userId
                )}" data-username="${escapeHtml(username)}" aria-label="Delete user ${escapeHtml(username)}" title="Delete user ${escapeHtml(username)}">Delete</button>`
              : "<span class='muted'>Current user</span>"
          }
        </td>
      </tr>
    `
    })
    .join("");
}

function closeEditUserPanel() {
  ui.editUserPanel.classList.add("hidden");
  ui.editUserForm.reset();
  ui.editUserId.value = "";
}

function openEditUserPanel(userId) {
  const row = userIndex.get(String(userId || ""));
  if (!row) {
    log("Edit user failed: user data not found.");
    return;
  }
  ui.editUserId.value = String(row.id || "");
  ui.editUserUsername.value = String(row.username || "");
  ui.editUserName.value = String(row.name || "");
  ui.editUserSurname.value = String(row.surname || "");
  ui.editUserEmail.value = String(row.email || "");
  ui.editUserIsActive.checked = Boolean(row.is_active);
  ui.editUserPanel.classList.remove("hidden");
}

function eventLevelBadge(level) {
  const raw = String(level || "info").trim().toLowerCase();
  const value = raw || "info";
  const sevClass =
    value === "error"
      ? "sev-bad"
      : value === "warn"
        ? "sev-warn"
        : value === "debug"
          ? "sev-debug"
          : "sev-good";
  return `<span class="sev-badge ${sevClass}">${escapeHtml(value)}</span>`;
}

function renderEventLogs(rows) {
  if (!Array.isArray(rows) || rows.length === 0) {
    ui.eventLogBody.innerHTML =
      "<tr><td colspan='5' class='muted'>No event history found</td></tr>";
    return;
  }

  ui.eventLogBody.innerHTML = rows
    .map(
      (row) => `
      <tr>
        <td>${escapeHtml(fmtDate(row.created_at))}</td>
        <td>${escapeHtml(row.username || "-")}</td>
        <td>${escapeHtml(row.source || "-")}</td>
        <td>${eventLevelBadge(row.level)}</td>
        <td>${escapeHtml(row.message || "")}</td>
      </tr>
    `
    )
    .join("");
}

async function refreshEventLogs() {
  try {
    pagination.eventLogs.pageSize = getPageSize(ui.eventLogPageSize, 15);
    const limit = pagination.eventLogs.pageSize;
    const offset =
      limit > 0 ? (pagination.eventLogs.page - 1) * limit : 0;
    const selectedLevel = String(ui.eventLogLevelFilter?.value || "all")
      .trim()
      .toLowerCase();
    const query = new URLSearchParams();
    query.set("limit", String(limit));
    query.set("offset", String(offset));
    query.set("level", selectedLevel || "all");
    const data = await apiRequest(`/admin/event-logs?${query.toString()}`, {
      method: "GET",
    });
    pagination.eventLogs.total = data.total ?? 0;
    updatePaginationUI("eventLogs", {
      prevBtn: ui.eventLogPrevBtn,
      nextBtn: ui.eventLogNextBtn,
      pageInfo: ui.eventLogPageInfo,
    });
    renderEventLogs(data.items || []);
  } catch (error) {
    ui.eventLogBody.innerHTML =
      "<tr><td colspan='5' class='muted'>Failed to load event history</td></tr>";
    log(`Event history load failed: ${error.message}`, { persist: false });
  }
}

async function refreshUsers() {
  try {
    const data = await apiRequest("/admin/users", { method: "GET" });
    renderUsers(data);
    log(`Loaded ${Array.isArray(data) ? data.length : 0} users.`);
  } catch (error) {
    ui.usersBody.innerHTML =
      "<tr><td colspan='5' class='muted'>Failed to load users</td></tr>";
    log(`User list load failed: ${error.message}`);
  }
}

async function createUser(event) {
  event.preventDefault();
  const payload = {
    username: ui.userUsername.value.trim(),
    password: ui.userPassword.value,
    name: ui.userName.value.trim(),
    surname: ui.userSurname.value.trim(),
    email: ui.userEmail.value.trim(),
    is_active: true,
  };

  if (!payload.username || !payload.password) {
    log("Create user failed: username and password are required.");
    return;
  }

  try {
    await apiRequest("/admin/users", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    log(`User created: ${payload.username}`);
    ui.userForm.reset();
    await refreshUsers();
  } catch (error) {
    log(`Create user failed: ${error.message}`);
  }
}

async function deleteUser(userId, username) {
  if (!userId) {
    return;
  }
  const label = username || userId;
  if (!window.confirm(`Delete user '${label}'?`)) {
    return;
  }

  try {
    await apiRequest(`/admin/users/${encodeURIComponent(userId)}`, {
      method: "DELETE",
    });
    log(`User deleted: ${label}`);
    await refreshUsers();
  } catch (error) {
    log(`Delete user failed: ${error.message}`);
  }
}

async function saveUserEdit(event) {
  event.preventDefault();
  const userId = ui.editUserId.value.trim();
  if (!userId) {
    log("Save user failed: user id missing.");
    return;
  }
  const payload = {
    name: ui.editUserName.value.trim(),
    surname: ui.editUserSurname.value.trim(),
    email: ui.editUserEmail.value.trim(),
    is_active: Boolean(ui.editUserIsActive.checked),
  };

  try {
    await apiRequest(`/admin/users/${encodeURIComponent(userId)}`, {
      method: "PUT",
      body: JSON.stringify(payload),
    });
    log(`User updated: ${ui.editUserUsername.value}`);
    closeEditUserPanel();
    await refreshUsers();
  } catch (error) {
    log(`Update user failed: ${error.message}`);
  }
}

async function importTargetsCsv(event) {
  event.preventDefault();
  const file = ui.targetsCsvFile?.files?.[0];
  if (!file) {
    log("CSV import failed: select a CSV file first.");
    return;
  }

  const formData = new FormData();
  formData.append("file", file, file.name || "targets.csv");

  try {
    const data = await apiRequest("/admin/targets/import-csv", {
      method: "POST",
      body: formData,
    });
    log(
      `CSV import done: added ${data.added ?? 0}; already in DB ${data.already_in_db ?? 0}; duplicates in file ${data.duplicates_in_file ?? 0}; invalid rows ${data.invalid_rows_count ?? 0}.`
    );
    if ((data.invalid_rows_count ?? 0) > 0) {
      const preview = Array.isArray(data.invalid_rows)
        ? data.invalid_rows
            .slice(0, 3)
            .map((r) => `line ${r.line}: ${r.reason}`)
            .join(" | ")
        : "";
      if (preview) {
        log(`CSV invalid row examples: ${preview}`);
      }
    }
    ui.bulkTargetsForm.reset();
    await refreshTargets();
    await loadDashboard();
  } catch (error) {
    log(`CSV import failed: ${error.message}`);
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
    refreshUsers(),
    loadProxyConfig(),
    loadSchedulerConfig(),
    loadSmtpConfig(),
  ]);
}

ui.targetForm.addEventListener("submit", addTarget);
ui.refreshTargetsBtn.addEventListener("click", refreshTargets);
ui.refreshSpoofableBtn.addEventListener("click", refreshSpoofable);
ui.exportSpoofableCsvBtn.addEventListener("click", exportSpoofableCsv);
ui.exportSpoofablePdfBtn.addEventListener("click", exportSpoofablePdf);
ui.runReportsBtn.addEventListener("click", runReports);
ui.refreshReportsBtn.addEventListener("click", refreshReports);
ui.sendReportsEmailBtn.addEventListener("click", openReportEmailPanel);
ui.reportEmailForm.addEventListener("submit", sendReportEmailFromPanel);
ui.cancelReportEmailBtn.addEventListener("click", closeReportEmailPanel);
ui.reportEmailPanel.addEventListener("click", (event) => {
  if (event.target === ui.reportEmailPanel) {
    closeReportEmailPanel();
  }
});
ui.exportReportsCsvBtn.addEventListener("click", exportReportsCsv);
ui.exportReportsPdfBtn.addEventListener("click", exportReportsPdf);
ui.refreshJobsBtn.addEventListener("click", refreshJobs);
ui.loginForm.addEventListener("submit", login);
ui.loginOidcBtn.addEventListener("click", () => {
  if (!oidcEnabled) {
    return;
  }
  startOidcLogin();
});
ui.logoutBtn.addEventListener("click", logout);
ui.authConfigForm.addEventListener("submit", saveAuthConfig);
ui.reloadAuthBtn.addEventListener("click", loadAuthConfig);
ui.proxyForm.addEventListener("submit", saveProxyConfig);
ui.reloadProxyBtn.addEventListener("click", loadProxyConfig);
ui.schedulerForm.addEventListener("submit", saveSchedulerConfig);
ui.reloadSchedulerBtn.addEventListener("click", loadSchedulerConfig);
ui.schedulerFrequency.addEventListener("change", () => {
  applySchedulerFrequencyVisibility(ui.schedulerFrequency.value);
});
ui.smtpForm.addEventListener("submit", saveSmtpConfig);
ui.reloadSmtpBtn.addEventListener("click", loadSmtpConfig);
ui.smtpUseAuth.addEventListener("change", () => {
  applySmtpAuthVisibility(ui.smtpUseAuth.checked);
});
ui.userForm.addEventListener("submit", createUser);
ui.purgeTargetsBtn.addEventListener("click", purgeTargetsData);
ui.purgeDnsBtn.addEventListener("click", purgeDnsData);
ui.purgeJobsAdminBtn.addEventListener("click", purgeJobsData);
ui.editUserForm.addEventListener("submit", saveUserEdit);
ui.cancelEditUserBtn.addEventListener("click", closeEditUserPanel);
ui.editTargetForm.addEventListener("submit", saveTargetEdit);
ui.cancelEditTargetBtn.addEventListener("click", closeEditTargetPanel);
ui.editTargetPanel.addEventListener("click", (event) => {
  if (event.target === ui.editTargetPanel) {
    closeEditTargetPanel();
  }
});
ui.refreshUsersBtn.addEventListener("click", refreshUsers);
ui.bulkTargetsForm.addEventListener("submit", importTargetsCsv);
ui.refreshEventLogBtn.addEventListener("click", refreshEventLogs);
ui.adminNavItems.forEach((item) => {
  item.addEventListener("click", () => {
    activateAdminPage(item.dataset.adminPage || "adminUsersPage");
  });
});
ui.adminNavToggleBtn.addEventListener("click", () => {
  ui.adminShell.classList.toggle("admin-nav-collapsed");
  updateAdminNavToggleState();
});
window.matchMedia(MOBILE_ADMIN_NAV_QUERY).addEventListener("change", (event) => {
  if (!ui.adminShell) {
    return;
  }
  if (event.matches) {
    ui.adminShell.classList.add("admin-nav-collapsed");
  } else {
    ui.adminShell.classList.remove("admin-nav-collapsed");
  }
  updateAdminNavToggleState();
});
ui.usersBody.addEventListener("click", (event) => {
  const editBtn = event.target.closest(".edit-user-btn");
  if (editBtn) {
    openEditUserPanel(editBtn.dataset.userId);
    return;
  }
  const deleteBtn = event.target.closest(".delete-user-btn");
  if (!deleteBtn) {
    return;
  }
  deleteUser(deleteBtn.dataset.userId, deleteBtn.dataset.username);
});

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
ui.reportsPageSize.addEventListener("change", () => {
  pagination.reports.page = 1;
  refreshReports();
});
ui.eventLogPageSize.addEventListener("change", () => {
  pagination.eventLogs.page = 1;
  refreshEventLogs();
});
ui.eventLogLevelFilter.addEventListener("change", () => {
  pagination.eventLogs.page = 1;
  refreshEventLogs();
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
ui.reportsPrevBtn.addEventListener("click", () => {
  pagination.reports.page = Math.max(1, pagination.reports.page - 1);
  refreshReports();
});
ui.reportsNextBtn.addEventListener("click", () => {
  pagination.reports.page += 1;
  refreshReports();
});
ui.reportsBody.addEventListener("change", (event) => {
  const checkbox = event.target.closest(".report-row-select");
  if (!checkbox) {
    return;
  }
  const targetId = String(checkbox.dataset.targetId || "").trim();
  if (!targetId) {
    return;
  }
  if (checkbox.checked) {
    selectedReportTargetIds.add(targetId);
  } else {
    selectedReportTargetIds.delete(targetId);
  }
  syncReportsSelectAll();
});
ui.reportsSelectAll.addEventListener("change", () => {
  const shouldSelect = Boolean(ui.reportsSelectAll.checked);
  currentReportItems.forEach((row) => {
    const key = reportSelectionKey(row);
    if (!key) {
      return;
    }
    if (shouldSelect) {
      selectedReportTargetIds.add(key);
    } else {
      selectedReportTargetIds.delete(key);
    }
  });
  renderReportRows(currentReportItems);
});
ui.eventLogPrevBtn.addEventListener("click", () => {
  pagination.eventLogs.page = Math.max(1, pagination.eventLogs.page - 1);
  refreshEventLogs();
});
ui.eventLogNextBtn.addEventListener("click", () => {
  pagination.eventLogs.page += 1;
  refreshEventLogs();
});

ui.menuItems.forEach((item) => {
  item.addEventListener("click", () => activateView(item.dataset.view));
});
ui.reportTypeSelect.addEventListener("change", () => {
  pagination.reports.page = 1;
  selectedReportTargetIds.clear();
  currentReportItems = [];
  currentReportId = String(ui.reportTypeSelect.value || "");
  syncReportsSelectAll();
  if (ui.reportsBody) {
    ui.reportsBody.innerHTML =
      "<tr><td colspan='6' class='muted'>Report selected. Click 'Run Report'.</td></tr>";
  }
});

ui.targetsBody.addEventListener("click", (event) => {
  const editBtn = event.target.closest(".edit-target-btn");
  if (editBtn) {
    openEditTargetPanel(
      editBtn.dataset.targetId,
      editBtn.dataset.hostname,
      editBtn.dataset.port
    );
    return;
  }

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

ui.jobResultsPanel.addEventListener("click", (event) => {
  const btn = event.target.closest(".open-jobs-btn");
  if (!btn) {
    return;
  }
  activateView("jobsView");
});
document.addEventListener("keydown", (event) => {
  if (event.key !== "Escape") {
    return;
  }
  if (ui.reportEmailPanel && !ui.reportEmailPanel.classList.contains("hidden")) {
    closeReportEmailPanel();
    return;
  }
  if (ui.editTargetPanel && !ui.editTargetPanel.classList.contains("hidden")) {
    closeEditTargetPanel();
  }
});

const persisted = loadPersistedSession();
const oidcHashPayload = readAuthHashPayload();
if (oidcHashPayload?.appToken) {
  setToken(oidcHashPayload.appToken, oidcHashPayload.username);
  log(`OpenID login successful for ${oidcHashPayload.username}.`);
} else if (oidcHashPayload?.oidcError) {
  setToken("");
  const extra = oidcHashPayload.oidcErrorDescription
    ? ` (${oidcHashPayload.oidcErrorDescription})`
    : "";
  log(`OpenID login failed: ${oidcHashPayload.oidcError}${extra}`);
} else {
  setToken(persisted.token, persisted.username);
}
if (ui.adminShell && isMobileAdminLayout()) {
  ui.adminShell.classList.add("admin-nav-collapsed");
}
updateAdminNavToggleState();
updateModalBodyLock();
if (accessToken) {
  refreshAll();
}
loadAuthMethod();
setInterval(() => {
  refreshAll();
}, 60000);
log("UI loaded.");
