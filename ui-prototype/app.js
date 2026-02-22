const ui = {
  menuItems: document.querySelectorAll(".menu-item"),
  viewTitle: document.getElementById("viewTitle"),
  loginForm: document.getElementById("loginForm"),
  authUsername: document.getElementById("authUsername"),
  authPassword: document.getElementById("authPassword"),
  loginBtn: document.getElementById("loginBtn"),
  logoutBtn: document.getElementById("logoutBtn"),
  authState: document.getElementById("authState"),
  refreshAllBtn: document.getElementById("refreshAllBtn"),
  metricHostsTotal: document.getElementById("metricHostsTotal"),
  metricHostsEnabled: document.getElementById("metricHostsEnabled"),
  metricScansTotal: document.getElementById("metricScansTotal"),
  metricScansRunning: document.getElementById("metricScansRunning"),
  metricResultsTotal: document.getElementById("metricResultsTotal"),
  metricDiffsTotal: document.getElementById("metricDiffsTotal"),
  lastScanAt: document.getElementById("lastScanAt"),
  targetForm: document.getElementById("targetForm"),
  hostname: document.getElementById("hostname"),
  port: document.getElementById("port"),
  refreshTargetsBtn: document.getElementById("refreshTargetsBtn"),
  targetsBody: document.getElementById("targetsBody"),
  refreshJobsBtn: document.getElementById("refreshJobsBtn"),
  jobsBody: document.getElementById("jobsBody"),
  jobResultsPanel: document.getElementById("jobResultsPanel"),
  logPanel: document.getElementById("logPanel"),
};

let accessToken = "";

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

function setToken(token) {
  accessToken = token || "";
  setAuthState(Boolean(accessToken), accessToken ? "Authenticated" : "Not authenticated");
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
      setAuthState(false, "Unauthorized");
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
    setToken(data.access_token);
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
    dashboardView: "Dashboard",
    targetsView: "Hosts / Targets",
    jobsView: "Jobs / Results",
  };

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

async function loadDashboard() {
  try {
    const data = await apiRequest("/dashboard/summary", { method: "GET" });
    setMetric(ui.metricHostsTotal, data.targets_total);
    setMetric(ui.metricHostsEnabled, data.targets_enabled);
    setMetric(ui.metricScansTotal, data.scans_total);
    setMetric(ui.metricScansRunning, data.scans_running);
    setMetric(ui.metricResultsTotal, data.results_total);
    setMetric(ui.metricDiffsTotal, data.diffs_total);
    ui.lastScanAt.textContent = data.last_scan_finished_at
      ? `Last completed scan: ${fmtDate(data.last_scan_finished_at)}`
      : "No completed scans yet.";
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
          <button data-target-id="${target.id}" class="run-scan-btn">Run Scan</button>
          <button data-target-id="${target.id}" class="delete-target-btn">Delete</button>
        </td>
      </tr>
    `
    )
    .join("");
}

function renderJobs(jobs) {
  if (!Array.isArray(jobs) || jobs.length === 0) {
    ui.jobsBody.innerHTML = "<tr><td colspan='6' class='muted'>No jobs found</td></tr>";
    return;
  }

  ui.jobsBody.innerHTML = jobs
    .map(
      (job) => `
      <tr>
        <td>${job.id ?? ""}</td>
        <td>${job.hostname ?? "Unknown"}:${job.port ?? "-"}</td>
        <td>${job.status ?? "-"}</td>
        <td>${fmtDate(job.started_at)}</td>
        <td>${fmtDate(job.finished_at)}</td>
        <td><button data-scan-id="${job.id}" class="view-job-btn">View Result</button></td>
      </tr>
    `
    )
    .join("");
}

async function refreshTargets() {
  try {
    const data = await apiRequest("/targets", { method: "GET" });
    renderTargets(data);
    log(`Loaded ${Array.isArray(data) ? data.length : 0} targets.`);
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
    const data = await apiRequest("/jobs?limit=100", { method: "GET" });
    renderJobs(data);
    log(`Loaded ${Array.isArray(data) ? data.length : 0} jobs.`);
  } catch (error) {
    log(`Job refresh failed: ${error.message}`);
  }
}

async function loadJobResults(scanId) {
  try {
    const data = await apiRequest(`/jobs/${scanId}/results`, { method: "GET" });
    ui.jobResultsPanel.textContent = JSON.stringify(data, null, 2);
    log(`Loaded results for job ${scanId}.`);
  } catch (error) {
    log(`Load job results failed: ${error.message}`);
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
  await Promise.all([loadDashboard(), refreshTargets(), refreshJobs()]);
}

ui.targetForm.addEventListener("submit", addTarget);
ui.refreshTargetsBtn.addEventListener("click", refreshTargets);
ui.refreshJobsBtn.addEventListener("click", refreshJobs);
ui.refreshAllBtn.addEventListener("click", refreshAll);
ui.loginForm.addEventListener("submit", login);
ui.logoutBtn.addEventListener("click", logout);

ui.menuItems.forEach((item) => {
  item.addEventListener("click", () => activateView(item.dataset.view));
});

ui.targetsBody.addEventListener("click", (event) => {
  const runBtn = event.target.closest(".run-scan-btn");
  if (runBtn) {
    runScan(runBtn.dataset.targetId);
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

log("Prototype loaded.");
