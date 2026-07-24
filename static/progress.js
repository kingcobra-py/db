// Dashboard polling for job progress, scan metrics, logs, and extracted credentials.
// Externalized to remain compatible with a strict script-src 'self' CSP.
(function () {
  "use strict";

  var POLL_MS = 1500;
  var ACTIVE = { pending: true, running: true };

  function human(bytes) {
    var n = Number(bytes) || 0;
    var units = ["B", "KB", "MB", "GB"];
    var index = 0;
    while (n >= 1024 && index < units.length - 1) {
      n /= 1024;
      index += 1;
    }
    return n.toFixed(1) + " " + units[index];
  }

  function activeRows() {
    return Array.prototype.filter.call(document.querySelectorAll("tr[data-job-id]"), function (row) {
      return Boolean(ACTIVE[row.getAttribute("data-job-status")]);
    });
  }

  function renderProgress(row, data) {
    var box = row.querySelector("[data-progress]");
    if (!box) return;

    var isDownloading = data.stage === "downloading" && Number(data.total) > 0;
    box.hidden = !isDownloading;
    if (!isDownloading) return;

    var percent = Math.min(100, Math.max(0, Number(data.percent) || 0));
    var fill = box.querySelector(".dl-bar > i");
    var label = box.querySelector(".dl-label");
    if (fill) fill.style.width = percent + "%";
    if (label) {
      var filename = data.file || "archive";
      var position = data.index && data.count ? " (" + data.index + "/" + data.count + ")" : "";
      label.textContent = "↓ " + filename + position + " — " + percent + "%  " + human(data.done) + " / " + human(data.total);
    }
  }

  function pollRow(row) {
    var id = row.getAttribute("data-job-id");
    return fetch("/jobs/" + encodeURIComponent(id) + "/progress", {
      credentials: "same-origin",
      headers: { Accept: "application/json" }
    }).then(function (response) {
      if (!response.ok) throw new Error("HTTP " + response.status);
      return response.json();
    }).then(function (data) {
      renderProgress(row, data);
      var originalStatus = row.getAttribute("data-job-status");
      return data.status && data.status !== originalStatus && data.stage !== "downloading" ? "changed" : "ok";
    }).catch(function () {
      return "ok";
    });
  }

  function pollJobs() {
    var rows = activeRows();
    if (!rows.length) return;
    Promise.all(rows.map(pollRow)).then(function (results) {
      if (results.indexOf("changed") !== -1) {
        window.location.reload();
        return;
      }
      window.setTimeout(pollJobs, POLL_MS);
    });
  }

  function loadScanMetrics() {
    document.querySelectorAll('tr[data-job-status="completed"]').forEach(function (row) {
      var jobId = row.getAttribute("data-job-id");
      fetch("/jobs/" + encodeURIComponent(jobId) + "/scan-metrics", {
        credentials: "same-origin",
        headers: { Accept: "application/json" }
      }).then(function (response) {
        return response.ok ? response.json() : null;
      }).then(function (data) {
        if (!data) return;
        var files = document.getElementById("files-" + jobId);
        var findings = document.getElementById("findings-" + jobId);
        if (files) files.textContent = String(data.files_scanned ?? "—");
        if (findings) findings.textContent = String(data.findings ?? "—");
      }).catch(function () {});
    });
  }

  function startJobPolling() {
    pollJobs();
    loadScanMetrics();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", startJobPolling);
  else startJobPolling();
})();

(function () {
  "use strict";
  var LOG_POLL_MS = 5000;

  function renderLogs(logs) {
    var container = document.getElementById("logs-list");
    if (!container) return;
    container.replaceChildren();

    if (!Array.isArray(logs) || logs.length === 0) {
      var empty = document.createElement("div");
      empty.className = "empty";
      empty.textContent = "No logs yet.";
      container.appendChild(empty);
      return;
    }

    logs.forEach(function (log) {
      var row = document.createElement("div");
      row.className = "log-entry log-" + (log.level || "info");
      var date = new Date(log.timestamp);
      var timestamp = Number.isNaN(date.getTime()) ? "--:--:--" : date.toLocaleTimeString();
      row.textContent = timestamp + " [" + String(log.level || "info").toUpperCase() + "] " + String(log.message || "");
      container.appendChild(row);
    });
  }

  function fetchLogs() {
    fetch("/logs", {
      credentials: "same-origin",
      headers: { Accept: "application/json" }
    }).then(function (response) {
      return response.ok ? response.json() : null;
    }).then(function (logs) {
      if (logs) renderLogs(logs);
    }).catch(function () {}).finally(function () {
      window.setTimeout(fetchLogs, LOG_POLL_MS);
    });
  }

  function start() {
    if (document.getElementById("logs-list")) fetchLogs();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start);
  else start();
})();

(function () {
  "use strict";

  function setCredentialActions(enabled) {
    var exportButton = document.getElementById("export-btn");
    var clearButton = document.getElementById("clear-btn");
    if (exportButton) {
      exportButton.classList.toggle("is-disabled", !enabled);
      exportButton.setAttribute("aria-disabled", enabled ? "false" : "true");
      exportButton.tabIndex = enabled ? 0 : -1;
    }
    if (clearButton) clearButton.disabled = !enabled;
  }

  function renderCredentials(credentials) {
    var container = document.getElementById("credentials-list");
    if (!container) return;
    container.replaceChildren();

    if (!Array.isArray(credentials) || credentials.length === 0) {
      var empty = document.createElement("div");
      empty.className = "empty";
      empty.textContent = "No credentials yet.";
      container.appendChild(empty);
      setCredentialActions(false);
      return;
    }

    credentials.forEach(function (credential) {
      var row = document.createElement("div");
      row.className = "credential-row";
      var code = document.createElement("code");
      var secret = String(credential.secret_key || "");
      var shortened = secret.length > 16 ? secret.slice(0, 16) + "…" : secret;
      code.textContent = String(credential.access_key || "") + ":" + shortened + ":" + String(credential.region || "");
      row.appendChild(code);
      container.appendChild(row);
    });
    setCredentialActions(true);
  }

  function loadCredentials() {
    if (!document.getElementById("credentials-list")) return;
    fetch("/credentials", {
      credentials: "same-origin",
      headers: { Accept: "application/json" }
    }).then(function (response) {
      return response.ok ? response.json() : null;
    }).then(function (credentials) {
      if (credentials) renderCredentials(credentials);
    }).catch(function () {});
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", loadCredentials);
  else loadCredentials();
})();
