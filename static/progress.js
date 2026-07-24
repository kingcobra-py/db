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

  function updateStatus(row, data) {
    var badge = row.querySelector(".status");
    if (!badge) return;
    var stage = data.stage || "";
    var state =
      data.status === "completed"
        ? "completed"
        : data.status === "failed"
          ? "failed"
          : data.status === "running" || stage === "fetching" || stage === "downloading"
            ? "running"
            : "pending";
    badge.className = "status " + state;
    badge.textContent = state === "completed" ? "Successful" : state.charAt(0).toUpperCase() + state.slice(1);
  }

  function renderProgress(row, data) {
    updateStatus(row, data);
    var box = row.querySelector("[data-progress]");
    if (!box) return;

    var stage = data.stage || "";
    var active =
      data.status === "pending" ||
      data.status === "running" ||
      stage === "downloading" ||
      stage === "queued" ||
      stage === "fetching";
    if (!active) return;

    box.hidden = false;
    box.classList.remove("is-complete", "is-failed");

    var fill = box.querySelector(".dl-bar > i");
    var label = box.querySelector(".dl-label");
    var percent = Math.max(0, Math.min(100, Number(data.percent) || 0));
    var indeterminate = stage === "queued" || stage === "fetching" || !(Number(data.total) > 0);
    box.classList.toggle("is-indeterminate", indeterminate);
    if (fill && !indeterminate) fill.style.width = percent + "%";

    if (!label) return;
    if (stage === "queued") {
      label.textContent = "Pending — waiting for download worker";
      return;
    }
    if (stage === "fetching") {
      label.textContent = "Running — fetching Telegram message…";
      return;
    }
    var filename = data.file || "file";
    var position = data.index && data.count ? " (" + data.index + "/" + data.count + ")" : "";
    if (stage === "downloading" && Number(data.total) > 0) {
      label.textContent =
        "Running — " + filename + position + " · " + percent + "% · " + human(data.done) + " / " + human(data.total);
      return;
    }
    if (data.status === "running") {
      label.textContent = "Running — extracting and scanning…";
      return;
    }
    label.textContent = "Pending — waiting for extraction worker";
  }

  function pollRow(row) {
    var id = row.getAttribute("data-job-id");
    return fetch("/jobs/" + encodeURIComponent(id) + "/progress", {
      credentials: "same-origin",
      headers: { Accept: "application/json" }
    })
      .then(function (response) {
        if (!response.ok) throw new Error("HTTP " + response.status);
        return response.json();
      })
      .then(function (data) {
        renderProgress(row, data);
        var originalStatus = row.getAttribute("data-job-status");
        return data.status && data.status !== originalStatus ? "changed" : "ok";
      })
      .catch(function () {
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
      })
        .then(function (response) {
          return response.ok ? response.json() : null;
        })
        .then(function (data) {
          if (!data) return;
          var files = document.getElementById("files-" + jobId);
          var findings = document.getElementById("findings-" + jobId);
          if (files) files.textContent = String(data.files_scanned != null ? data.files_scanned : "—");
          if (findings) findings.textContent = String(data.findings != null ? data.findings : "—");
        })
        .catch(function () {});
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
      var level = String(log.level || "info").replace(/[^a-z-]/gi, "");
      row.className = "log-entry log-" + level;
      var date = new Date(log.timestamp);
      var timestamp = Number.isNaN(date.getTime()) ? "--:--:--" : date.toLocaleTimeString();
      row.textContent =
        timestamp + " [" + String(log.level || "info").toUpperCase() + "] " + String(log.message || "");
      container.appendChild(row);
    });
  }

  function fetchLogs() {
    fetch("/logs", {
      credentials: "same-origin",
      headers: { Accept: "application/json" }
    })
      .then(function (response) {
        return response.ok ? response.json() : null;
      })
      .then(function (logs) {
        if (logs) renderLogs(logs);
      })
      .catch(function () {})
      .finally(function () {
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
      code.textContent =
        String(credential.access_key || "") + ":" + shortened + ":" + String(credential.region || "unknown");
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
    })
      .then(function (response) {
        return response.ok ? response.json() : null;
      })
      .then(function (credentials) {
        if (credentials) renderCredentials(credentials);
      })
      .catch(function () {});
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", loadCredentials);
  else loadCredentials();
})();
