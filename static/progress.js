// Dashboard polling for job progress, scan metrics, logs, and extracted credentials.
// Externalized to remain compatible with a strict script-src 'self' CSP.
(function () {
  "use strict";

  var POLL_MS = 2000;
  var lastStats = null;

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

  function rowById(id) {
    return document.querySelector('tr[data-job-id="' + id + '"]');
  }

  function updateStatCards(stats) {
    if (!stats) return;
    ["pending", "running", "completed", "failed"].forEach(function (key) {
      var card = document.querySelector('.stat[data-job-filter="' + key + '"] strong');
      if (card && stats[key] != null) card.textContent = String(stats[key]);
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
    row.setAttribute("data-job-status", data.status || row.getAttribute("data-job-status") || "");
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
    if (!active) {
      box.hidden = true;
      return;
    }

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

  function statsChanged(next) {
    if (!lastStats || !next) return false;
    return (
      lastStats.pending !== next.pending ||
      lastStats.running !== next.running ||
      lastStats.completed !== next.completed ||
      lastStats.failed !== next.failed
    );
  }

  function pulse() {
    return fetch("/dashboard/pulse", {
      credentials: "same-origin",
      headers: { Accept: "application/json" }
    })
      .then(function (response) {
        if (!response.ok) throw new Error("HTTP " + response.status);
        return response.json();
      })
      .then(function (data) {
        updateStatCards(data.stats);
        var terminalChange = false;
        (data.jobs || []).forEach(function (job) {
          var row = rowById(job.id);
          if (!row) {
            // A newly active job is not in the current DOM slice — refresh once.
            terminalChange = true;
            return;
          }
          var previous = row.getAttribute("data-job-status");
          renderProgress(row, job);
          if (job.status && previous && job.status !== previous && (job.status === "completed" || job.status === "failed")) {
            terminalChange = true;
          }
        });
        if (lastStats && statsChanged(data.stats) && (data.stats.completed > lastStats.completed || data.stats.failed > lastStats.failed)) {
          terminalChange = true;
        }
        lastStats = data.stats || lastStats;
        if (terminalChange) {
          window.location.reload();
          return;
        }
        window.setTimeout(pulse, POLL_MS);
      })
      .catch(function () {
        window.setTimeout(pulse, POLL_MS * 2);
      });
  }

  function loadStorage() {
    var target = document.querySelector("[data-storage-value]");
    if (!target) return;
    fetch("/storage-info", {
      credentials: "same-origin",
      headers: { Accept: "application/json" }
    })
      .then(function (response) {
        return response.ok ? response.json() : null;
      })
      .then(function (data) {
        if (!data) return;
        target.innerHTML =
          String(data.total_human_readable || human(data.total_bytes || 0)) + " <small>used</small>";
      })
      .catch(function () {});
  }

  function startJobPolling() {
    var pending = document.querySelector('.stat[data-job-filter="pending"] strong');
    var running = document.querySelector('.stat[data-job-filter="running"] strong');
    var completed = document.querySelector('.stat[data-job-filter="completed"] strong');
    var failed = document.querySelector('.stat[data-job-filter="failed"] strong');
    lastStats = {
      pending: pending ? Number(pending.textContent || 0) : 0,
      running: running ? Number(running.textContent || 0) : 0,
      completed: completed ? Number(completed.textContent || 0) : 0,
      failed: failed ? Number(failed.textContent || 0) : 0
    };
    loadStorage();
    pulse();
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
