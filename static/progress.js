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

  function displayPhase(data) {
    var stage = String(data.stage || "").toLowerCase();
    if (data.status === "completed") return "completed";
    if (data.status === "failed") return "failed";
    if (stage === "queued" || stage === "fetching" || stage === "downloading") return "downloading";
    if (stage === "extracting" || stage === "scanning" || data.status === "running") return "extracting";
    return "pending";
  }

  function phaseLabel(phase) {
    if (phase === "completed") return "Successful";
    if (phase === "failed") return "Failed";
    if (phase === "downloading") return "Downloading";
    if (phase === "extracting") return "Extracting";
    return "Pending";
  }

  function updateStatus(row, data) {
    var badge = row.querySelector(".status");
    if (!badge) return;
    var phase = displayPhase(data);
    badge.className = "status " + phase;
    badge.textContent = phaseLabel(phase);
    row.setAttribute("data-job-status", data.status || row.getAttribute("data-job-status") || "");
    row.setAttribute("data-job-stage", String(data.stage || "").toLowerCase());
  }

  function renderProgress(row, data) {
    updateStatus(row, data);
    var box = row.querySelector("[data-progress]");
    if (!box) return;

    var stage = String(data.stage || "").toLowerCase();
    var phase = displayPhase(data);
    var active =
      phase === "pending" ||
      phase === "downloading" ||
      phase === "extracting" ||
      data.status === "pending" ||
      data.status === "running";
    if (!active) {
      box.hidden = true;
      return;
    }

    box.hidden = false;
    box.classList.remove("is-complete", "is-failed");

    var fill = box.querySelector(".dl-bar > i");
    var label = box.querySelector(".dl-label");
    var percent = Math.max(0, Math.min(100, Number(data.percent) || 0));
    var indeterminate =
      stage === "queued" ||
      stage === "fetching" ||
      stage === "extracting" ||
      stage === "scanning" ||
      !(Number(data.total) > 0);
    box.classList.toggle("is-indeterminate", indeterminate);
    if (fill && !indeterminate) fill.style.width = percent + "%";

    if (!label) return;
    if (stage === "queued") {
      label.textContent = "Pending — waiting for download worker";
      return;
    }
    if (stage === "fetching") {
      label.textContent = "Downloading — fetching Telegram message…";
      return;
    }
    var filename = data.file || "file";
    var position = data.index && data.count ? " (" + data.index + "/" + data.count + ")" : "";
    if (stage === "downloading" && Number(data.total) > 0) {
      label.textContent =
        "Downloading — " + filename + position + " · " + percent + "% · " + human(data.done) + " / " + human(data.total);
      return;
    }
    if (stage === "downloading") {
      label.textContent = "Downloading — media…";
      return;
    }
    if (stage === "scanning") {
      label.textContent = "Extracting — scanning credentials…";
      return;
    }
    if (stage === "extracting" || data.status === "running") {
      label.textContent = "Extracting — unpacking archive…";
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

  function sessionMeta(session) {
    var bits = [];
    if (session.username) bits.push("@" + session.username);
    bits.push(session.online ? "Online" : "Offline");
    if (session.active_jobs) bits.push(session.active_jobs + " active");
    if (session.last_error) bits.push(session.last_error);
    return bits.join(" · ");
  }

  function updateSessions(sessions) {
    var chips = document.querySelector("[data-session-chips]");
    var list = document.querySelector("[data-session-list]");
    if (!chips && !list) return;

    if (chips) {
      if (!sessions.length) {
        chips.innerHTML =
          '<span class="session-chip is-empty"><i class="session-dot is-offline" aria-hidden="true"></i><span class="session-name">No sessions</span></span>';
      } else {
        chips.innerHTML = sessions
          .map(function (session) {
            var title = session.last_error
              ? session.last_error
              : session.online
                ? "Online"
                : "Offline";
            var cls = session.online ? "is-online" : "is-offline";
            var name = session.display_name || session.label || "Account";
            return (
              '<span class="session-chip" data-session-id="' +
              String(session.id || "") +
              '" title="' +
              String(title).replace(/"/g, "&quot;") +
              '"><i class="session-dot ' +
              cls +
              '" aria-hidden="true"></i><span class="session-name">' +
              String(name).replace(/</g, "&lt;") +
              "</span></span>"
            );
          })
          .join("");
      }
    }

    if (!list) return;
    sessions.forEach(function (session) {
      var row = list.querySelector('[data-session-id="' + session.id + '"]');
      if (!row) return;
      var dot = row.querySelector(".session-dot");
      var name = row.querySelector("[data-session-name]");
      var small = row.querySelector("small");
      if (dot) {
        dot.classList.toggle("is-online", !!session.online);
        dot.classList.toggle("is-offline", !session.online);
      }
      if (name) name.textContent = session.display_name || session.label || "Account";
      if (small) small.textContent = sessionMeta(session);
    });
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
        updateSessions(data.sessions || []);
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
