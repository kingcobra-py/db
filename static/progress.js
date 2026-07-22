// Download-progress poller for the Archive Scanner dashboard.
// Loaded as an external script to comply with the CSP (script-src 'self').
// It finds job rows that are still active, polls /jobs/<id>/progress, and
// updates a per-row progress bar. When a job leaves the download stage it
// reloads the page so the rest of the row (status, output links) refreshes.
(function () {
  "use strict";

  var POLL_MS = 1500;
  var ACTIVE = { pending: 1, running: 1 }; // statuses worth polling

  function human(n) {
    if (!n || n < 0) n = 0;
    var units = ["B", "KB", "MB", "GB"], i = 0;
    while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
    return n.toFixed(1) + " " + units[i];
  }

  function rows() {
    var out = [], nodes = document.querySelectorAll("tr[data-job-id]");
    for (var i = 0; i < nodes.length; i++) {
      var status = nodes[i].getAttribute("data-job-status");
      if (ACTIVE[status]) out.push(nodes[i]);
    }
    return out;
  }

  function render(row, data) {
    var box = row.querySelector("[data-progress]");
    if (!box) return;
    var isDownloading = data.stage === "downloading" && data.total > 0;
    if (!isDownloading) { box.hidden = true; return; }
    box.hidden = false;
    var fill = box.querySelector(".dl-bar > i");
    var label = box.querySelector(".dl-label");
    if (fill) fill.style.width = data.percent + "%";
    if (label) {
      var name = data.file || "file";
      var pos = (data.index && data.count) ? (" (" + data.index + "/" + data.count + ")") : "";
      label.textContent = "\u2b07 " + name + pos + " \u2014 " + data.percent + "%  " +
        human(data.done) + " / " + human(data.total);
    }
  }

  function pollOne(row) {
    var id = row.getAttribute("data-job-id");
    return fetch("/jobs/" + encodeURIComponent(id) + "/progress", {
      credentials: "same-origin", headers: { "Accept": "application/json" }
    }).then(function (r) {
      if (!r.ok) throw new Error("http " + r.status);
      return r.json();
    }).then(function (data) {
      render(row, data);
      // If the server now reports a status this row didn't start with, the job
      // moved on (queued/completed/failed): refresh once to update the table.
      var started = row.getAttribute("data-job-status");
      if (data.status && data.status !== started && data.stage !== "downloading") {
        return "changed";
      }
      return "ok";
    }).catch(function () { return "ok"; });
  }

  function tick() {
    var active = rows();
    if (!active.length) return; // nothing to poll; stop the loop
    Promise.all(active.map(pollOne)).then(function (results) {
      if (results.indexOf("changed") !== -1) {
        window.location.reload();
        return;
      }
      window.setTimeout(tick, POLL_MS);
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", tick);
  } else {
    tick();
  }

  // Load scan metrics for completed jobs
  function loadScanMetrics() {
    document.querySelectorAll('tr[data-job-status="completed"]').forEach(function(row) {
      var jobId = row.getAttribute('data-job-id');
      fetch('/jobs/' + encodeURIComponent(jobId) + '/scan-metrics', {
        credentials: 'same-origin',
        headers: { 'Accept': 'application/json' }
      }).then(function (r) {
        if (!r.ok) return;
        return r.json();
      }).then(function (data) {
        if (!data) return;
        var filesEl = document.getElementById('files-' + jobId);
        var findingsEl = document.getElementById('findings-' + jobId);
        if (filesEl) filesEl.textContent = data.files_scanned;
        if (findingsEl) findingsEl.textContent = data.findings;
      }).catch(function () {});
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", loadScanMetrics);
  } else {
    loadScanMetrics();
  }
})();

// Log poller for activity logs
(function logPoller() {
  var LOG_POLL_MS = 5000;
  var lastLogTime = 0;

  function fetchLogs() {
    fetch('/logs', {
      credentials: 'same-origin',
      headers: { 'Accept': 'application/json' }
    }).then(function(r) {
      if (!r.ok) return;
      return r.json();
    }).then(function(logs) {
      if (!logs || !Array.isArray(logs)) return;
      var container = document.getElementById('logs-list');
      if (!container) return;

      container.innerHTML = '';
      logs.forEach(function(log) {
        var row = document.createElement('div');
        row.className = 'log-entry log-' + (log.level || 'info');
        var ts = new Date(log.timestamp).toLocaleTimeString();
        row.textContent = ts + ' [' + (log.level || 'info').toUpperCase() + '] ' + log.message;
        container.appendChild(row);
      });

      if (logs.length === 0) {
        container.innerHTML = '<div class="empty">No logs yet.</div>';
      }
    }).catch(function() {
      // Silently fail and retry
    }).finally(function() {
      window.setTimeout(fetchLogs, LOG_POLL_MS);
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", fetchLogs);
  } else {
    fetchLogs();
  }
})();

// Credentials poller
(function() {
  function load() {
    fetch('/credentials', { credentials: 'same-origin', headers: {'Accept': 'application/json'} })
    .then(r => r.ok ? r.json() : null).then(creds => {
      if (!creds) return;
      const c = document.getElementById('credentials-list');
      if (!c) return;
      if (creds.length === 0) {
        c.innerHTML = '<div class="empty">No credentials yet.</div>';
        document.getElementById('export-btn').disabled = true;
        document.getElementById('clear-btn').disabled = true;
        return;
      }
      c.innerHTML = creds.map(cr => `<div class="credential-row">${cr.access_key}:${cr.secret_key}:${cr.region}</div>`).join('');
      document.getElementById('export-btn').disabled = false;
      document.getElementById('clear-btn').disabled = false;
    });
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", load);
  else load();
})();
