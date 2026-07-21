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
})();
