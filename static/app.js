(function () {
  "use strict";

  document.querySelectorAll("form[data-confirm]").forEach(function (form) {
    form.addEventListener("submit", function (event) {
      if (!window.confirm(form.dataset.confirm || "Continue?")) event.preventDefault();
    });
  });

  document.querySelectorAll(".refresh").forEach(function (button) {
    button.addEventListener("click", function () {
      button.classList.add("is-loading");
      window.location.reload();
    });
  });

  (function setupJobFilters() {
    var buttons = Array.prototype.slice.call(document.querySelectorAll("[data-job-filter]"));
    var rows = Array.prototype.slice.call(document.querySelectorAll("tr[data-job-id]"));
    var emptyFilter = document.querySelector("[data-filter-empty]");
    var emptyJobs = document.querySelector("[data-empty-jobs]");
    var hint = document.querySelector("[data-filter-hint]");
    if (!buttons.length) return;

    var active = "";

    function applyFilter(status) {
      active = status || "";
      var visible = 0;
      rows.forEach(function (row) {
        var match = !active || row.getAttribute("data-job-status") === active;
        row.hidden = !match;
        if (match) visible += 1;
      });
      buttons.forEach(function (button) {
        var selected = button.getAttribute("data-job-filter") === active;
        button.classList.toggle("is-active", selected);
        button.setAttribute("aria-pressed", selected ? "true" : "false");
      });
      if (emptyFilter) emptyFilter.hidden = !(active && visible === 0 && rows.length > 0);
      if (emptyJobs) emptyJobs.hidden = Boolean(active) || rows.length > 0;
      if (hint) {
        if (active) {
          hint.hidden = false;
          hint.textContent = "Showing " + active + " jobs only. Tap the card again to clear.";
        } else {
          hint.hidden = true;
          hint.textContent = "";
        }
      }
    }

    buttons.forEach(function (button) {
      button.addEventListener("click", function () {
        var status = button.getAttribute("data-job-filter") || "";
        applyFilter(active === status ? "" : status);
      });
    });
  })();

  var workers = document.getElementById("workers");
  var minus = document.getElementById("workers-minus");
  var plus = document.getElementById("workers-plus");

  function clampWorker(value) {
    var parsed = parseInt(value || "1", 10);
    if (Number.isNaN(parsed)) parsed = 1;
    return Math.min(24, Math.max(1, parsed));
  }

  if (workers && minus && plus) {
    minus.addEventListener("click", function () {
      workers.value = String(clampWorker(workers.value) - 1);
      workers.value = String(clampWorker(workers.value));
      workers.dispatchEvent(new Event("change", { bubbles: true }));
    });
    plus.addEventListener("click", function () {
      workers.value = String(clampWorker(workers.value) + 1);
      workers.value = String(clampWorker(workers.value));
      workers.dispatchEvent(new Event("change", { bubbles: true }));
    });
    workers.addEventListener("change", function () {
      workers.value = String(clampWorker(workers.value));
    });
  }

  var menu = document.getElementById("settings-menu");
  var toggles = Array.prototype.slice.call(document.querySelectorAll("[data-settings-toggle]"));
  var closeTimer = 0;

  function setExpanded(expanded) {
    toggles.forEach(function (toggle) {
      toggle.setAttribute("aria-expanded", expanded ? "true" : "false");
      toggle.classList.toggle("active", expanded || toggle.dataset.settingsCurrent === "true");
    });
  }

  function openSettings() {
    if (!menu) return;
    window.clearTimeout(closeTimer);
    menu.hidden = false;
    window.requestAnimationFrame(function () {
      menu.classList.add("is-open");
      setExpanded(true);
    });
  }

  function closeSettings() {
    if (!menu || menu.hidden) return;
    menu.classList.remove("is-open");
    setExpanded(false);
    closeTimer = window.setTimeout(function () {
      menu.hidden = true;
    }, 190);
  }

  function toggleSettings(event) {
    event.preventDefault();
    event.stopPropagation();
    if (!menu) return;
    if (menu.hidden || !menu.classList.contains("is-open")) openSettings();
    else closeSettings();
  }

  toggles.forEach(function (toggle) {
    toggle.addEventListener("click", toggleSettings);
  });

  document.addEventListener("click", function (event) {
    if (!menu || menu.hidden) return;
    if (menu.contains(event.target)) return;
    if (toggles.some(function (toggle) { return toggle.contains(event.target); })) return;
    closeSettings();
  });

  document.addEventListener("keydown", function (event) {
    if (event.key === "Escape") closeSettings();
  });
})();
