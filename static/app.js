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
