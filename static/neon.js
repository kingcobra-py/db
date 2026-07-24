(function () {
  'use strict';

  function $(selector, root) {
    return (root || document).querySelector(selector);
  }

  document.querySelectorAll('[data-range]').forEach(function (button) {
    button.addEventListener('click', function () {
      var input = $('#url');
      if (!input) return;
      input.value = button.getAttribute('data-range') || '';
      input.focus();
    });
  });

  document.querySelectorAll('.rail-btn[href^="#"]').forEach(function (link) {
    link.addEventListener('click', function () {
      document.querySelectorAll('.rail-btn').forEach(function (item) {
        item.classList.remove('active');
      });
      link.classList.add('active');
    });
  });

  var palette = $('#command-palette');
  var openButton = $('#open-palette');
  var paletteInput = $('#palette-input');

  function openPalette() {
    if (!palette) return;
    palette.classList.add('open');
    window.setTimeout(function () {
      if (paletteInput) paletteInput.focus();
    }, 40);
  }

  function closePalette() {
    if (!palette) return;
    palette.classList.remove('open');
    if (paletteInput) paletteInput.value = '';
    document.querySelectorAll('.palette-item').forEach(function (item) {
      item.hidden = false;
    });
  }

  if (openButton) openButton.addEventListener('click', openPalette);
  if (palette) {
    palette.addEventListener('click', function (event) {
      if (event.target === palette) closePalette();
    });
  }

  document.addEventListener('keydown', function (event) {
    var tag = document.activeElement && document.activeElement.tagName;
    if (event.key === '/' && tag !== 'INPUT' && tag !== 'TEXTAREA') {
      event.preventDefault();
      openPalette();
    }
    if (event.key === 'Escape') closePalette();
  });

  if (paletteInput) {
    paletteInput.addEventListener('input', function () {
      var query = paletteInput.value.toLowerCase();
      document.querySelectorAll('.palette-item').forEach(function (item) {
        item.hidden = item.textContent.toLowerCase().indexOf(query) === -1;
      });
    });
  }

  document.querySelectorAll('[data-command]').forEach(function (item) {
    item.addEventListener('click', function () {
      var command = item.getAttribute('data-command');
      closePalette();
      var target = command === 'queue' ? $('#queue') :
        command === 'settings' ? $('#settings') :
        command === 'logs' ? $('#logs') : null;
      if (target) target.scrollIntoView({ behavior: 'smooth', block: 'start' });
      if (command === 'queue') {
        var input = $('#url');
        if (input) input.focus();
      }
    });
  });
})();
