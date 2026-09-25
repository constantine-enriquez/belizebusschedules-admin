/**
 * Static SVG icons for the admin UI.
 * Applies once on load — no MutationObserver (that caused RESULT_CODE_HUNG loops).
 */
;(function () {
  const icons = {
    users:
      '<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"/>',
    bus: '<path d="M6 17h12M6 17a2 2 0 0 1-2-2V6c0-2 2-3 8-3s8 1 8 3v9a2 2 0 0 1-2 2M6 17v2m12-2v2M4 10h16M7 14h.01M17 14h.01"/>',
    sessions: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    ads: '<path d="m3 11 18-5v12L3 13v-2Z"/><path d="M7 14v5a2 2 0 0 0 2 2h2l-1.5-6"/>',
    edit: '<path d="M12 20h9"/><path d="M16.5 3.5a2.12 2.12 0 0 1 3 3L8 18l-4 1 1-4Z"/>',
    trash: '<path d="M3 6h18M8 6V4h8v2M19 6l-1 15H6L5 6M10 11v6M14 11v6"/>',
    plus: '<path d="M12 5v14M5 12h14"/>',
    image:
      '<rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><path d="m21 15-5-5L5 21"/>',
    card: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 10h18M7 15h4"/>',
    strip: '<rect x="3" y="7" width="18" height="10" rx="2"/><path d="M7 12h6M17 12h1"/>',
    close: '<path d="m6 6 12 12M18 6 6 18"/>',
    logout:
      '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="M16 17l5-5-5-5"/><path d="M21 12H9"/>',
  }

  function svg(name) {
    return '<svg viewBox="0 0 24 24" aria-hidden="true">' + icons[name] + '</svg>'
  }

  function setIcon(element, name) {
    if (!element || !icons[name]) return
    if (element.getAttribute('data-icon-ready') === name) return
    element.innerHTML = svg(name)
    element.setAttribute('data-icon-ready', name)
  }

  function applyIcons(root) {
    const scope = root && root.querySelectorAll ? root : document

    scope.querySelectorAll('.nav-item').forEach(function (item) {
      const section = item.getAttribute('data-section') || ''
      const name =
        section === 'users'
          ? 'users'
          : section === 'vehicles'
            ? 'bus'
            : section === 'sessions'
              ? 'sessions'
              : section === 'ads'
                ? 'ads'
                : null
      if (name) setIcon(item.querySelector('.nav-icon'), name)
    })

    ;[
      ['userModalIcon', 'users'],
      ['editUserModalIcon', 'edit'],
      ['deleteModalIcon', 'trash'],
      ['vehicleModalIcon', 'bus'],
      ['editVehicleModalIcon', 'edit'],
      ['deleteVehicleModalIcon', 'trash'],
      ['adModalIcon', 'ads'],
      ['deleteAdModalIcon', 'trash'],
    ].forEach(function (entry) {
      setIcon(document.getElementById(entry[0]), entry[1])
    })

    scope.querySelectorAll('[data-icon]').forEach(function (node) {
      setIcon(node, node.getAttribute('data-icon'))
    })

    scope.querySelectorAll('.vehicle-thumb-placeholder').forEach(function (node) {
      setIcon(node, 'image')
    })
  }

  window.AdminIcons = { svg: svg, setIcon: setIcon, apply: applyIcons }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () {
      applyIcons(document)
    })
  } else {
    applyIcons(document)
  }
})()
