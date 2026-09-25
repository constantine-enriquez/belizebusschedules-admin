/**
 * Admin Ads UI — strip + card lists, editor, live preview (passenger-matched).
 * Expects globals from index.html: API_BASE, apiFetch, escHtml, escAttr, toast, closeModals
 */
;(function () {
  const CATEGORIES = [
    { value: 'hotel', label: 'Hotel / lodging' },
    { value: 'restaurant', label: 'Restaurant / café' },
    { value: 'shop', label: 'Shop / convenience' },
    { value: 'taxi', label: 'Taxi / transfer' },
    { value: 'tour', label: 'Tour operator' },
    { value: 'pharmacy', label: 'Pharmacy' },
    { value: 'car_rental', label: 'Car rental' },
    { value: 'other', label: 'Other' },
  ]

  const CTA_TYPES = [
    { value: 'whatsapp', label: 'WhatsApp', defaultLabel: 'WhatsApp', placeholder: 'https://wa.me/501…' },
    { value: 'call', label: 'Call', defaultLabel: 'Call', placeholder: 'tel:+501…' },
    { value: 'directions', label: 'Directions', defaultLabel: 'Directions', placeholder: 'https://maps.google.com/…' },
    { value: 'website', label: 'Website', defaultLabel: 'Visit', placeholder: 'https://…' },
    { value: 'custom', label: 'Custom', defaultLabel: 'Learn more', placeholder: 'https://…' },
  ]

  const FIELD_LIMITS = {
    'ad-eyebrow': 28,
    'ad-title': 36,
    'ad-support': 42,
    'ad-subtitle': 48,
    'ad-body': 90,
    'ad-discount-teaser': 36,
    'ad-discount-code': 16,
    'ad-discount-summary': 48,
    cta_label: 14,
  }

  let ads = []
  let adsTab = 'strip'
  let editorCtas = []
  let previewDiscountOpen = false
  let locationOrigins = []
  let locationDestinations = []

  const ICON_SVGS = {
    hotel:
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M3 20V9l9-5 9 5v11"/><path d="M9 20v-6h6v6"/><path d="M9 10h.01M15 10h.01"/></svg>',
    restaurant:
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M8 3v8a2 2 0 104 0V3M10 11v10"/><path d="M16 3v18M16 3c2 0 3 1.5 3 4s-1 4-3 4"/></svg>',
    shop:
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M4 9h16l-1.2 11H5.2L4 9z"/><path d="M8 9V7a4 4 0 018 0v2"/></svg>',
    taxi:
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M5 16l1.2-5.2A2 2 0 018.15 9h7.7a2 2 0 011.95 1.8L19 16"/><path d="M5 16h14v3H5zM7.5 19.5a1.5 1.5 0 100-3 1.5 1.5 0 000 3zM16.5 19.5a1.5 1.5 0 100-3 1.5 1.5 0 000 3z"/><path d="M9 9l1-3h4l1 3"/></svg>',
    tour:
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="9"/><path d="M12 3c2.5 3 2.5 15 0 18M3.5 9h17M3.5 15h17M12 3a14 14 0 010 18"/></svg>',
    pharmacy:
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="4" y="3" width="16" height="18" rx="2"/><path d="M12 8v8M8 12h8"/></svg>',
    car_rental:
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M4 15l1.4-5.2A2 2 0 017.35 8.5h9.3a2 2 0 011.95 1.3L20 15"/><path d="M4 15h16v3.5a1 1 0 01-1 1H5a1 1 0 01-1-1V15z"/><circle cx="7.5" cy="18" r="1.4"/><circle cx="16.5" cy="18" r="1.4"/><path d="M8 8.5l1.2-2.5h5.6L16 8.5"/></svg>',
    other:
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 21s7-5.2 7-11a7 7 0 10-14 0c0 5.8 7 11 7 11z"/><circle cx="12" cy="10" r="2.5"/></svg>',
  }

  const WA_SVG =
    '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M12.04 2a9.9 9.9 0 00-8.5 14.9L2 22l5.26-1.38A9.9 9.9 0 1012.04 2zm5.78 14.1c-.24.68-1.4 1.25-1.93 1.33-.5.07-1.13.1-1.82-.11-.42-.13-.96-.31-1.65-.61-2.9-1.26-4.79-4.18-4.93-4.38-.14-.2-1.15-1.53-1.15-2.92 0-1.39.73-2.07.99-2.35.26-.28.57-.35.76-.35h.55c.17 0 .41-.07.64.49.24.58.82 2 .89 2.15.07.15.12.32.02.52-.1.2-.15.32-.3.5-.14.17-.3.39-.43.52-.14.14-.29.29-.12.56.17.28.75 1.23 1.61 2 .1.99 2.03 1.64 2.32 1.78.29.14.46.12.63-.07.17-.2.72-.84.91-1.13.19-.28.39-.24.65-.14.26.1 1.66.78 1.95.92.28.14.47.21.54.33.07.12.07.69-.17 1.37z"/></svg>'

  function categoryIcon(kind, size) {
    const k = CATEGORIES.some((c) => c.value === kind) ? kind : 'other'
    return `<span class="ad-avatar ${size || ''} ad-kind-${k}" aria-hidden="true">${ICON_SVGS[k]}</span>`
  }

  function sponsoredBadge(compact) {
    return `<span class="ad-sponsored-wrap${compact ? ' compact' : ''}"><span class="ad-sponsored">Sponsored</span><span class="ad-why-dot" title="Why this ad?">ⓘ</span></span>`
  }

  function toDatetimeLocal(iso) {
    if (!iso) return ''
    const d = new Date(iso)
    if (Number.isNaN(d.getTime())) return ''
    const pad = (n) => String(n).padStart(2, '0')
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`
  }

  function fromDatetimeLocal(val) {
    if (!val) return ''
    const d = new Date(val)
    if (Number.isNaN(d.getTime())) return ''
    return d.toISOString()
  }

  function defaultCta(type) {
    const meta = CTA_TYPES.find((t) => t.value === type) || CTA_TYPES[0]
    return {
      type: meta.value,
      label: meta.defaultLabel,
      href: '',
      style: type === 'whatsapp' ? 'primary' : 'secondary',
    }
  }

  window.setAdsTab = function setAdsTab(tab) {
    adsTab = tab === 'card' ? 'card' : 'strip'
    document.querySelectorAll('.ads-tab').forEach((el) => {
      el.classList.toggle('active', el.dataset.adsTab === adsTab)
    })
    document.getElementById('ads-panel-strip')?.classList.toggle('active', adsTab === 'strip')
    document.getElementById('ads-panel-card')?.classList.toggle('active', adsTab === 'card')
    const btn = document.getElementById('ads-add-btn')
    if (btn) btn.textContent = adsTab === 'strip' ? '+ Add strip ad' : '+ Add card ad'
    renderAdsTables()
  }

  window.loadAds = async function loadAds() {
    const stripBody = document.getElementById('ads-strip-body')
    const cardBody = document.getElementById('ads-card-body')
    if (stripBody) {
      stripBody.innerHTML =
        '<tr><td colspan="6"><div class="empty"><div class="empty-icon"></div>Loading…</div></td></tr>'
    }
    if (cardBody) {
      cardBody.innerHTML =
        '<tr><td colspan="6"><div class="empty"><div class="empty-icon"></div>Loading…</div></td></tr>'
    }
    try {
      const res = await apiFetch(`${API_BASE}/ads`)
      const data = await res.json()
      if (!res.ok) throw new Error(data.error || 'Failed to load ads')
      ads = data.ads || []
      renderAdsTables()
      const countEl = document.getElementById('ads-count')
      if (countEl) countEl.textContent = `(${ads.length})`
    } catch (e) {
      ads = []
      const msg = `<tr><td colspan="6"><div class="empty"><div class="empty-icon"></div>${escHtml(e.message)}</div></td></tr>`
      if (stripBody) stripBody.innerHTML = msg
      if (cardBody) cardBody.innerHTML = msg
    }
  }

  function statusBadge(ad) {
    const label = ad.schedule_label || ad.status || '—'
    const cls = String(label).toLowerCase().replace(/\s+/g, '-')
    return `<span class="badge badge-ad-${escAttr(cls)}">${escHtml(label)}</span>`
  }

  function fmtDateRange(ad) {
    const a = ad.starts_at ? String(ad.starts_at).slice(0, 10) : '—'
    const b = ad.ends_at ? String(ad.ends_at).slice(0, 10) : '—'
    return `${escHtml(a)} → ${escHtml(b)}`
  }

  function renderAdsTables() {
    const strips = ads.filter((a) => a.placement === 'strip')
    const cards = ads.filter((a) => a.placement === 'card')
    const stripBody = document.getElementById('ads-strip-body')
    const cardBody = document.getElementById('ads-card-body')
    const stripCount = document.getElementById('ads-strip-count')
    const cardCount = document.getElementById('ads-card-count')
    if (stripCount) stripCount.textContent = `(${strips.length})`
    if (cardCount) cardCount.textContent = `(${cards.length})`

    if (stripBody) {
      if (!strips.length) {
        stripBody.innerHTML =
          '<tr><td colspan="6"><div class="empty"><div class="empty-icon"></div>No strip ads yet</div></td></tr>'
      } else {
        stripBody.innerHTML = strips
          .map(
            (a) => `<tr>
          <td style="font-weight:500">${escHtml(a.origin)} → ${escHtml(a.destination)}</td>
          <td>${escHtml(a.title)}</td>
          <td style="font-size:12px;color:var(--muted)">${fmtDateRange(a)}</td>
          <td>${statusBadge(a)}</td>
          <td><span class="badge badge-ad-cat">${escHtml(a.category_kind)}</span></td>
          <td><div class="td-actions">
            <button class="btn btn-edit" onclick="openAdEditor('${escAttr(a.id)}')">Edit</button>
            <button class="btn btn-danger-sm" onclick="deleteAd('${escAttr(a.id)}')">Delete</button>
          </div></td>
        </tr>`
          )
          .join('')
      }
    }

    if (cardBody) {
      if (!cards.length) {
        cardBody.innerHTML =
          '<tr><td colspan="6"><div class="empty"><div class="empty-icon"></div>No card ads yet</div></td></tr>'
      } else {
        cardBody.innerHTML = cards
          .map(
            (a) => `<tr>
          <td style="font-weight:500">${escHtml(a.origin)} → ${escHtml(a.destination)}</td>
          <td>${escHtml(a.title)}</td>
          <td style="font-size:12px;color:var(--muted)">${fmtDateRange(a)}</td>
          <td>${statusBadge(a)}</td>
          <td><span class="badge badge-ad-cat">${escHtml(a.category_kind)}</span></td>
          <td><div class="td-actions">
            <button class="btn btn-edit" onclick="openAdEditor('${escAttr(a.id)}')">Edit</button>
            <button class="btn btn-danger-sm" onclick="deleteAd('${escAttr(a.id)}')">Delete</button>
          </div></td>
        </tr>`
          )
          .join('')
      }
    }
  }

  window.openAdCreate = function openAdCreate() {
    openAdEditor(null, adsTab)
  }

  window.openAdEditor = async function openAdEditor(id, forcePlacement) {
    previewDiscountOpen = false
    const ad = id ? ads.find((a) => a.id === id) : null
    const placement = ad?.placement || forcePlacement || adsTab || 'strip'
    document.getElementById('ad-editor-id').value = ad?.id || ''
    document.getElementById('ad-editor-placement').value = placement

    await ensureOriginsLoaded()
    fillOriginSelect(ad?.origin || '')
    await fillDestinationSelect(ad?.origin || '', ad?.destination || '')

    document.getElementById('ad-starts').value = toDatetimeLocal(
      ad?.starts_at || new Date().toISOString()
    )
    const endDefault = new Date()
    endDefault.setDate(endDefault.getDate() + 30)
    document.getElementById('ad-ends').value = toDatetimeLocal(
      ad?.ends_at || endDefault.toISOString()
    )
    document.getElementById('ad-status').value = ad?.status || 'draft'
    document.getElementById('ad-category').value = ad?.category_kind || 'hotel'
    document.getElementById('ad-eyebrow').value = ad?.eyebrow || ''
    document.getElementById('ad-title').value = ad?.title || ''
    document.getElementById('ad-subtitle').value = ad?.subtitle || ''
    document.getElementById('ad-body').value = ad?.body || ''
    document.getElementById('ad-support').value = ad?.support || ''

    const hasDiscount = !!(ad?.discount_code || ad?.discount_summary)
    document.getElementById('ad-discount-enabled').checked = hasDiscount
    document.getElementById('ad-discount-teaser').value =
      ad?.discount_teaser || 'Tap for a discount code'
    document.getElementById('ad-discount-code').value = ad?.discount_code || ''
    document.getElementById('ad-discount-summary').value = ad?.discount_summary || ''
    document.getElementById('ad-discount-valid').value = ad?.discount_valid_until || ''

    editorCtas =
      ad?.ctas?.length > 0
        ? ad.ctas.map((c) => ({ ...c }))
        : [defaultCta('whatsapp')]

    togglePlacementFields(placement)
    syncPlacementControls(placement)
    refreshCharCounters()
    renderCtaBuilder()
    updateAdPreview()
    document.getElementById('ad-editor-modal').classList.add('open')
  }

  async function ensureOriginsLoaded() {
    if (locationOrigins.length) return
    try {
      const res = await apiFetch(`${API_BASE}/locations`)
      const data = await res.json()
      if (!res.ok) throw new Error(data.error || 'Failed to load locations')
      locationOrigins = data.origins || []
    } catch (e) {
      locationOrigins = []
      toast(e.message || 'Failed to load locations', 'err')
    }
  }

  function fillOriginSelect(selected) {
    const sel = document.getElementById('ad-origin')
    if (!sel) return
    const opts = ['<option value="">— select origin —</option>']
    locationOrigins.forEach((place) => {
      opts.push(
        `<option value="${escAttr(place)}"${place === selected ? ' selected' : ''}>${escHtml(place)}</option>`
      )
    })
    if (selected && !locationOrigins.includes(selected)) {
      opts.push(
        `<option value="${escAttr(selected)}" selected>${escHtml(selected)} (not in schedules)</option>`
      )
    }
    sel.innerHTML = opts.join('')
  }

  async function fillDestinationSelect(origin, selected) {
    const sel = document.getElementById('ad-destination')
    if (!sel) return
    sel.innerHTML = '<option value="">— select destination —</option>'
    locationDestinations = []
    if (!origin) return
    try {
      const res = await apiFetch(
        `${API_BASE}/locations?origin=${encodeURIComponent(origin)}`
      )
      const data = await res.json()
      if (!res.ok) throw new Error(data.error || 'Failed to load destinations')
      locationDestinations = data.destinations || []
    } catch (e) {
      toast(e.message || 'Failed to load destinations', 'err')
      return
    }
    const opts = ['<option value="">— select destination —</option>']
    locationDestinations.forEach((place) => {
      opts.push(
        `<option value="${escAttr(place)}"${place === selected ? ' selected' : ''}>${escHtml(place)}</option>`
      )
    })
    if (selected && !locationDestinations.includes(selected)) {
      opts.push(
        `<option value="${escAttr(selected)}" selected>${escHtml(selected)} (not in schedules)</option>`
      )
    }
    sel.innerHTML = opts.join('')
  }

  window.onAdOriginChange = async function onAdOriginChange() {
    const origin = document.getElementById('ad-origin')?.value || ''
    await fillDestinationSelect(origin, '')
    updateAdPreview()
  }

  function togglePlacementFields(placement) {
    document.querySelectorAll('[data-ad-only="card"]').forEach((el) => {
      el.style.display = placement === 'card' ? '' : 'none'
    })
    document.querySelectorAll('[data-ad-only="strip"]').forEach((el) => {
      el.style.display = placement === 'strip' ? '' : 'none'
    })
    const disc = document.getElementById('ad-discount-fields')
    if (disc) {
      const on =
        placement === 'card' && document.getElementById('ad-discount-enabled')?.checked
      disc.style.display = on ? '' : 'none'
    }
  }

  function syncPlacementControls(placement) {
    document.querySelectorAll('[data-ad-placement]').forEach((button) => {
      button.classList.toggle('active', button.dataset.adPlacement === placement)
    })
    const isEditing = !!document.getElementById('ad-editor-id')?.value
    document.getElementById('ad-editor-title-text').textContent =
      `${isEditing ? 'Edit' : 'New'} ${placement} ad`
    document.getElementById('ad-editor-desc').textContent =
      placement === 'strip'
        ? 'Compact banner above search results — short copy only.'
        : 'Sponsored result card — more detail, still kept compact.'
    const help = document.getElementById('ad-preview-help')
    if (help) {
      help.textContent =
        placement === 'strip'
          ? 'Strip size as shown above the results list.'
          : 'Card size as shown in the results list.'
    }
    document.querySelectorAll('[data-ad-step-actions]').forEach((step) => {
      step.textContent = placement === 'card' ? '5' : '4'
    })
    const actionsTitle = document.getElementById('ad-actions-title')
    const actionsHelp = document.getElementById('ad-actions-help')
    if (actionsTitle) {
      actionsTitle.textContent =
        placement === 'strip' ? 'Add contact action' : 'Add contact actions'
    }
    if (actionsHelp) {
      actionsHelp.textContent =
        placement === 'strip'
          ? 'Strip ads get exactly one action (WhatsApp, call, etc.).'
          : 'Card ads can have 1–3 actions. Keep labels short.'
    }
  }

  window.setAdEditorPlacement = function setAdEditorPlacement(placement) {
    document.getElementById('ad-editor-placement').value =
      placement === 'card' ? 'card' : 'strip'
    syncPlacementControls(placement)
    window.onAdPlacementFieldsChange()
  }

  window.onAdPlacementFieldsChange = function onAdPlacementFieldsChange() {
    const placement = document.getElementById('ad-editor-placement').value
    togglePlacementFields(placement)
    const max = placement === 'strip' ? 1 : 3
    if (editorCtas.length > max) editorCtas = editorCtas.slice(0, max)
    if (editorCtas.length < 1) editorCtas = [defaultCta('whatsapp')]
    renderCtaBuilder()
    updateAdPreview()
  }

  window.onAdDiscountToggle = function onAdDiscountToggle() {
    togglePlacementFields(document.getElementById('ad-editor-placement').value)
    updateAdPreview()
  }

  function renderCtaBuilder() {
    const wrap = document.getElementById('ad-cta-list')
    if (!wrap) return
    const placement = document.getElementById('ad-editor-placement').value
    const max = placement === 'strip' ? 1 : 3
    wrap.innerHTML = editorCtas
      .map((cta, i) => {
        const typeOpts = CTA_TYPES.map(
          (t) =>
            `<option value="${t.value}" ${cta.type === t.value ? 'selected' : ''}>${t.label}</option>`
        ).join('')
        const meta = CTA_TYPES.find((t) => t.value === cta.type) || CTA_TYPES[0]
        return `<div class="cta-row" data-cta-i="${i}">
        <div class="field" style="margin:0"><label>Type</label>
          <select onchange="onCtaField(${i},'type',this.value)">${typeOpts}</select>
        </div>
        <div class="field" style="margin:0"><label>Label <span class="char-limit">${escHtml(String(cta.label || '').length)}/${FIELD_LIMITS.cta_label}</span></label>
          <input type="text" maxlength="${FIELD_LIMITS.cta_label}" value="${escAttr(cta.label)}" oninput="onCtaField(${i},'label',this.value)">
        </div>
        <div class="field" style="margin:0;flex:1.4"><label>Href</label>
          <input type="text" value="${escAttr(cta.href)}" placeholder="${escAttr(meta.placeholder)}" oninput="onCtaField(${i},'href',this.value)">
        </div>
        <div class="field" style="margin:0"><label>Style</label>
          <select onchange="onCtaField(${i},'style',this.value)">
            <option value="primary" ${cta.style === 'primary' ? 'selected' : ''}>Primary</option>
            <option value="secondary" ${cta.style !== 'primary' ? 'selected' : ''}>Secondary</option>
          </select>
        </div>
        ${
          placement === 'card'
            ? `<button type="button" class="btn btn-ghost" style="align-self:end;padding:8px" aria-label="Remove action" onclick="removeCta(${i})" ${editorCtas.length <= 1 ? 'disabled' : ''}>Remove</button>`
            : ''
        }
      </div>`
      })
      .join('')

    const addBtn = document.getElementById('ad-cta-add')
    if (addBtn) {
      addBtn.style.display = placement === 'card' && editorCtas.length < max ? '' : 'none'
    }
  }

  window.onCtaField = function onCtaField(i, key, value) {
    if (!editorCtas[i]) return
    if (key === 'label') {
      value = String(value || '').slice(0, FIELD_LIMITS.cta_label)
    }
    editorCtas[i][key] = value
    if (key === 'type') {
      const meta = CTA_TYPES.find((t) => t.value === value)
      if (meta && (!editorCtas[i].label || CTA_TYPES.some((t) => t.defaultLabel === editorCtas[i].label))) {
        editorCtas[i].label = meta.defaultLabel
      }
      if (value === 'whatsapp') editorCtas[i].style = 'primary'
      renderCtaBuilder()
    } else if (key === 'label') {
      const row = document.querySelector(`.cta-row[data-cta-i="${i}"] .char-limit`)
      if (row) row.textContent = `${value.length}/${FIELD_LIMITS.cta_label}`
    }
    updateAdPreview()
  }

  window.addCta = function addCta() {
    const placement = document.getElementById('ad-editor-placement').value
    if (placement !== 'card' || editorCtas.length >= 3) return
    editorCtas.push(defaultCta('call'))
    renderCtaBuilder()
    updateAdPreview()
  }

  window.removeCta = function removeCta(i) {
    if (editorCtas.length <= 1) return
    editorCtas.splice(i, 1)
    renderCtaBuilder()
    updateAdPreview()
  }

  function collectFormAd() {
    const placement = document.getElementById('ad-editor-placement').value
    const discountOn =
      placement === 'card' && document.getElementById('ad-discount-enabled').checked
    return {
      placement,
      origin: document.getElementById('ad-origin').value.trim(),
      destination: document.getElementById('ad-destination').value.trim(),
      starts_at: fromDatetimeLocal(document.getElementById('ad-starts').value),
      ends_at: fromDatetimeLocal(document.getElementById('ad-ends').value),
      status: document.getElementById('ad-status').value,
      category_kind: document.getElementById('ad-category').value,
      eyebrow: document.getElementById('ad-eyebrow').value.trim(),
      title: document.getElementById('ad-title').value.trim(),
      subtitle: document.getElementById('ad-subtitle').value.trim(),
      body: document.getElementById('ad-body').value.trim(),
      support: document.getElementById('ad-support').value.trim(),
      discount_teaser: discountOn
        ? document.getElementById('ad-discount-teaser').value.trim()
        : '',
      discount_code: discountOn
        ? document.getElementById('ad-discount-code').value.trim()
        : '',
      discount_summary: discountOn
        ? document.getElementById('ad-discount-summary').value.trim()
        : '',
      discount_valid_until: discountOn
        ? document.getElementById('ad-discount-valid').value.trim()
        : '',
      ctas: editorCtas.map((c) => ({ ...c })),
    }
  }

  window.updateAdPreview = function updateAdPreview() {
    const host = document.getElementById('ad-preview-host')
    if (!host) return
    const ad = collectFormAd()
    if (ad.placement === 'strip') {
      host.innerHTML = renderStripPreview(ad)
    } else {
      host.innerHTML = renderCardPreview(ad)
    }
  }

  function renderStripPreview(ad) {
    const support = ad.support || ''
    const cta = ad.ctas[0] || { label: 'View' }
    return `<aside class="pv-strip">
      ${categoryIcon(ad.category_kind, 'sm')}
      <div class="pv-strip-copy">
        <div class="pv-meta">${sponsoredBadge(true)}<span class="pv-eyebrow">${escHtml(ad.eyebrow || 'Near destination')}</span></div>
        <p class="pv-strip-primary"><strong>${escHtml(ad.title || 'Business name')}</strong>${
          support ? `<span class="pv-support">${escHtml(support)}</span>` : ''
        }</p>
      </div>
      <span class="pv-strip-cta"><span>${escHtml(cta.label || 'View')}</span>
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4"><path d="M9 6l6 6-6 6"/></svg>
      </span>
    </aside>`
  }

  function renderCardPreview(ad) {
    const discountOn = !!(ad.discount_code || ad.discount_summary)
    let discountHtml = ''
    if (discountOn) {
      if (!previewDiscountOpen) {
        discountHtml = `<button type="button" class="pv-discount" onclick="togglePreviewDiscount()">
          <span class="pv-discount-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 12v7a2 2 0 01-2 2H6a2 2 0 01-2-2v-7"/><path d="M12 3v13M8 12l4 4 4-4"/></svg></span>
          <span class="pv-discount-teaser">${escHtml(ad.discount_teaser || 'Tap for a discount code')}</span>
          <svg class="pv-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 9l6 6 6-6"/></svg>
        </button>`
      } else {
        let valid = ''
        if (ad.discount_valid_until) {
          const parsed = new Date(`${ad.discount_valid_until}T12:00:00`)
          const formatted = Number.isNaN(parsed.getTime())
            ? ad.discount_valid_until
            : parsed.toLocaleDateString('en-BZ', { month: 'short', day: 'numeric', year: 'numeric' })
          valid = `<p class="pv-discount-valid">Valid until ${escHtml(formatted)}</p>`
        }
        discountHtml = `<div class="pv-discount open">
          <p class="pv-discount-summary">${escHtml(ad.discount_summary || 'Discount')}</p>
          <div class="pv-code-row"><span class="pv-code-label">Discount code</span><span class="pv-code-value">${escHtml(ad.discount_code || 'CODE')}</span></div>
          ${valid}
          <div class="pv-discount-actions">
            <button type="button" class="pv-copy" onclick="togglePreviewDiscount()">Hide</button>
          </div>
        </div>`
      }
    }

    const actions = (ad.ctas || [])
      .map((c) => {
        const primary = c.style === 'primary'
        const icon = c.type === 'whatsapp' ? WA_SVG : ''
        return `<span class="pv-action${primary ? ' primary' : ''}">${icon}${escHtml(c.label || c.type)}</span>`
      })
      .join('')

    return `<article class="pv-card">
      <div class="pv-hero">${categoryIcon(ad.category_kind, 'lg')}</div>
      <header class="pv-header">
        <div class="pv-meta">${sponsoredBadge(false)}<span class="pv-eyebrow">${escHtml(ad.eyebrow || 'Near destination')}</span></div>
        <h3>${escHtml(ad.title || 'Business name')}</h3>
        ${ad.subtitle ? `<p class="pv-headline">${escHtml(ad.subtitle)}</p>` : ''}
        ${ad.body ? `<p class="pv-copy">${escHtml(ad.body)}</p>` : ''}
      </header>
      ${discountOn ? `<div class="pv-discount-wrap">${discountHtml}</div>` : ''}
      <div class="pv-actions">${actions || '<span class="pv-action primary">WhatsApp</span>'}</div>
    </article>`
  }

  window.togglePreviewDiscount = function togglePreviewDiscount() {
    previewDiscountOpen = !previewDiscountOpen
    updateAdPreview()
  }

  window.saveAd = async function saveAd() {
    const id = document.getElementById('ad-editor-id').value
    const body = collectFormAd()
    if (!body.origin || !body.destination) return toast('Origin and destination required', 'err')
    if (!body.title) return toast('Title required', 'err')
    if (!body.starts_at || !body.ends_at) return toast('Schedule dates required', 'err')

    async function send(force) {
      const url = id
        ? `${API_BASE}/ads/${encodeURIComponent(id)}${force ? '?force=1' : ''}`
        : `${API_BASE}/ads${force ? '?force=1' : ''}`
      const res = await apiFetch(url, {
        method: id ? 'PATCH' : 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      const data = await res.json().catch(() => ({}))
      return { res, data }
    }

    try {
      let { res, data } = await send(false)
      if (res.status === 409 && data.code === 'OVERLAP') {
        const names = (data.overlaps || []).map((o) => o.title).join(', ')
        if (
          confirm(
            `Overlap with active ad(s): ${names || 'another ad'}.\n\nSave anyway?`
          )
        ) {
          ;({ res, data } = await send(true))
        } else {
          return
        }
      }
      if (!res.ok) throw new Error(data.error || 'Save failed')
      closeModals()
      toast(id ? 'Ad updated' : 'Ad created', 'ok')
      loadAds()
    } catch (e) {
      toast(e.message, 'err')
    }
  }

  window.deleteAd = async function deleteAd(id) {
    if (!confirm('Delete this ad permanently?')) return
    try {
      const res = await apiFetch(`${API_BASE}/ads/${encodeURIComponent(id)}`, {
        method: 'DELETE',
      })
      const data = await res.json().catch(() => ({}))
      if (!res.ok) throw new Error(data.error || 'Delete failed')
      toast('Ad deleted', 'ok')
      loadAds()
    } catch (e) {
      toast(e.message, 'err')
    }
  }

  function updateCharCounter(el) {
    if (!el || !el.id) return
    const max = FIELD_LIMITS[el.id]
    if (!max) return
    const len = String(el.value || '').length
    const counter = document.querySelector(`.char-limit[data-for="${el.id}"]`)
    if (!counter) return
    counter.textContent = `${len}/${max}`
    counter.classList.toggle('warn', len >= max - 4 && len < max)
    counter.classList.toggle('full', len >= max)
  }

  function refreshCharCounters() {
    Object.keys(FIELD_LIMITS).forEach((id) => {
      if (id === 'cta_label') return
      updateCharCounter(document.getElementById(id))
    })
  }

  window.onAdTextInput = function onAdTextInput(el) {
    updateCharCounter(el)
    updateAdPreview()
  }

  function bindPreviewInputs() {
    ;[
      'ad-origin',
      'ad-destination',
      'ad-eyebrow',
      'ad-title',
      'ad-subtitle',
      'ad-body',
      'ad-support',
      'ad-category',
      'ad-discount-teaser',
      'ad-discount-code',
      'ad-discount-summary',
      'ad-discount-valid',
    ].forEach((id) => {
      const el = document.getElementById(id)
      if (!el || el.dataset.adsBound) return
      el.dataset.adsBound = '1'
      el.addEventListener('input', function () {
        updateCharCounter(el)
        updateAdPreview()
      })
      el.addEventListener('change', updateAdPreview)
    })
    refreshCharCounters()
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', bindPreviewInputs)
  } else {
    bindPreviewInputs()
  }
})()
