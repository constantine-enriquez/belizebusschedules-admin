/**
 * Admin Schedules → Manual — browse, add, edit, duplicate, delete, and undo trips.
 * Expects globals from index.html: API_BASE, apiFetch, escHtml, escAttr, toast, closeModals
 * Validation mirrors functions/lib/scheduleHelpers.js; the server stays authoritative.
 */
;(function () {
  let schedules = []
  let meta = { days: [], service_types: [], places: [], phone_number: null }
  let changes = []
  let currentCompany = ''
  let editorStops = []
  let warningsAcknowledged = false
  let loadToken = 0
  let draftSave = null
  let editorSaveLabel = 'Save trip'

  const ACTION_LABELS = { create: 'Added', update: 'Edited', delete: 'Deleted', restore: 'Undo' }
  const FIELD_LABELS = [
    ['company', 'company'],
    ['route', 'route name'],
    ['origin', 'origin'],
    ['destination', 'destination'],
    ['departure_time', 'departure'],
    ['arrival_time', 'arrival'],
    ['days_of_operation', 'days'],
    ['service_type', 'service'],
    ['stops_data', 'stops'],
    ['notes', 'notes'],
    ['phone_number', 'phone'],
  ]

  const $ = (id) => document.getElementById(id)
  const pad = (n) => String(n).padStart(2, '0')

  function normalizeTime(input) {
    if (input == null) return { value: null }
    const raw = String(input).trim()
    if (!raw || raw.toLowerCase() === 'null') return { value: null }
    const compact = raw.replace(/\s+/g, '').replace(/\./g, '').toUpperCase()
    let m = compact.match(/^(\d{1,2}):?(\d{2})(AM|PM)$/)
    if (m) {
      const h = Number(m[1])
      const min = Number(m[2])
      if (h >= 1 && h <= 12 && min <= 59) return { value: `${h}:${pad(min)} ${m[3]}` }
    }
    m = compact.match(/^(\d{1,2}):(\d{2})$/)
    if (m) {
      const h = Number(m[1])
      const min = Number(m[2])
      if (h <= 23 && min <= 59) return { value: `${h % 12 || 12}:${pad(min)} ${h >= 12 ? 'PM' : 'AM'}` }
    }
    return { value: null, error: `"${raw}" is not a valid time` }
  }

  function timeToMinutes(value) {
    const m = String(value || '').match(/^(\d{1,2}):(\d{2}) (AM|PM)$/)
    if (!m) return null
    return ((Number(m[1]) % 12) + (m[3] === 'PM' ? 12 : 0)) * 60 + Number(m[2])
  }

  /** "h:mm AM" → "HH:MM" for <input type="time">. */
  function to24(value) {
    const mins = timeToMinutes(normalizeTime(value).value)
    return mins == null ? '' : `${pad(Math.floor(mins / 60))}:${pad(mins % 60)}`
  }

  function from24(value) {
    return value ? normalizeTime(value).value : null
  }

  function shiftTime(value, deltaMinutes) {
    const mins = timeToMinutes(value)
    if (mins == null) return null
    const t = (((mins + deltaMinutes) % 1440) + 1440) % 1440
    return normalizeTime(`${Math.floor(t / 60)}:${pad(t % 60)}`).value
  }

  function placeMatches(a, b) {
    const x = String(a || '').trim().toLowerCase()
    const y = String(b || '').trim().toLowerCase()
    if (!x || !y) return true
    return x === y || x.startsWith(y) || y.startsWith(x)
  }

  function compareTrips(a, b) {
    return (
      String(a.origin || '').localeCompare(String(b.origin || '')) ||
      String(a.destination || '').localeCompare(String(b.destination || '')) ||
      (timeToMinutes(normalizeTime(a.departure_time).value) ?? 9999) -
        (timeToMinutes(normalizeTime(b.departure_time).value) ?? 9999) ||
      a.BID - b.BID
    )
  }

  function haystack(s) {
    return [
      s.route,
      s.origin,
      s.destination,
      s.departure_time,
      s.arrival_time,
      s.days_of_operation,
      s.service_type,
      s.notes,
      String(s.BID),
      ...(s.stops || []).map((st) => st.location),
    ]
      .filter(Boolean)
      .join(' ')
      .toLowerCase()
  }

  function optionList(values) {
    return (values || []).map((v) => `<option value="${escAttr(v)}"></option>`).join('')
  }

  function fillDatalists(m = meta) {
    $('sch-places-list').innerHTML = optionList(m.places)
    $('sch-days-list').innerHTML = optionList(m.days)
    $('sch-service-list').innerHTML = optionList(m.service_types)
  }

  function fillOriginFilter() {
    const sel = $('sch-origin-filter')
    const cur = sel.value
    const origins = [...new Set(schedules.map((s) => s.origin).filter(Boolean))].sort()
    sel.innerHTML =
      '<option value="">Any origin</option>' +
      origins.map((o) => `<option value="${escAttr(o)}">${escHtml(o)}</option>`).join('')
    if (cur && origins.includes(cur)) sel.value = cur
  }

  function emptyRow(message) {
    return `<tr><td colspan="7"><div class="empty"><div class="empty-icon"></div>${escHtml(message)}</div></td></tr>`
  }

  window.loadScheduleManual = function loadScheduleManual() {
    if ($('sch-company').value) loadSchedules()
  }

  window.onScheduleCompanyChange = function onScheduleCompanyChange() {
    $('sch-origin-filter').value = ''
    $('sch-search').value = ''
    loadSchedules()
  }

  async function loadSchedules() {
    const company = $('sch-company').value
    currentCompany = company
    $('sch-add-btn').disabled = !company
    const body = $('sch-table-body')

    if (!company) {
      schedules = []
      changes = []
      $('sch-count').textContent = ''
      $('sch-visible-note').textContent = ''
      body.innerHTML = emptyRow('Pick a company to see its trips.')
      renderChanges()
      return
    }

    const token = ++loadToken
    body.innerHTML = emptyRow('Loading trips…')
    try {
      const res = await apiFetch(
        `${API_BASE}/schedules?company=${encodeURIComponent(company)}&full=1`
      )
      const data = await res.json()
      if (!res.ok) throw new Error(data.error || 'Failed to load trips')
      if (token !== loadToken) return
      schedules = data.schedules || []
      meta = data.meta || meta
      fillDatalists()
      fillOriginFilter()
      renderScheduleTable()
    } catch (e) {
      if (token !== loadToken) return
      schedules = []
      body.innerHTML = emptyRow(e.message)
    }
    loadScheduleChanges()
  }

  function scheduleRowHtml(s) {
    const stopsLine = s.stops_invalid
      ? '<span class="sch-route-warn">Stops data is unreadable — open to fix</span>'
      : (s.stops || []).map((st) => escHtml(st.location)).join(' → ')
    const routeName =
      s.route && s.route !== `${s.origin} to ${s.destination}`
        ? `<div class="sch-route-sub">${escHtml(s.route)}</div>`
        : ''
    const notes = s.notes ? `<div class="sch-route-sub">Note: ${escHtml(s.notes)}</div>` : ''
    return `<tr>
      <td class="sch-time">${escHtml(s.departure_time || '—')}</td>
      <td class="sch-time sch-time-muted">${escHtml(s.arrival_time || '—')}</td>
      <td>
        <div class="sch-route-main">${escHtml(s.origin || '?')} → ${escHtml(s.destination || '?')}</div>
        ${routeName}
        ${stopsLine ? `<div class="sch-route-sub">${stopsLine}</div>` : ''}
        ${notes}
      </td>
      <td>${s.days_of_operation ? `<span class="sch-chip">${escHtml(s.days_of_operation)}</span>` : '—'}</td>
      <td style="font-size:12px;">${escHtml(s.service_type || '—')}</td>
      <td><span class="td-id">${escHtml(String(s.BID))}</span></td>
      <td><div class="td-actions">
        <button class="btn btn-edit" onclick="openScheduleEditor(${Number(s.BID)})">Edit</button>
        <button class="btn btn-ghost" style="padding:6px 10px;font-size:11px;min-height:0;" onclick="duplicateSchedule(${Number(s.BID)})" title="Copy this trip into a new one">Copy</button>
        <button class="btn btn-danger-sm" onclick="openScheduleDelete(${Number(s.BID)})">Delete</button>
      </div></td>
    </tr>`
  }

  window.renderScheduleTable = function renderScheduleTable() {
    if (!currentCompany) return
    const q = $('sch-search').value.trim().toLowerCase()
    const origin = $('sch-origin-filter').value
    const rows = schedules
      .filter((s) => (!origin || s.origin === origin) && (!q || haystack(s).includes(q)))
      .sort(compareTrips)

    $('sch-count').textContent = `(${schedules.length})`
    $('sch-visible-note').textContent =
      rows.length === schedules.length
        ? `${schedules.length} trip${schedules.length === 1 ? '' : 's'}`
        : `Showing ${rows.length} of ${schedules.length}`

    $('sch-table-body').innerHTML = rows.length
      ? rows.map(scheduleRowHtml).join('')
      : emptyRow(schedules.length ? 'No trips match these filters.' : 'No trips for this company yet.')
  }

  // ── Editor ────────────────────────────────────────────────

  function setSaveButton(acknowledged) {
    warningsAcknowledged = acknowledged
    $('se-save-btn').textContent = acknowledged ? 'Save anyway' : editorSaveLabel
  }

  function renderIssues(errors, warnings) {
    const box = $('se-issues')
    const list = (items) => `<ul>${items.map((i) => `<li>${escHtml(i)}</li>`).join('')}</ul>`
    let html = ''
    if (errors.length) {
      html += `<div class="sch-issues sch-issues-err"><strong>Fix before saving:</strong>${list(errors)}</div>`
    }
    if (warnings.length) {
      html += `<div class="sch-issues sch-issues-warn"><strong>Double-check:</strong>${list(warnings)}${
        errors.length ? '' : '<div style="margin-top:6px;">Click “Save anyway” if this is correct.</div>'
      }</div>`
    }
    box.innerHTML = html
    if (html) box.scrollIntoView({ block: 'nearest', behavior: 'smooth' })
  }

  function openEditor(bid, duplicate) {
    const s = bid != null ? schedules.find((x) => x.BID === bid) : null
    const editing = !!s && !duplicate
    draftSave = null
    fillEditor(s, {
      bid: editing ? s.BID : null,
      title: editing ? `Edit trip · BID ${s.BID}` : duplicate ? 'Copy trip' : 'New trip',
      desc: duplicate
        ? 'Adjust the copy (usually the times) and save it as a new trip.'
        : 'Riders get changes the next time their app syncs.',
      saveLabel: 'Save trip',
    })
  }

  /**
   * Opens the trip editor for an AI Upload draft. Nothing is sent to the API;
   * `onSave(payload)` receives the edited trip when the user clicks save.
   */
  window.openScheduleDraftEditor = function openScheduleDraftEditor(trip, onSave, opts = {}) {
    draftSave = onSave
    fillEditor(trip, {
      bid: null,
      title: opts.title || 'Edit extracted trip',
      desc: 'Changes stay in this review until you apply the import.',
      saveLabel: 'Done',
      lockCompany: true,
    })
  }

  function fillEditor(s, { bid, title, desc, saveLabel, lockCompany = false }) {
    const notices = []
    editorSaveLabel = saveLabel
    $('se-bid').value = bid != null ? String(bid) : ''
    $('se-title').textContent = title
    $('se-desc').textContent = desc

    $('se-company').value = s?.company || currentCompany
    $('se-company').readOnly = lockCompany
    $('se-phone').value = s ? s.phone_number || '' : meta.phone_number || ''
    $('se-origin').value = s?.origin || ''
    $('se-destination').value = s?.destination || ''
    $('se-route').value = s?.route || ''
    $('se-days').value = s?.days_of_operation || ''
    $('se-service').value = s?.service_type || ''
    $('se-notes').value = s?.notes || ''

    for (const [field, inputId, label] of [
      ['departure_time', 'se-departure', 'Departure'],
      ['arrival_time', 'se-arrival', 'Arrival'],
    ]) {
      const raw = s?.[field]
      $(inputId).value = to24(raw)
      if (raw && normalizeTime(raw).error) notices.push(`${label} "${raw}" couldn't be read — please re-enter it.`)
    }

    editorStops = (s?.stops || []).map((st, i) => {
      const out = { location: st.location || '', arrive: null, depart: null }
      for (const key of ['arrive', 'depart']) {
        const n = normalizeTime(st[key])
        if (n.error) notices.push(`Stop ${i + 1} ${key} "${st[key]}" couldn't be read and was cleared.`)
        out[key] = n.value
      }
      return out
    })

    const noticeEl = $('se-stops-invalid')
    if (s?.stops_invalid) {
      noticeEl.innerHTML = `The stored stops for this trip couldn't be read, so the list starts empty. Saving will replace them.
        <details style="margin-top:6px;"><summary>Show stored value</summary><code>${escHtml(s.stops_data || '')}</code></details>`
      noticeEl.style.display = ''
    } else if (notices.length) {
      noticeEl.innerHTML = notices.map(escHtml).join('<br>')
      noticeEl.style.display = ''
    } else {
      noticeEl.innerHTML = ''
      noticeEl.style.display = 'none'
    }

    $('se-issues').innerHTML = ''
    setSaveButton(false)
    renderStops()
    $('schedule-editor-modal').classList.add('open')
    if (window.AdminIcons) window.AdminIcons.apply($('schedule-editor-modal'))
  }

  window.openScheduleCreate = function openScheduleCreate() {
    if (!currentCompany) return toast('Pick a company first', 'err')
    openEditor(null, false)
  }
  window.openScheduleEditor = function openScheduleEditor(bid) {
    openEditor(bid, false)
  }
  window.duplicateSchedule = function duplicateSchedule(bid) {
    openEditor(bid, true)
  }

  function renderStops() {
    const wrap = $('se-stops')
    if (!editorStops.length) {
      wrap.innerHTML =
        '<div class="sch-stops-empty">No stops yet. Use “Fill first &amp; last from trip” or add stops one by one.</div>'
      return
    }
    const last = editorStops.length - 1
    wrap.innerHTML = editorStops
      .map(
        (st, i) => `<div class="sch-stop-row" data-index="${i}">
        <span class="sch-stop-num">${i + 1}</span>
        <input class="sch-stop-loc" type="text" list="sch-places-list" autocomplete="off" data-field="location" value="${escAttr(st.location)}" aria-label="Stop ${i + 1} location" placeholder="Location">
        <input type="time" data-field="arrive" value="${to24(st.arrive)}" aria-label="Stop ${i + 1} arrive">
        <input type="time" data-field="depart" value="${to24(st.depart)}" aria-label="Stop ${i + 1} depart">
        <div class="sch-stop-actions">
          <button type="button" class="sch-icon-btn" data-move="-1" ${i === 0 ? 'disabled' : ''} aria-label="Move stop up">↑</button>
          <button type="button" class="sch-icon-btn" data-move="1" ${i === last ? 'disabled' : ''} aria-label="Move stop down">↓</button>
          <button type="button" class="sch-icon-btn danger" data-remove="1" aria-label="Remove stop">✕</button>
        </div>
      </div>`
      )
      .join('')
  }

  window.addScheduleStop = function addScheduleStop() {
    const blank = { location: '', arrive: null, depart: null }
    const at = editorStops.length >= 2 ? editorStops.length - 1 : editorStops.length
    editorStops.splice(at, 0, blank)
    setSaveButton(false)
    renderStops()
    $('se-stops').querySelector(`.sch-stop-row[data-index="${at}"] .sch-stop-loc`)?.focus()
  }

  window.fillScheduleEndStops = function fillScheduleEndStops() {
    const origin = $('se-origin').value.trim()
    const destination = $('se-destination').value.trim()
    if (!origin || !destination) return toast('Enter origin and destination first', 'err')
    const dep = from24($('se-departure').value)
    const arr = from24($('se-arrival').value)
    const first = { location: origin, arrive: dep ? shiftTime(dep, -15) : null, depart: dep }
    const lastStop = { location: destination, arrive: arr, depart: null }
    if (editorStops.length < 2) editorStops = [first, lastStop]
    else {
      editorStops[0] = first
      editorStops[editorStops.length - 1] = lastStop
    }
    setSaveButton(false)
    renderStops()
  }

  window.shiftScheduleTimes = function shiftScheduleTimes() {
    const delta = Number($('se-shift').value)
    if (!delta) return
    for (const id of ['se-departure', 'se-arrival']) {
      const t = from24($(id).value)
      if (t) $(id).value = to24(shiftTime(t, delta))
    }
    editorStops = editorStops.map((s) => ({
      ...s,
      arrive: s.arrive ? shiftTime(s.arrive, delta) : null,
      depart: s.depart ? shiftTime(s.depart, delta) : null,
    }))
    setSaveButton(false)
    $('se-issues').innerHTML = ''
    renderStops()
    toast(`Shifted all times by ${delta > 0 ? '+' : ''}${delta} min`, 'ok')
  }

  function collectPayload() {
    const val = (id) => $(id).value.trim()
    return {
      company: val('se-company'),
      route: val('se-route'),
      origin: val('se-origin'),
      destination: val('se-destination'),
      departure_time: from24($('se-departure').value),
      arrival_time: from24($('se-arrival').value),
      days_of_operation: val('se-days'),
      service_type: val('se-service'),
      notes: val('se-notes'),
      phone_number: val('se-phone'),
      stops: editorStops.map((s) => ({
        arrive: s.arrive || null,
        depart: s.depart || null,
        location: String(s.location || '').trim(),
      })),
    }
  }

  function validateClient(p, bid, { skipDuplicate = false } = {}) {
    const errors = []
    const warnings = []
    if (!p.company) errors.push('Company is required')
    if (!p.origin) errors.push('Origin is required')
    if (!p.destination) errors.push('Destination is required')
    if (!p.departure_time) errors.push('Departure time is required')
    if (!p.days_of_operation) errors.push('Days of operation is required')
    p.stops.forEach((s, i) => {
      if (!s.location) errors.push(`Stop ${i + 1}: location is required`)
    })
    if (errors.length) return { errors, warnings }

    const dep = timeToMinutes(p.departure_time)
    const arr = timeToMinutes(p.arrival_time)
    if (!p.arrival_time) warnings.push('No arrival time set')
    else if (arr <= dep) warnings.push('Arrival is not after departure (fine only for overnight trips)')

    const dup = !skipDuplicate && schedules.find(
      (s) =>
        s.BID !== bid &&
        s.company === p.company &&
        s.origin === p.origin &&
        s.destination === p.destination &&
        normalizeTime(s.departure_time).value === p.departure_time &&
        (s.days_of_operation || '') === p.days_of_operation
    )
    if (dup) warnings.push(`Looks like a duplicate of BID ${dup.BID}`)

    const stops = p.stops
    if (stops.length < 2) {
      warnings.push('Trips usually list at least the origin and destination as stops')
      return { errors, warnings }
    }
    const first = stops[0]
    const last = stops[stops.length - 1]
    if (!placeMatches(first.location, p.origin)) {
      warnings.push(`First stop "${first.location}" doesn't match origin "${p.origin}"`)
    }
    if (!placeMatches(last.location, p.destination)) {
      warnings.push(`Last stop "${last.location}" doesn't match destination "${p.destination}"`)
    }
    if (first.depart && first.depart !== p.departure_time) {
      warnings.push(`First stop departs ${first.depart} but trip departure is ${p.departure_time}`)
    }
    if (last.arrive && p.arrival_time && last.arrive !== p.arrival_time) {
      warnings.push(`Last stop arrives ${last.arrive} but trip arrival is ${p.arrival_time}`)
    }
    if (last.depart) warnings.push('Last stop usually has no depart time')

    let prev = null
    outer: for (let i = 0; i < stops.length; i++) {
      for (const key of ['arrive', 'depart']) {
        const t = timeToMinutes(stops[i][key])
        if (t == null) continue
        if (prev != null && t < prev) {
          warnings.push(`Stop ${i + 1} (${stops[i].location}) ${key} time goes backwards`)
          break outer
        }
        prev = t
      }
    }
    return { errors, warnings }
  }

  window.saveSchedule = async function saveSchedule() {
    const bidRaw = $('se-bid').value
    const bid = bidRaw ? Number(bidRaw) : null
    const payload = collectPayload()
    const { errors, warnings } = validateClient(payload, bid, { skipDuplicate: !!draftSave })
    renderIssues(errors, warnings)
    if (errors.length) return
    if (warnings.length && !warningsAcknowledged) {
      setSaveButton(true)
      return
    }

    if (draftSave) {
      const onSave = draftSave
      draftSave = null
      closeModals()
      onSave(payload)
      return
    }

    const btn = $('se-save-btn')
    btn.disabled = true
    try {
      const res = await apiFetch(bid ? `${API_BASE}/schedules/${bid}` : `${API_BASE}/schedules`, {
        method: bid ? 'PATCH' : 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      })
      const data = await res.json()
      if (!res.ok) {
        if (Array.isArray(data.errors)) renderIssues(data.errors, [])
        throw new Error(data.error || 'Save failed')
      }
      closeModals()
      toast(bid ? 'Trip updated' : 'Trip added', 'ok')
      if (payload.company !== currentCompany && typeof loadCompanies === 'function') loadCompanies()
      await loadSchedules()
    } catch (e) {
      toast(e.message, 'err')
    } finally {
      btn.disabled = false
    }
  }

  // ── Delete ────────────────────────────────────────────────

  window.openScheduleDelete = function openScheduleDelete(bid) {
    const s = schedules.find((x) => x.BID === bid)
    if (!s) return
    $('sd-bid').value = String(bid)
    $('sd-route').textContent = `${s.origin || '?'} → ${s.destination || '?'}`
    $('sd-detail').textContent = [s.departure_time, s.days_of_operation, s.service_type, `BID ${bid}`]
      .filter(Boolean)
      .join(' · ')
    const warning = $('sd-active-warning')
    warning.hidden = true
    $('schedule-delete-modal').classList.add('open')
    if (window.AdminIcons) window.AdminIcons.apply($('schedule-delete-modal'))
    showActiveSessionWarning(s, warning)
  }

  async function showActiveSessionWarning(s, el) {
    try {
      const params = new URLSearchParams({
        company: s.company,
        schedule_id: String(s.BID),
        active_only: '1',
        limit: '20',
      })
      const res = await apiFetch(`${API_BASE}/sessions?${params}`)
      const data = await res.json()
      const active = res.ok ? data.sessions || [] : []
      if (!active.length || $('sd-bid').value !== String(s.BID)) return
      const names = active.map((x) => x.driver_display_name || x.driver_email || 'a driver')
      el.textContent = `${active.length === 1 ? 'A driver is' : `${active.length} drivers are`} on this trip right now (${names.join(', ')}). Their session will stay open but lose its route.`
      el.hidden = false
    } catch {
      // Warning only; deleting still works without it.
    }
  }

  window.confirmScheduleDelete = async function confirmScheduleDelete() {
    const bid = Number($('sd-bid').value)
    try {
      const res = await apiFetch(`${API_BASE}/schedules/${bid}`, { method: 'DELETE' })
      const data = await res.json()
      if (!res.ok) throw new Error(data.error || 'Delete failed')
      closeModals()
      toast('Trip deleted — undo it from Recent changes', 'ok')
      await loadSchedules()
    } catch (e) {
      toast(e.message, 'err')
    }
  }

  // ── Change history / undo ────────────────────────────────

  async function loadScheduleChanges() {
    const company = currentCompany
    if (!company) return
    try {
      const res = await apiFetch(
        `${API_BASE}/schedule-changes?company=${encodeURIComponent(company)}&limit=20`
      )
      const data = await res.json()
      if (!res.ok) throw new Error(data.error || 'Failed to load changes')
      if (company !== currentCompany) return
      changes = data.changes || []
      renderChanges()
    } catch (e) {
      $('sch-changes-body').innerHTML =
        `<div class="empty"><div class="empty-icon"></div>${escHtml(e.message)}</div>`
    }
  }

  function comparable(row, key) {
    const v = row?.[key]
    if (key !== 'stops_data') return String(v ?? '')
    try {
      return JSON.stringify(JSON.parse(v || '[]'))
    } catch {
      return String(v ?? '')
    }
  }

  function changeSummary(c) {
    const row = c.after || c.before || {}
    const label = `${row.origin || '?'} → ${row.destination || '?'} · ${row.departure_time || '—'}`
    let detail = ''
    if (c.before && c.after) {
      const diff = FIELD_LABELS.filter(([k]) => comparable(c.before, k) !== comparable(c.after, k)).map(
        ([, l]) => l
      )
      detail = diff.length ? `Changed ${diff.join(', ')}` : 'No field changes'
    } else if (c.action === 'restore') {
      detail = c.after ? 'Trip restored' : 'Trip removed'
    }
    return { label, detail }
  }

  function renderChanges() {
    const body = $('sch-changes-body')
    if (!currentCompany) {
      body.innerHTML = '<div class="empty"><div class="empty-icon"></div>Changes you make here will show up for undo.</div>'
      return
    }
    if (!changes.length) {
      body.innerHTML = '<div class="empty"><div class="empty-icon"></div>No changes yet for this company.</div>'
      return
    }
    body.innerHTML = changes
      .map((c) => {
        const when = c.created_at
          ? new Date(c.created_at).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' })
          : ''
        if (c.kind === 'batch') return batchChangeHtml(c, when)
        const { label, detail } = changeSummary(c)
        const metaLine = [when, c.actor, c.bid != null ? `BID ${c.bid}` : null, detail]
          .filter(Boolean)
          .map(escHtml)
          .join(' · ')
        return `<div class="sch-change">
          <span class="badge badge-sch-${escAttr(c.action)}">${escHtml(ACTION_LABELS[c.action] || c.action)}</span>
          <div class="sch-change-main">
            <div>${escHtml(label)}</div>
            <div class="sch-change-meta">${metaLine}</div>
          </div>
          <button class="btn btn-ghost" style="padding:6px 12px;font-size:11px;min-height:0;" onclick="undoScheduleChange(${Number(c.id)})">Undo</button>
        </div>`
      })
      .join('')
  }

  function batchChangeHtml(c, when) {
    const n = c.counts || {}
    const parts = [
      n.create ? `${n.create} added` : null,
      n.update ? `${n.update} edited` : null,
      n.delete ? `${n.delete} removed` : null,
      n.restore ? `${n.restore} restored` : null,
    ].filter(Boolean)
    const isUndo = c.batch_type === 'undo'
    const metaLine = [when, c.actor].filter(Boolean).map(escHtml).join(' · ')
    return `<div class="sch-change">
      <span class="badge ${isUndo ? 'badge-sch-restore' : 'badge-sch-ai'}">${isUndo ? 'Undo' : 'AI import'}</span>
      <div class="sch-change-main">
        <div>${isUndo ? 'Undid an import' : 'Photo import'} · ${escHtml(parts.join(', ') || 'no changes')}</div>
        <div class="sch-change-meta">${metaLine}</div>
      </div>
      <button class="btn btn-ghost" style="padding:6px 12px;font-size:11px;min-height:0;" onclick="undoScheduleBatch('${escAttr(c.batch_id)}')">${isUndo ? 'Redo import' : 'Undo import'}</button>
    </div>`
  }

  async function postUndo(body, retry) {
    const res = await apiFetch(`${API_BASE}/schedule-changes`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })
    const data = await res.json()
    if (res.status === 409 && data.conflict && !body.force) {
      if (confirm(data.error)) return retry()
      return null
    }
    if (!res.ok) throw new Error(data.error || 'Undo failed')
    return data
  }

  window.undoScheduleChange = async function undoScheduleChange(id, force = false) {
    try {
      const data = await postUndo({ id, force }, () => undoScheduleChange(id, true))
      if (!data) return
      toast(data.unchanged ? 'Nothing to undo' : 'Change undone', 'ok')
      await loadSchedules()
    } catch (e) {
      toast(e.message, 'err')
    }
  }

  /** Undoes a whole AI import. Resolves true when something was undone. */
  window.undoScheduleBatch = async function undoScheduleBatch(batchId, force = false) {
    try {
      const data = await postUndo({ batch_id: batchId, force }, () => undoScheduleBatch(batchId, true))
      if (!data) return false
      toast(data.unchanged ? 'Nothing to undo' : 'Import undone', 'ok')
      if (currentCompany) await loadSchedules()
      return !data.unchanged
    } catch (e) {
      toast(e.message, 'err')
      return false
    }
  }

  window.ScheduleRules = {
    normalizeTime,
    timeToMinutes,
    fillDatalists,
    validate: (payload) => validateClient(payload, null, { skipDuplicate: true }),
  }

  // ── Wiring ────────────────────────────────────────────────

  const stopsWrap = $('se-stops')
  stopsWrap?.addEventListener('input', (e) => {
    const row = e.target.closest('.sch-stop-row')
    const field = e.target.dataset.field
    if (!row || !field) return
    const stop = editorStops[Number(row.dataset.index)]
    if (!stop) return
    stop[field] = field === 'location' ? e.target.value : from24(e.target.value)
  })
  stopsWrap?.addEventListener('click', (e) => {
    const btn = e.target.closest('button')
    const row = e.target.closest('.sch-stop-row')
    if (!btn || !row) return
    const i = Number(row.dataset.index)
    if (btn.dataset.remove) {
      editorStops.splice(i, 1)
    } else if (btn.dataset.move) {
      const j = i + Number(btn.dataset.move)
      if (j < 0 || j >= editorStops.length) return
      ;[editorStops[i], editorStops[j]] = [editorStops[j], editorStops[i]]
    } else {
      return
    }
    setSaveButton(false)
    renderStops()
  })

  document
    .querySelector('#schedule-editor-modal .sch-editor-body')
    ?.addEventListener('input', () => {
      if (warningsAcknowledged) setSaveButton(false)
    })
})()
