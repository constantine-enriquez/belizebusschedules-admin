/**
 * Admin Schedules → AI Upload — photo → Gemini → review drafts → replace a company's schedule.
 * Expects globals from index.html (API_BASE, apiFetch, escHtml, escAttr, toast, closeModals, showSection)
 * and from schedules-ui.js (openScheduleDraftEditor, undoScheduleBatch, ScheduleRules).
 */
;(function () {
  const MAX_DIM = 2400
  const LOW_CONFIDENCE = 0.7
  const FIELD_LABELS = {
    company: 'company',
    route: 'route name',
    origin: 'origin',
    destination: 'destination',
    departure_time: 'departure',
    arrival_time: 'arrival',
    days_of_operation: 'days',
    service_type: 'service',
    stops_data: 'stops',
    notes: 'notes',
    phone_number: 'phone',
  }

  let aiCompany = ''
  let companyMeta = null
  let currentCount = 0
  let upload = null
  let drafts = []
  let nextDraftId = 1
  let plan = null
  let lastImport = null
  let settings = null
  let busy = false
  let busyTimer = null

  const $ = (id) => document.getElementById(id)
  const rules = () => window.ScheduleRules

  // ── Company + settings ────────────────────────────────────

  window.loadAiUpload = async function loadAiUpload() {
    if (!settings) await fetchSettings().catch(() => {})
    if ($('ai-company').value && $('ai-company').value !== aiCompany) onAiCompanyChange()
    updateRunButton()
  }

  async function fetchSettings() {
    const res = await apiFetch(`${API_BASE}/schedule-ai/settings`)
    const data = await res.json()
    if (!res.ok) throw new Error(data.error || 'Failed to load AI settings')
    settings = data
    $('ai-key-missing').hidden = !!data.has_api_key
    return data
  }

  window.onAiCompanyChange = async function onAiCompanyChange() {
    const sel = $('ai-company')
    if (drafts.length && sel.value !== aiCompany) {
      if (!confirm('Switching company discards the trips in review. Continue?')) {
        sel.value = aiCompany
        return
      }
      clearReview()
    }
    aiCompany = sel.value
    companyMeta = null
    currentCount = 0
    $('ai-company-help').textContent = ''
    updateRunButton()
    if (!aiCompany) return

    const company = aiCompany
    try {
      const res = await apiFetch(`${API_BASE}/schedules?company=${encodeURIComponent(company)}&full=1`)
      const data = await res.json()
      if (!res.ok) throw new Error(data.error || 'Failed to load company')
      if (company !== aiCompany) return
      companyMeta = data.meta || null
      currentCount = (data.schedules || []).length
      if (companyMeta) rules().fillDatalists(companyMeta)
      $('ai-company-help').textContent = `${company} currently has ${currentCount} trip${currentCount === 1 ? '' : 's'}.`
    } catch (e) {
      $('ai-company-help').textContent = e.message
    }
  }

  function updateRunButton() {
    $('ai-run-btn').disabled = busy || !aiCompany || !upload
  }

  // ── Photo ─────────────────────────────────────────────────

  async function prepareImage(file) {
    const type = file.type || (/\.(heic|heif)$/i.test(file.name) ? 'image/heic' : '')
    try {
      const bmp = await createImageBitmap(file)
      const scale = Math.min(1, MAX_DIM / Math.max(bmp.width, bmp.height))
      if (scale === 1 && /^image\/(jpeg|png|webp)$/.test(type) && file.size <= 4 * 1024 * 1024) {
        bmp.close()
        return { blob: file, type }
      }
      const canvas = document.createElement('canvas')
      canvas.width = Math.round(bmp.width * scale)
      canvas.height = Math.round(bmp.height * scale)
      canvas.getContext('2d').drawImage(bmp, 0, 0, canvas.width, canvas.height)
      bmp.close()
      const blob = await new Promise((resolve) => canvas.toBlob(resolve, 'image/jpeg', 0.9))
      if (blob) return { blob, type: 'image/jpeg' }
    } catch {
      // Browser can't decode it (e.g. HEIC outside Safari) — send the original.
    }
    return { blob: file, type }
  }

  async function onFileChosen(file) {
    if (!file) return
    const okType =
      /^image\/(jpeg|png|webp|heic|heif)$/i.test(file.type) || /\.(jpe?g|png|webp|heic|heif)$/i.test(file.name)
    if (!okType) return toast('Choose a JPEG, PNG, WebP, or HEIC photo', 'err')

    const prepared = await prepareImage(file)
    if (prepared.blob.size > 14 * 1024 * 1024) return toast('Photo is too large (max 14 MB)', 'err')
    if (upload?.previewUrl) URL.revokeObjectURL(upload.previewUrl)
    upload = { ...prepared, name: file.name, previewUrl: URL.createObjectURL(prepared.blob) }

    const img = $('ai-drop-preview')
    img.onerror = () => {
      img.hidden = true
      $('ai-drop-empty').hidden = false
      $('ai-drop-empty').querySelector('strong').textContent = 'Photo attached (no preview in this browser)'
    }
    img.src = upload.previewUrl
    img.hidden = false
    $('ai-drop-empty').hidden = true
    $('ai-drop-name').textContent = file.name
    $('ai-drop-name').hidden = false
    updateRunButton()
  }

  // ── Extract ───────────────────────────────────────────────

  function setBusy(on, message = '') {
    busy = on
    const status = $('ai-status')
    clearInterval(busyTimer)
    status.classList.toggle('busy', on)
    status.textContent = message
    if (on) {
      const started = Date.now()
      busyTimer = setInterval(() => {
        status.textContent = `${message} ${Math.round((Date.now() - started) / 1000)}s`
      }, 1000)
    }
    updateRunButton()
  }

  window.runAiExtract = async function runAiExtract() {
    if (!aiCompany) return toast('Pick a company first', 'err')
    if (!upload) return toast('Choose a schedule photo first', 'err')
    if (drafts.length && !confirm('Replace the trips currently in review with a new read?')) return

    const started = Date.now()
    setBusy(true, 'Reading schedule… this can take up to a minute.')
    try {
      const form = new FormData()
      form.append('company', aiCompany)
      form.append('note', $('ai-note').value.trim())
      form.append('image', new File([upload.blob], upload.name, { type: upload.type }))
      const res = await apiFetch(`${API_BASE}/schedule-ai/extract`, { method: 'POST', body: form })
      const data = await res.json().catch(() => ({}))
      if (!res.ok) throw new Error(data.error || `Extraction failed (${res.status})`)

      drafts = (data.trips || []).map((t) => ({
        id: nextDraftId++,
        include: true,
        edited: false,
        trip: { ...t.trip, company: aiCompany },
        serverErrors: t.errors || [],
        confidence: t.confidence,
        unreadable: t.unreadable_fields || [],
      }))
      currentCount = data.current_count ?? currentCount
      plan = null

      $('ai-photo').src = upload.previewUrl
      $('ai-photo-open').href = upload.previewUrl
      const notes = $('ai-photo-notes')
      notes.hidden = !data.photo_notes
      notes.textContent = data.photo_notes ? `Note from the AI: ${data.photo_notes}` : ''
      $('ai-done').hidden = true
      $('ai-review').hidden = false
      renderAiTable()
      $('ai-review').scrollIntoView({ behavior: 'smooth', block: 'start' })

      const secs = Math.round((Date.now() - started) / 1000)
      setBusy(false, `Read ${drafts.length} trip${drafts.length === 1 ? '' : 's'} with ${data.model} in ${secs}s.`)
      if (!drafts.length) toast('No trips found in that photo — try a clearer shot', 'err')
    } catch (e) {
      setBusy(false, '')
      toast(e.message, 'err')
    }
  }

  // ── Review table ──────────────────────────────────────────

  function tripKey(t) {
    const n = rules().normalizeTime(t.departure_time).value || ''
    return [t.origin, t.destination, n, t.days_of_operation].map((v) => String(v || '').trim().toLowerCase()).join('|')
  }

  function issuesFor(d, dupKeys) {
    const { errors, warnings } = rules().validate(d.trip)
    const outErrors = !d.edited && d.serverErrors.length ? d.serverErrors : errors
    const outWarnings = [...warnings]
    if (!d.edited) {
      if (d.unreadable.length) outWarnings.unshift(`AI couldn't read: ${d.unreadable.join(', ')}`)
      if (typeof d.confidence === 'number' && d.confidence < LOW_CONFIDENCE) {
        outWarnings.unshift(`AI was unsure about this trip (${Math.round(d.confidence * 100)}%)`)
      }
    }
    if (d.include && dupKeys.get(tripKey(d.trip)) > 1) outWarnings.unshift('Same as another trip in this photo')
    return { errors: outErrors, warnings: outWarnings }
  }

  function duplicateKeys() {
    const counts = new Map()
    for (const d of drafts) {
      if (!d.include) continue
      const k = tripKey(d.trip)
      counts.set(k, (counts.get(k) || 0) + 1)
    }
    return counts
  }

  function compareTrips(a, b) {
    const t = (x) => rules().timeToMinutes(rules().normalizeTime(x.trip.departure_time).value) ?? 9999
    return (
      String(a.trip.origin || '').localeCompare(String(b.trip.origin || '')) ||
      String(a.trip.destination || '').localeCompare(String(b.trip.destination || '')) ||
      t(a) - t(b)
    )
  }

  function planPill(d) {
    const p = plan?.byDraft.get(d.id)
    if (!p) return ''
    if (p.type === 'add') return '<span class="ai-pill ai-pill-new">New trip</span>'
    if (p.type === 'same') return `<span class="ai-pill ai-pill-same">Unchanged · BID ${p.bid}</span>`
    const fields = p.changed.map((c) => FIELD_LABELS[c] || c).join(', ')
    return `<span class="ai-pill ai-pill-chg">Updates BID ${p.bid}</span><span class="ai-check-detail">Changes ${escHtml(fields)}</span>`
  }

  function draftRowHtml(d, dupKeys) {
    const t = d.trip
    const { errors, warnings } = issuesFor(d, dupKeys)
    let check
    if (errors.length) {
      check = `<span class="ai-pill ai-pill-err">Fix ${errors.length}</span><span class="ai-check-detail">${escHtml(errors[0])}</span>`
    } else if (warnings.length) {
      check = `<span class="ai-pill ai-pill-warn">Check</span><span class="ai-check-detail" title="${escAttr(warnings.join('\n'))}">${escHtml(warnings[0])}${warnings.length > 1 ? ` (+${warnings.length - 1} more)` : ''}</span>`
    } else {
      check = `<span class="ai-pill ai-pill-ok">${d.edited ? 'Edited' : 'Looks good'}</span>`
    }
    const stops = (t.stops || []).map((s) => escHtml(s.location)).join(' → ')
    return `<tr class="${d.include ? '' : 'excluded'}">
      <td><input type="checkbox" data-include="${d.id}" ${d.include ? 'checked' : ''} aria-label="Include this trip"></td>
      <td class="col-check"><div class="ai-check">${check}${planPill(d)}</div></td>
      <td class="sch-time">${escHtml(t.departure_time || '—')}</td>
      <td class="sch-time sch-time-muted">${escHtml(t.arrival_time || '—')}</td>
      <td class="col-route">
        <div class="sch-route-main">${escHtml(t.origin || '?')} → ${escHtml(t.destination || '?')}</div>
        ${stops ? `<div class="sch-route-sub">${stops}</div>` : ''}
        ${t.notes ? `<div class="sch-route-sub">Note: ${escHtml(t.notes)}</div>` : ''}
      </td>
      <td class="col-days">${t.days_of_operation ? `<span class="sch-chip">${escHtml(t.days_of_operation)}</span>` : '—'}</td>
      <td style="font-size:12px;">${escHtml(t.service_type || '—')}</td>
      <td><div class="td-actions">
        <button class="btn btn-edit" data-edit="${d.id}">Edit</button>
        <button class="btn btn-danger-sm" data-remove="${d.id}">Remove</button>
      </div></td>
    </tr>`
  }

  function renderAiTable() {
    const dupKeys = duplicateKeys()
    const sorted = drafts.slice().sort(compareTrips)
    $('ai-table-body').innerHTML = sorted.length
      ? sorted.map((d) => draftRowHtml(d, dupKeys)).join('')
      : '<tr><td colspan="8"><div class="empty"><div class="empty-icon"></div>No trips in review. Add one, or read another photo.</div></td></tr>'

    const included = drafts.filter((d) => d.include)
    const needFix = included.filter((d) => issuesFor(d, dupKeys).errors.length).length
    $('ai-trip-count').textContent = `(${drafts.length})`
    $('ai-compare-note').textContent = `Photo: ${drafts.length} trip${drafts.length === 1 ? '' : 's'} · ${aiCompany} now: ${currentCount}`
    $('ai-footer-note').textContent =
      `${included.length} of ${drafts.length} included` + (needFix ? ` · ${needFix} need${needFix === 1 ? 's' : ''} fixing` : '')
    $('ai-check-all').checked = drafts.length > 0 && included.length === drafts.length
    $('ai-review-btn').disabled = !included.length
  }

  function invalidatePlan() {
    plan = null
  }

  function findDraft(id) {
    return drafts.find((d) => d.id === Number(id))
  }

  function editDraft(d) {
    window.openScheduleDraftEditor(
      { ...d.trip, company: aiCompany },
      (payload) => {
        d.trip = { ...payload, company: aiCompany }
        d.edited = true
        invalidatePlan()
        renderAiTable()
      },
      { title: 'Edit extracted trip' }
    )
  }

  window.addAiTrip = function addAiTrip() {
    window.openScheduleDraftEditor(
      { company: aiCompany, phone_number: companyMeta?.phone_number || '', stops: [] },
      (payload) => {
        drafts.push({
          id: nextDraftId++,
          include: true,
          edited: true,
          trip: { ...payload, company: aiCompany },
          serverErrors: [],
          confidence: null,
          unreadable: [],
        })
        invalidatePlan()
        renderAiTable()
      },
      { title: 'Add missing trip' }
    )
  }

  function clearReview() {
    drafts = []
    plan = null
    $('ai-review').hidden = true
    $('ai-table-body').innerHTML = ''
  }

  window.discardAiReview = function discardAiReview() {
    if (drafts.length && !confirm('Discard all trips in this review?')) return
    clearReview()
    $('ai-status').textContent = ''
  }

  // ── Review + apply ────────────────────────────────────────

  async function postApply(dryRun) {
    const included = drafts.filter((d) => d.include)
    const res = await apiFetch(`${API_BASE}/schedule-ai/apply`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        company: aiCompany,
        trips: included.map((d) => d.trip),
        remove_missing: $('ai-remove-missing').checked,
        dry_run: dryRun,
      }),
    })
    const data = await res.json().catch(() => ({}))
    if (!res.ok) {
      for (const { index, errors } of data.errors_by_trip || []) {
        const d = included[index]
        if (d) {
          d.serverErrors = errors
          d.edited = false
        }
      }
      if (data.errors_by_trip) renderAiTable()
      throw new Error(data.error || 'Request failed')
    }
    return { data, included }
  }

  window.reviewAiChanges = async function reviewAiChanges() {
    const dupKeys = duplicateKeys()
    const included = drafts.filter((d) => d.include)
    if (!included.length) return toast('Tick at least one trip to import', 'err')
    const blocking = included.filter((d) => issuesFor(d, dupKeys).errors.length)
    if (blocking.length) {
      return toast(`${blocking.length} included trip${blocking.length === 1 ? ' needs' : 's need'} fixing first (or untick ${blocking.length === 1 ? 'it' : 'them'})`, 'err')
    }

    const btn = $('ai-review-btn')
    btn.disabled = true
    try {
      const { data, included: sent } = await postApply(true)
      const byDraft = new Map()
      for (const a of data.plan.add) byDraft.set(sent[a.index].id, { type: 'add' })
      for (const u of data.plan.update) byDraft.set(sent[u.index].id, { type: 'update', bid: u.bid, changed: u.changed })
      for (const s of data.plan.same) byDraft.set(sent[s.index].id, { type: 'same', bid: s.bid })
      plan = { data, byDraft, sent }
      renderAiTable()
      renderAiApplyCounts()
      $('ai-apply-modal').classList.add('open')
      if (window.AdminIcons) window.AdminIcons.apply($('ai-apply-modal'))
    } catch (e) {
      toast(e.message, 'err')
    } finally {
      btn.disabled = false
    }
  }

  function tripLine(t) {
    return `${escHtml(t.departure_time || '—')} · ${escHtml(t.origin || '?')} → ${escHtml(t.destination || '?')} <span>· ${escHtml(t.days_of_operation || '')}</span>`
  }

  function listBlock(title, items, open) {
    if (!items.length) return ''
    return `<details class="ai-apply-list"${open ? ' open' : ''}><summary>${escHtml(title)} (${items.length})</summary><ul>${items
      .map((i) => `<li>${i}</li>`)
      .join('')}</ul></details>`
  }

  window.renderAiApplyCounts = function renderAiApplyCounts() {
    if (!plan) return
    const { data, sent } = plan
    const removeMissing = $('ai-remove-missing').checked
    const removeCount = removeMissing ? data.plan.remove.length : 0
    const counts = [
      ['New', data.plan.add.length, ''],
      ['Updated', data.plan.update.length, ''],
      ['Unchanged', data.plan.same.length, ''],
      [removeMissing ? 'Removed' : 'Kept (not in photo)', removeMissing ? removeCount : data.plan.remove.length, removeMissing ? 'remove' : ''],
    ]
    $('ai-apply-counts').innerHTML = counts
      .map(([l, n, cls]) => `<div class="ai-apply-count ${cls}"><div class="n">${n}</div><div class="l">${escHtml(l)}</div></div>`)
      .join('')

    $('ai-apply-lists').innerHTML = [
      listBlock('New trips', data.plan.add.map((a) => tripLine(sent[a.index].trip)), true),
      listBlock(
        'Updated trips',
        data.plan.update.map(
          (u) =>
            `${tripLine(sent[u.index].trip)} <span>· BID ${u.bid} · ${escHtml(u.changed.map((c) => FIELD_LABELS[c] || c).join(', '))}</span>`
        ),
        true
      ),
      removeMissing
        ? listBlock(
            'Removed — not in the photo',
            data.plan.remove.map(
              (r) =>
                `${tripLine(r)} <span>· BID ${r.bid}</span>${
                  r.active_sessions ? ` <strong class="ai-active-driver">· driver on it now</strong>` : ''
                }`
            ),
            true
          )
        : '',
    ].join('')

    const stranded = removeMissing ? data.plan.remove.filter((r) => r.active_sessions) : []
    const warning = $('ai-apply-warning')
    warning.hidden = !stranded.length
    warning.textContent = stranded.length
      ? `${stranded.length} trip${stranded.length === 1 ? '' : 's'} being removed ${stranded.length === 1 ? 'has' : 'have'} a driver on ${stranded.length === 1 ? 'it' : 'them'} right now. Their session will stay open but lose its route — consider waiting, or untick “Remove trips” below.`
      : ''

    $('ai-remove-row').hidden = !data.plan.remove.length
    $('ai-apply-title').textContent = `Update ${aiCompany} schedule`
    const total = data.plan.add.length + data.plan.update.length + removeCount
    const btn = $('ai-apply-btn')
    btn.disabled = total === 0
    btn.textContent = total === 0 ? 'No changes to apply' : removeCount ? `Replace ${aiCompany} schedule` : 'Apply changes'
  }

  window.applyAiImport = async function applyAiImport() {
    const btn = $('ai-apply-btn')
    btn.disabled = true
    const label = btn.textContent
    btn.textContent = 'Applying…'
    try {
      const { data } = await postApply(false)
      closeModals()
      lastImport = { batchId: data.batch_id, company: aiCompany }
      const c = data.counts
      const parts = [
        `${c.add} added`,
        `${c.update} updated`,
        c.remove ? `${c.remove} removed` : null,
        `${c.same} unchanged`,
        c.kept_missing ? `${c.kept_missing} kept (not in photo)` : null,
      ].filter(Boolean)
      $('ai-done-title').textContent = data.unchanged ? 'Nothing changed' : `${aiCompany} schedule updated`
      $('ai-done-desc').textContent = `${parts.join(' · ')}. Riders get the new schedule on their next app sync.`
      $('ai-undo-btn').hidden = !data.batch_id
      $('ai-undo-btn').disabled = false
      $('ai-undo-btn').textContent = 'Undo this import'
      clearReview()
      currentCount = c.current + c.add - c.remove
      $('ai-company-help').textContent = `${aiCompany} currently has ${currentCount} trip${currentCount === 1 ? '' : 's'}.`
      $('ai-done').hidden = false
      if (window.AdminIcons) window.AdminIcons.apply($('ai-done'))
      $('ai-done').scrollIntoView({ behavior: 'smooth', block: 'start' })
      toast('Schedule updated', 'ok')
    } catch (e) {
      toast(e.message, 'err')
      btn.textContent = label
    } finally {
      btn.disabled = false
    }
  }

  window.undoAiImport = async function undoAiImport() {
    if (!lastImport?.batchId) return
    const btn = $('ai-undo-btn')
    btn.disabled = true
    const undone = await window.undoScheduleBatch(lastImport.batchId)
    if (undone) {
      $('ai-done-title').textContent = 'Import undone'
      $('ai-done-desc').textContent = `${lastImport.company} is back to how it was before this import.`
      btn.textContent = 'Undone'
      onAiCompanyChange()
    } else {
      btn.disabled = false
    }
  }

  window.viewAiCompanyInManual = function viewAiCompanyInManual() {
    const company = lastImport?.company || aiCompany
    const sel = $('sch-company')
    if (sel && company) sel.value = company
    showSection('schedules-manual')
  }

  window.resetAiUpload = function resetAiUpload() {
    $('ai-done').hidden = true
    clearReview()
    if (upload?.previewUrl) URL.revokeObjectURL(upload.previewUrl)
    upload = null
    $('ai-file').value = ''
    $('ai-note').value = ''
    $('ai-drop-preview').hidden = true
    $('ai-drop-preview').removeAttribute('src')
    $('ai-drop-name').hidden = true
    $('ai-drop-empty').hidden = false
    $('ai-drop-empty').querySelector('strong').textContent = 'Drop a schedule photo here'
    $('ai-status').textContent = ''
    updateRunButton()
    $('ai-upload-card').scrollIntoView({ behavior: 'smooth', block: 'start' })
  }

  // ── Settings ──────────────────────────────────────────────

  function setPromptState() {
    const v = $('ai-prompt').value.trim()
    const isDefault = settings && v === settings.default_system_prompt.trim()
    $('ai-prompt-state').textContent = isDefault ? '(default)' : '(customized)'
  }

  window.openAiSettings = async function openAiSettings() {
    try {
      const s = await fetchSettings()
      $('ai-model').value = s.model === s.default_model ? '' : s.model
      $('ai-model').placeholder = s.default_model
      $('ai-prompt').value = s.system_prompt
      setPromptState()
      const key = $('ai-settings-key')
      key.hidden = s.has_api_key
      key.innerHTML = 'No <code>GEMINI_API_KEY</code> secret found. Add it in Cloudflare Pages → Settings → Variables and secrets, then redeploy.'
      $('ai-settings-modal').classList.add('open')
      if (window.AdminIcons) window.AdminIcons.apply($('ai-settings-modal'))
    } catch (e) {
      toast(e.message, 'err')
    }
  }

  window.resetAiPrompt = function resetAiPrompt() {
    if (!settings) return
    $('ai-prompt').value = settings.default_system_prompt
    setPromptState()
    toast('Default instructions restored — save to keep them', 'ok')
  }

  window.saveAiSettings = async function saveAiSettings() {
    const prompt = $('ai-prompt').value.trim()
    const btn = $('ai-settings-save')
    btn.disabled = true
    try {
      const res = await apiFetch(`${API_BASE}/schedule-ai/settings`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          system_prompt: prompt === settings.default_system_prompt.trim() ? '' : prompt,
          model: $('ai-model').value.trim(),
        }),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.error || 'Save failed')
      settings = data
      closeModals()
      toast('AI settings saved', 'ok')
    } catch (e) {
      toast(e.message, 'err')
    } finally {
      btn.disabled = false
    }
  }

  // ── Wiring ────────────────────────────────────────────────

  const drop = $('ai-drop')
  $('ai-file')?.addEventListener('change', (e) => onFileChosen(e.target.files[0]))
  drop?.addEventListener('dragover', (e) => {
    e.preventDefault()
    drop.classList.add('dragging')
  })
  drop?.addEventListener('dragleave', () => drop.classList.remove('dragging'))
  drop?.addEventListener('drop', (e) => {
    e.preventDefault()
    drop.classList.remove('dragging')
    onFileChosen(e.dataTransfer.files[0])
  })

  $('ai-table-body')?.addEventListener('change', (e) => {
    const id = e.target.dataset.include
    if (!id) return
    const d = findDraft(id)
    if (!d) return
    d.include = e.target.checked
    invalidatePlan()
    renderAiTable()
  })
  $('ai-table-body')?.addEventListener('click', (e) => {
    const btn = e.target.closest('button')
    if (!btn) return
    if (btn.dataset.edit) {
      const d = findDraft(btn.dataset.edit)
      if (d) editDraft(d)
    } else if (btn.dataset.remove) {
      drafts = drafts.filter((d) => d.id !== Number(btn.dataset.remove))
      invalidatePlan()
      renderAiTable()
    }
  })
  $('ai-check-all')?.addEventListener('change', (e) => {
    for (const d of drafts) d.include = e.target.checked
    invalidatePlan()
    renderAiTable()
  })
  $('ai-prompt')?.addEventListener('input', setPromptState)
})()
