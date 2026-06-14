(function () {
  'use strict';

  const FEATURE_ORDER = [
    'Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
    'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
    'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std',
    'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean', 'Bwd Packet Length Std',
    'Flow Bytes/s', 'Flow Packets/s',
    'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
    'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
    'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min',
    'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags',
    'Fwd Header Length', 'Bwd Header Length',
    'Fwd Packets/s', 'Bwd Packets/s',
    'Min Packet Length', 'Max Packet Length', 'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance',
    'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count',
    'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count',
    'Down/Up Ratio', 'Average Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size',
    'Fwd Header Length.1',
    'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate',
    'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate',
    'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes',
    'Init_Win_bytes_forward', 'Init_Win_bytes_backward',
    'act_data_pkt_fwd', 'min_seg_size_forward',
    'Active Mean', 'Active Std', 'Active Max', 'Active Min',
    'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
  ];

  const state = {
    interfaces: [],
    recentKeys: new Set(),
    acknowledgedAttackTs: 0,
    csvFile: null,
    latestData: null,
    reduceMotion: window.matchMedia('(prefers-reduced-motion: reduce)').matches,
    frame: 0,
    canvasReady: false,
    tripwireMode: 'armed',
    tripwireAnimationId: null,
    modalTrigger: null
  };

  const els = {
    activeInterface: document.getElementById('activeInterface'),
    captureChip: document.getElementById('captureChip'),
    captureChipLabel: document.getElementById('captureChipLabel'),
    toggleSniffingBtn: document.getElementById('toggleSniffingBtn'),
    tripwirePanel: document.getElementById('tripwirePanel'),
    tripwireCanvas: document.getElementById('tripwireCanvas'),
    tripwireLabel: document.getElementById('tripwireLabel'),
    tripwireStats: document.getElementById('tripwireStats'),
    tripwireLastSeen: document.getElementById('tripwireLastSeen'),
    tripwireAcknowledged: document.getElementById('tripwireAcknowledged'),
    tripwireAlertText: document.getElementById('tripwireAlertText'),
    acknowledgeBtn: document.getElementById('acknowledgeBtn'),
    statPackets: document.getElementById('statPackets'),
    statFlagged: document.getElementById('statFlagged'),
    statThreatRate: document.getElementById('statThreatRate'),
    statActiveFlows: document.getElementById('statActiveFlows'),
    statPacketsMeta: document.getElementById('statPacketsMeta'),
    statFlaggedMeta: document.getElementById('statFlaggedMeta'),
    statThreatRateMeta: document.getElementById('statThreatRateMeta'),
    statModelMeta: document.getElementById('statModelMeta'),
    eventCount: document.getElementById('eventCount'),
    eventRate: document.getElementById('eventRate'),
    eventRows: document.getElementById('eventRows'),
    csvDropzone: document.getElementById('csvDropzone'),
    csvFileInput: document.getElementById('csvFileInput'),
    csvFileInputMirror: document.getElementById('csvFileInputMirror'),
    predictCsvBtn: document.getElementById('predictCsvBtn'),
    csvResult: document.getElementById('csvResult'),
    ifaceSelect: document.getElementById('ifaceSelect'),
    setIfaceBtn: document.getElementById('setIfaceBtn'),
    currentIface: document.getElementById('currentIface'),
    statusInterface: document.getElementById('statusInterface'),
    statusLastAttack: document.getElementById('statusLastAttack'),
    statusChannelState: document.getElementById('statusChannelState'),
    alertChannelPill: document.getElementById('alertChannelPill'),
    statusChannelMode: document.getElementById('statusChannelMode'),
    statusConfiguredCount: document.getElementById('statusConfiguredCount'),
    statusLastDispatch: document.getElementById('statusLastDispatch'),
    alertDispatchSummary: document.getElementById('alertDispatchSummary'),
    alertDispatchResult: document.getElementById('alertDispatchResult'),
    sendAllAlertsBtn: document.getElementById('sendAllAlertsBtn'),
    singleSampleInput: document.getElementById('singleSampleInput'),
    predictSingleBtn: document.getElementById('predictSingleBtn'),
    singleResult: document.getElementById('singleResult'),
    flowModalBackdrop: document.getElementById('flowModalBackdrop'),
    flowModalTitle: document.getElementById('flowModalTitle'),
    flowModalSummary: document.getElementById('flowModalSummary'),
    flowModalContent: document.getElementById('flowModalContent'),
    flowModalClose: document.getElementById('flowModalClose')
  };

  function setText(element, value) {
    if (element) {
      element.textContent = value;
    }
  }

  function setValue(element, value) {
    if (element) {
      element.value = value;
    }
  }

  function escapeHtml(value) {
    return String(value)
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#39;');
  }

  function pad(value) {
    return String(value).padStart(2, '0');
  }

  function formatTime(ts) {
    if (!ts) {
      return '--:--:--';
    }
    const date = new Date(ts * 1000);
    return [pad(date.getHours()), pad(date.getMinutes()), pad(date.getSeconds())].join(':');
  }

  function formatDateTime(ts) {
    if (!ts) {
      return 'Never';
    }
    return new Date(ts * 1000).toLocaleString();
  }

  function formatPercent(value) {
    return `${value.toFixed(2)}%`;
  }

  function formatCount(value) {
    return new Intl.NumberFormat('en-US').format(value || 0);
  }

  function formatValue(value) {
    if (value === null || value === undefined || value === '') {
      return '-';
    }
    if (typeof value === 'number') {
      return Number.isInteger(value) ? String(value) : value.toFixed(4).replace(/0+$/, '').replace(/\.$/, '');
    }
    return String(value);
  }

  function eventKey(item) {
    return [item.ts, item.src_ip, item.src_port, item.dst_ip, item.dst_port, item.binary_label].join('|');
  }

  function setCaptureState(sniffing) {
    if (els.captureChip) {
      els.captureChip.classList.toggle('is-live', sniffing);
    }
    setText(els.captureChipLabel, sniffing ? 'CAPTURING' : 'IDLE');

    if (els.toggleSniffingBtn) {
      const label = els.toggleSniffingBtn.querySelector('span');
      if (label) {
        label.textContent = sniffing ? 'Stop capture' : 'Start capture';
      }
      els.toggleSniffingBtn.setAttribute('aria-pressed', sniffing ? 'true' : 'false');
    }

    setText(els.statusChannelState, sniffing ? 'Monitoring live traffic' : 'Capture paused');
  }

  function updateInterfaceLabel(selected) {
    const label = selected || 'auto';
    setText(els.activeInterface, `iface: ${label}`);
    setText(els.currentIface, `Selected: ${label}`);
    setText(els.statusInterface, label);
  }

  function resizeCanvas() {
    const canvas = els.tripwireCanvas;
    if (!canvas) {
      return;
    }

    const dpr = window.devicePixelRatio || 1;
    const width = canvas.clientWidth || 1;
    const height = canvas.clientHeight || 1;
    const nextWidth = Math.max(1, Math.floor(width * dpr));
    const nextHeight = Math.max(1, Math.floor(height * dpr));

    if (canvas.width !== nextWidth || canvas.height !== nextHeight) {
      canvas.width = nextWidth;
      canvas.height = nextHeight;
      state.canvasReady = true;
    }

    const ctx = canvas.getContext('2d');
    if (ctx) {
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    }
  }

  function drawTripwireFrame() {
    const canvas = els.tripwireCanvas;
    if (!canvas) {
      return;
    }

    const ctx = canvas.getContext('2d');
    if (!ctx) {
      return;
    }

    const width = canvas.clientWidth || 1;
    const height = canvas.clientHeight || 1;
    ctx.clearRect(0, 0, width, height);

    const baseline = height * 0.58;
    const step = Math.max(8, Math.floor(width / 120));
    const points = [];
    const tripped = state.tripwireMode === 'tripped';
    const amplitude = tripped ? height * 0.22 : height * 0.08;
    const stroke = tripped ? 'rgba(255, 107, 110, 0.95)' : 'rgba(91, 185, 139, 0.72)';
    const wash = tripped ? 'rgba(229, 72, 77, 0.16)' : 'rgba(91, 185, 139, 0.08)';

    ctx.fillStyle = wash;
    ctx.fillRect(0, 0, width, height);

    for (let x = 0; x <= width; x += step) {
      const wave = Math.sin((x / 28) + state.frame / 18) * amplitude;
      const shimmer = Math.cos((x / 11) - state.frame / 16) * amplitude * 0.32;
      let y = baseline - wave - shimmer;
      if (tripped && x > width * 0.68 && x < width * 0.78) {
        y -= amplitude * 1.8 * Math.sin((x - width * 0.68) * 1.2);
      }
      points.push([x, y]);
    }

    ctx.beginPath();
    ctx.moveTo(points[0][0], points[0][1]);
    points.slice(1).forEach(([x, y]) => ctx.lineTo(x, y));
    ctx.strokeStyle = stroke;
    ctx.lineWidth = tripped ? 2.5 : 1.75;
    ctx.stroke();

    ctx.beginPath();
    ctx.moveTo(0, baseline + height * 0.05);
    ctx.lineTo(width, baseline + height * 0.05);
    ctx.strokeStyle = 'rgba(92, 107, 130, 0.15)';
    ctx.lineWidth = 1;
    ctx.stroke();
  }

  function animateTripwire() {
    if (!els.tripwireCanvas) {
      return;
    }
    if (state.reduceMotion) {
      resizeCanvas();
      drawTripwireFrame();
      return;
    }
    state.frame += 1;
    resizeCanvas();
    drawTripwireFrame();
    state.tripwireAnimationId = window.requestAnimationFrame(animateTripwire);
  }

  function setTripwireMode(mode, latestAttack) {
    if (!els.tripwirePanel || !els.tripwireCanvas || !els.tripwireLabel) {
      return;
    }

    const tripped = mode === 'tripped';
    state.tripwireMode = mode;
    els.tripwirePanel.classList.toggle('is-tripped', tripped);
    els.tripwireCanvas.classList.toggle('is-armed', !tripped);
    els.tripwireLabel.classList.toggle('is-tripped', tripped);
    els.tripwirePanel.setAttribute('role', tripped ? 'alert' : 'status');

    if (tripped && latestAttack) {
      const typeLabel = latestAttack.attack_type ? ` (${latestAttack.attack_type})` : '';
      setText(els.tripwireLabel, `TRIPWIRE · INTRUSION DETECTED — ${latestAttack.src_ip || 'unknown'}${typeLabel}`);
      setText(els.tripwireAlertText, `Tripwire tripped by ${latestAttack.src_ip || 'unknown'}${typeLabel}`);
      setText(els.tripwireAcknowledged, 'ack: pending');
      if (els.acknowledgeBtn) {
        els.acknowledgeBtn.classList.remove('button--ghost');
        els.acknowledgeBtn.classList.add('button--accent');
      }
    } else {
      setText(els.tripwireLabel, 'TRIPWIRE · ARMED');
      setText(els.tripwireAlertText, 'Tripwire armed');
      setText(els.tripwireAcknowledged, state.acknowledgedAttackTs ? `ack: ${formatTime(state.acknowledgedAttackTs)}` : 'ack: not yet');
      if (els.acknowledgeBtn) {
        els.acknowledgeBtn.classList.remove('button--accent');
        els.acknowledgeBtn.classList.add('button--ghost');
      }
    }

    if (state.reduceMotion) {
      resizeCanvas();
      drawTripwireFrame();
    }
  }

  function updateAlertChannels(channels) {
    channels.forEach((channel) => {
      const form = document.querySelector(`[data-alert-config-form][data-channel="${channel.key}"]`);
      const badge = document.getElementById(`channelBadge-${channel.key}`);
      const destination = document.getElementById(`channelDestination-${channel.key}`);
      const lastResult = document.getElementById(`channelLastResult-${channel.key}`);
      const lastAttempt = document.getElementById(`channelLastAttempt-${channel.key}`);
      const hint = document.getElementById(`channelHint-${channel.key}`);
      const enabled = document.getElementById(`channelEnabled-${channel.key}`);
      const feedback = document.getElementById(`channelFeedback-${channel.key}`);

      if (badge) {
        if (!channel.configured) {
          badge.textContent = 'Not configured';
        } else if (!channel.enabled) {
          badge.textContent = 'Disabled';
        } else if (channel.last_result === 'failed') {
          badge.textContent = 'Delivery failed';
        } else {
          badge.textContent = 'Enabled';
        }

        badge.classList.remove('is-ready', 'is-offline', 'is-failed', 'is-paused');
        if (!channel.configured) {
          badge.classList.add('is-offline');
        } else if (!channel.enabled) {
          badge.classList.add('is-paused');
        } else if (channel.last_result === 'failed') {
          badge.classList.add('is-failed');
        } else {
          badge.classList.add('is-ready');
        }
      }

      if (enabled) {
        enabled.checked = Boolean(channel.enabled);
      }

      if (feedback) {
        if (channel.configured && channel.enabled) {
          feedback.textContent = 'Ready to send alerts.';
        } else if (channel.configured) {
          feedback.textContent = 'Configured but disabled.';
        } else {
          feedback.textContent = 'Not configured yet.';
        }
      }

      (channel.fields || []).forEach((field, index) => {
        const input = form ? form.querySelector(`[name="${field.env}"]`) : null;
        const secretState = document.getElementById(`fieldSecretState-${channel.key}-${field.env}`);
        if (input && !field.secret && document.activeElement !== input) {
          setValue(input, field.value || '');
        }
        if (secretState) {
          secretState.textContent = field.configured
            ? 'Saved secret will be reused if you leave this blank.'
            : 'Enter the secret to configure this channel.';
        }
      });

      setText(destination, channel.destination || 'Not set');
      setText(lastResult, channel.last_message || channel.last_result || 'No attempts yet');
      setText(lastAttempt, formatDateTime(channel.last_attempt_ts));
      setText(hint, channel.hint || '-');
    });
  }

  function updateAlertStatus(data, latestAttack) {
    const totals = data.totals || {};
    const alerts = data.alerts || {};
    const summary = alerts.summary || {};
    const channels = Array.isArray(alerts.channels) ? alerts.channels : [];
    const configuredCount = summary.configured_count || 0;
    const enabledCount = summary.enabled_count || 0;
    const attackTs = totals.last_attack_ts || (latestAttack ? latestAttack.ts : null);
    if (attackTs) {
      const type = totals.last_attack_type || (latestAttack && latestAttack.attack_type) || '';
      const typeSuffix = type ? ` (${type})` : '';
      setText(els.statusLastAttack, `${formatTime(attackTs)} · ${totals.last_attack_src_ip || (latestAttack && latestAttack.src_ip) || 'unknown'}${typeSuffix}`);
      setText(els.alertChannelPill, 'Attention');
    } else if (enabledCount > 0) {
      setText(els.statusLastAttack, 'None yet');
      setText(els.alertChannelPill, 'Armed');
    } else if (configuredCount > 0) {
      setText(els.statusLastAttack, 'None yet');
      setText(els.alertChannelPill, 'Channels disabled');
    } else {
      setText(els.statusLastAttack, 'None yet');
      setText(els.alertChannelPill, 'Configure channels');
    }

    if (enabledCount > 0) {
      setText(els.statusChannelMode, 'Multi-channel broadcast');
    } else if (configuredCount > 0) {
      setText(els.statusChannelMode, 'Channels configured but disabled');
    } else {
      setText(els.statusChannelMode, 'Log only until a channel is configured');
    }

    setText(els.statusConfiguredCount, `${enabledCount} enabled / ${configuredCount} configured`);
    setText(
      els.statusLastDispatch,
      summary.last_dispatch_ts ? `${formatDateTime(summary.last_dispatch_ts)} · ${summary.last_dispatch_subject || 'Alert sent'}` : 'No dispatch yet'
    );

    const healthyCount = summary.healthy_count || 0;
    if (enabledCount > 0) {
      setText(els.statusChannelState, `${healthyCount}/${enabledCount} enabled channel${enabledCount === 1 ? '' : 's'} ready for delivery`);
    } else if (configuredCount > 0) {
      setText(els.statusChannelState, 'Channels are saved but currently disabled');
    } else {
      setText(els.statusChannelState, 'Log-only mode until at least one channel is configured');
    }

    updateAlertChannels(channels);
  }

  function renderStats(data) {
    const totals = data.totals || {};
    const packets = totals.packets || 0;
    const total = totals.total || 0;
    const attack = totals.attack || 0;
    const activeFlows = data.active_flows || 0;
    const threatRate = total > 0 ? (attack / total) * 100 : 0;

    setText(els.statPackets, formatCount(packets));
    setText(els.statFlagged, formatCount(attack));
    setText(els.statThreatRate, formatPercent(threatRate));
    setText(els.statActiveFlows, formatCount(activeFlows));
    setText(els.statPacketsMeta, `${formatCount(activeFlows)} active flow${activeFlows === 1 ? '' : 's'}`);
    setText(els.statFlaggedMeta, `${formatCount(attack)} attack flows`);
    setText(els.statThreatRateMeta, total > 0 ? `${formatCount(attack)} / ${formatCount(total)}` : 'attack / total');

    if (els.statFlagged) {
      els.statFlagged.classList.toggle('is-threat', attack > 0);
    }

    const recent = Array.isArray(data.recent) ? data.recent : [];
    const latestTs = totals.last_event_ts || (recent.length ? recent[recent.length - 1].ts : null);
    const recentWindow = latestTs ? recent.filter((item) => latestTs - item.ts <= 60) : recent;
    const flowsPerMinute = recentWindow.length;

    setText(els.eventCount, `${formatCount(recent.length)} flows`);
    setText(els.eventRate, `${formatCount(flowsPerMinute)} flows/min`);
    setText(els.tripwireStats, `${formatCount(flowsPerMinute)} flows/min`);
    setText(els.tripwireLastSeen, `last classification: ${formatTime(latestTs)}`);

    const latestAttack = recent.slice().reverse().find((item) => item.binary_label === 'ATTACK') || null;
    const acknowledged = state.acknowledgedAttackTs || 0;
    const attackTs = totals.last_attack_ts || (latestAttack ? latestAttack.ts : null);
    const tripped = attackTs && attackTs > acknowledged;
    const activeAttack = tripped ? {
      src_ip: totals.last_attack_src_ip || (latestAttack ? latestAttack.src_ip : 'unknown'),
      attack_type: totals.last_attack_type || (latestAttack ? latestAttack.attack_type : null)
    } : null;

    if (activeAttack) {
      setTripwireMode('tripped', activeAttack);
    } else {
      setTripwireMode('armed');
    }

    updateAlertStatus(data, latestAttack);
  }

  function renderFeatureDrawer(features) {
    const items = FEATURE_ORDER.map((name) => {
      const value = features && Object.prototype.hasOwnProperty.call(features, name) ? features[name] : '-';
      return `<div class="detail-grid__item"><span class="detail-grid__key">${escapeHtml(name)}</span><span class="detail-grid__value">${escapeHtml(formatValue(value))}</span></div>`;
    }).join('');

    return `<p class="detail-drawer__title"><span>Flow feature vector</span><span class="verdict-chip is-normal">78 features</span></p><div class="detail-grid">${items}</div>`;
  }

  function openFlowModal(item, trigger) {
    if (!els.flowModalBackdrop || !els.flowModalSummary || !els.flowModalContent) {
      return;
    }

    state.modalTrigger = trigger || null;

    const typeLabel = item.attack_type || (item.binary_label === 'ATTACK' ? 'unknown' : 'BENIGN');
    setText(els.flowModalTitle, `${item.src_ip}:${item.src_port} → ${item.dst_ip}:${item.dst_port}`);

    els.flowModalSummary.innerHTML = [
      ['Captured', formatTime(item.ts)],
      ['Protocol', item.protocol || '-'],
      ['Verdict', item.binary_label || '-'],
      ['Attack type', typeLabel],
      ['Forward packets', formatValue(item.total_fwd_packets)],
      ['Backward packets', formatValue(item.total_bwd_packets)],
      ['Duration (us)', formatValue(item.flow_duration_us)],
      ['Bytes / s', formatValue(item.flow_bytes_per_s)]
    ].map(([label, value]) => (
      `<div class="summary-item"><span class="summary-item__label">${escapeHtml(label)}</span><span class="summary-item__value">${escapeHtml(value)}</span></div>`
    )).join('');

    els.flowModalContent.innerHTML = renderFeatureDrawer(item.features || {});
    els.flowModalBackdrop.hidden = false;
    document.body.classList.add('is-modal-open');
    if (els.flowModalClose) {
      els.flowModalClose.focus();
    }
  }

  function closeFlowModal() {
    if (!els.flowModalBackdrop) {
      return;
    }

    els.flowModalBackdrop.hidden = true;
    document.body.classList.remove('is-modal-open');
    if (state.modalTrigger) {
      state.modalTrigger.focus();
    }
  }

  function renderEventRows(data) {
    if (!els.eventRows) {
      return;
    }

    const items = Array.isArray(data.recent) ? data.recent.slice().reverse() : [];
    const nextKeys = new Set(items.map(eventKey));
    const fragment = document.createDocumentFragment();
    const seenKeys = new Set();
    const colSpan = 7;

    if (!items.length) {
      const row = document.createElement('tr');
      const cell = document.createElement('td');
      cell.colSpan = colSpan;
      cell.className = 'mono mono--low';

      const activeFlows = data.active_flows || 0;
      if (activeFlows > 0) {
        cell.textContent = `${formatCount(activeFlows)} active flow${activeFlows === 1 ? '' : 's'} assembling on ${data.interface || 'auto'}. Flows appear here after they expire or when capture stops.`;
      } else {
        cell.textContent = `No flows classified yet. Capture is armed on ${data.interface || 'auto'}.`;
      }

      row.appendChild(cell);
      fragment.appendChild(row);
      els.eventRows.replaceChildren(fragment);
      state.recentKeys = nextKeys;
      return;
    }

    for (const item of items) {
      const key = eventKey(item);
      seenKeys.add(key);

      const row = document.createElement('tr');
      const isAttack = item.binary_label === 'ATTACK';
      row.className = `event-row ${isAttack ? 'is-attack' : 'is-normal'}`;
      row.tabIndex = 0;
      row.dataset.key = key;
      row.setAttribute('role', 'button');
      row.setAttribute('aria-label', `Inspect flow from ${item.src_ip} to ${item.dst_ip}`);
      if (!state.recentKeys.has(key)) {
        row.classList.add('is-new');
      }

      const verdictClass = isAttack ? 'is-attack' : 'is-normal';
      const verdictLabel = isAttack ? 'ATTACK' : 'BENIGN';
      const attackTypeCell = isAttack
        ? `<span class="verdict-chip is-attack">${escapeHtml(item.attack_type || 'unknown')}</span>`
        : '<span class="mono mono--low">-</span>';

      row.innerHTML = `
        <td class="mono">${escapeHtml(formatTime(item.ts))}</td>
        <td class="mono">${escapeHtml(formatValue(item.src_ip))}:${escapeHtml(formatValue(item.src_port))}</td>
        <td class="mono">${escapeHtml(formatValue(item.dst_ip))}:${escapeHtml(formatValue(item.dst_port))}</td>
        <td class="mono">${escapeHtml(formatValue(item.protocol))}</td>
        <td class="mono hide-sm">${escapeHtml(formatValue(item.total_fwd_packets))} / ${escapeHtml(formatValue(item.total_bwd_packets))}</td>
        <td><span class="verdict-chip ${verdictClass}">${verdictLabel}</span></td>
        <td>${attackTypeCell}</td>
      `;

      row.addEventListener('click', () => openFlowModal(item, row));
      row.addEventListener('keydown', (event) => {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault();
          openFlowModal(item, row);
        }
      });

      fragment.appendChild(row);
    }

    els.eventRows.replaceChildren(fragment);
    state.recentKeys = seenKeys;
    els.eventRows.querySelectorAll('tr.event-row').forEach((row) => {
      window.requestAnimationFrame(() => row.classList.remove('is-new'));
    });
  }

  function prettyPrint(value) {
    return JSON.stringify(value, null, 2);
  }

  async function readJsonResponse(response) {
    const text = await response.text();
    let data;

    try {
      data = text ? JSON.parse(text) : {};
    } catch (error) {
      throw new Error(text || response.statusText || 'Unexpected response');
    }

    if (!response.ok) {
      throw new Error(data.error || response.statusText || 'Request failed');
    }

    return data;
  }

  async function loadInterfaces() {
    if (!els.ifaceSelect) {
      return;
    }

    try {
      const response = await fetch('/interfaces');
      const data = await readJsonResponse(response);
      const interfaces = Array.isArray(data.interfaces) ? data.interfaces : [];
      state.interfaces = interfaces;

      els.ifaceSelect.innerHTML = '';
      interfaces.forEach((item) => {
        const option = document.createElement('option');
        option.value = item.iface;
        option.textContent = item.addr && item.addr !== '0.0.0.0' ? `${item.iface} (${item.addr})` : item.iface;
        els.ifaceSelect.appendChild(option);
      });

      if (data.selected) {
        els.ifaceSelect.value = data.selected;
      }
      updateInterfaceLabel(data.selected || els.ifaceSelect.value || 'auto');
    } catch (error) {
      setText(els.statusChannelState, `Interface load failed: ${error.message}`);
    }
  }

  async function setInterface() {
    if (!els.ifaceSelect) {
      return;
    }

    const iface = els.ifaceSelect.value;
    if (!iface) {
      return;
    }

    try {
      const response = await fetch('/set-interface', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ iface })
      });
      const data = await readJsonResponse(response);
      updateInterfaceLabel(data.selected || iface);
      await fetchLiveStatus();
    } catch (error) {
      setText(els.statusChannelState, `Interface update failed: ${error.message}`);
    }
  }

  async function toggleSniffing() {
    try {
      const response = await fetch('/toggle-sniffing', { method: 'POST' });
      const data = await readJsonResponse(response);
      setCaptureState(Boolean(data.sniffing));

      if (!data.sniffing && data.flushed_flows) {
        setText(els.statusChannelState, `Capture paused · flushed ${formatCount(data.flushed_flows)} active flow${data.flushed_flows === 1 ? '' : 's'}`);
      }

      await fetchLiveStatus();
    } catch (error) {
      setText(els.statusChannelState, `Capture toggle failed: ${error.message}`);
    }
  }

  async function uploadCsv() {
    const file = state.csvFile || (els.csvFileInput && els.csvFileInput.files && els.csvFileInput.files[0]);
    if (!file) {
      setText(els.csvResult, 'Choose a CSV file first.');
      return;
    }

    const form = new FormData();
    form.append('file', file);
    setText(els.csvResult, 'Uploading and predicting...');

    try {
      const response = await fetch('/predict-file', { method: 'POST', body: form });
      const data = await readJsonResponse(response);
      setText(els.csvResult, prettyPrint(data));
    } catch (error) {
      setText(els.csvResult, `Error: ${error.message}`);
    }
  }

  async function predictSingleSample() {
    const row = els.singleSampleInput ? els.singleSampleInput.value.trim() : '';
    if (!row) {
      setText(els.singleResult, 'Paste one comma-separated feature row first.');
      return;
    }

    setText(els.singleResult, 'Predicting sample...');

    try {
      const response = await fetch('/predict-sample', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ row })
      });
      const data = await readJsonResponse(response);
      setText(els.singleResult, prettyPrint(data));
    } catch (error) {
      setText(els.singleResult, `Error: ${error.message}`);
    }
  }

  async function sendTestAlert(channel) {
    setText(els.alertDispatchSummary, `Sending test alert${channel && channel !== 'all' ? ` to ${channel}` : ' to all configured channels'}...`);
    setText(els.alertDispatchResult, 'Sending...');

    try {
      const response = await fetch('/alerts/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ channel: channel || 'all' })
      });
      const data = await readJsonResponse(response);
      const results = Array.isArray(data.results) ? data.results : [];
      const delivered = results.filter((item) => item.ok).length;
      const total = results.length;

      setText(els.alertDispatchSummary, total ? `Last test: ${delivered}/${total} channel${total === 1 ? '' : 's'} delivered` : 'No configured channels were available for this test.');
      if (els.alertDispatchResult) {
        els.alertDispatchResult.textContent = prettyPrint(results);
      }

      await fetchLiveStatus();
    } catch (error) {
      setText(els.alertDispatchSummary, `Test alert failed: ${error.message}`);
      setText(els.alertDispatchResult, `Error: ${error.message}`);
    }
  }

  async function saveAlertConfig(form) {
    const channel = form.dataset.channel || '';
    const feedback = document.getElementById(`channelFeedback-${channel}`);
    const formData = new FormData(form);
    const settings = {};

    form.querySelectorAll('[name]').forEach((input) => {
      if (input.name !== 'enabled') {
        settings[input.name] = input.value;
      }
    });

    setText(feedback, 'Saving settings...');

    try {
      const response = await fetch('/alerts/configure', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          channel,
          enabled: formData.get('enabled') === 'on',
          settings
        })
      });
      await readJsonResponse(response);

      form.querySelectorAll('input[type="password"]').forEach((input) => {
        input.value = '';
      });
      setText(feedback, 'Settings saved.');
      await fetchLiveStatus();
    } catch (error) {
      setText(feedback, `Save failed: ${error.message}`);
    }
  }

  async function discoverTelegramChat(button) {
    const form = button.closest('[data-alert-config-form]');
    const feedback = document.getElementById('channelFeedback-telegram');
    const input = form ? form.querySelector('[name="TELEGRAM_CHAT_ID"]') : null;

    setText(feedback, 'Looking up the latest Telegram chat...');

    try {
      const response = await fetch('/alerts/telegram/discover', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      });
      const data = await readJsonResponse(response);

      if (input) {
        input.value = data.chat_id || '';
      }

      setText(feedback, `Latest Telegram recipient loaded: ${data.chat_label || data.chat_id || 'chat found'}. Click Save settings to keep it.`);
    } catch (error) {
      setText(feedback, `Telegram lookup failed: ${error.message}`);
    }
  }

  function acknowledgeTripwire() {
    if (!state.latestData || !state.latestData.totals) {
      return;
    }

    const attackTs = state.latestData.totals.last_attack_ts;
    if (attackTs) {
      state.acknowledgedAttackTs = attackTs;
      setText(els.tripwireAcknowledged, `ack: ${formatTime(attackTs)}`);
      setTripwireMode('armed');
      renderStats(state.latestData);
    }
  }

  async function fetchLiveStatus() {
    try {
      const response = await fetch('/live-status');
      const data = await readJsonResponse(response);
      state.latestData = data;
      setCaptureState(Boolean(data.sniffing));
      updateInterfaceLabel(data.interface || (els.ifaceSelect && els.ifaceSelect.value) || 'auto');
      renderStats(data);
      renderEventRows(data);
    } catch (error) {
      setText(els.eventCount, '0 flows');
      setText(els.eventRate, '0 flows/min');
      setText(els.tripwireAlertText, `Live status unavailable: ${error.message}`);
      setText(els.statusChannelState, `Live status unavailable: ${error.message}`);
    }
  }

  function wireDropzone() {
    if (!els.csvDropzone || !els.csvFileInput || !els.csvFileInputMirror) {
      return;
    }

    const setDragState = (active) => {
      els.csvDropzone.classList.toggle('is-dragover', active);
    };

    els.csvDropzone.addEventListener('dragover', (event) => {
      event.preventDefault();
      setDragState(true);
    });

    els.csvDropzone.addEventListener('dragleave', () => setDragState(false));
    els.csvDropzone.addEventListener('drop', (event) => {
      event.preventDefault();
      setDragState(false);
      if (event.dataTransfer.files && event.dataTransfer.files[0]) {
        state.csvFile = event.dataTransfer.files[0];
        els.csvFileInput.value = '';
        els.csvFileInputMirror.value = state.csvFile.name;
      }
    });
  }

  function wireInputs() {
    if (els.csvFileInput && els.csvFileInputMirror) {
      els.csvFileInput.addEventListener('change', () => {
        const file = els.csvFileInput.files && els.csvFileInput.files[0];
        state.csvFile = file || null;
        els.csvFileInputMirror.value = file ? file.name : 'No file selected';
      });
    }

    if (els.toggleSniffingBtn) {
      els.toggleSniffingBtn.addEventListener('click', toggleSniffing);
    }
    if (els.setIfaceBtn) {
      els.setIfaceBtn.addEventListener('click', setInterface);
    }
    if (els.predictCsvBtn) {
      els.predictCsvBtn.addEventListener('click', uploadCsv);
    }
    if (els.acknowledgeBtn) {
      els.acknowledgeBtn.addEventListener('click', acknowledgeTripwire);
    }
    if (els.predictSingleBtn) {
      els.predictSingleBtn.addEventListener('click', predictSingleSample);
    }
    if (els.sendAllAlertsBtn) {
      els.sendAllAlertsBtn.addEventListener('click', () => sendTestAlert('all'));
    }
    if (els.singleSampleInput) {
      els.singleSampleInput.addEventListener('keydown', (event) => {
        if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') {
          event.preventDefault();
          predictSingleSample();
        }
      });
    }

    if (els.ifaceSelect) {
      els.ifaceSelect.addEventListener('change', () => {
        updateInterfaceLabel(els.ifaceSelect.value || 'auto');
      });
    }

    document.querySelectorAll('[data-alert-config-form]').forEach((form) => {
      form.addEventListener('submit', (event) => {
        event.preventDefault();
        saveAlertConfig(form);
      });
    });

    document.querySelectorAll('[data-alert-test-button]').forEach((button) => {
      button.addEventListener('click', () => {
        sendTestAlert(button.dataset.alertTestButton || 'all');
      });
    });

    document.querySelectorAll('[data-telegram-discover]').forEach((button) => {
      button.addEventListener('click', () => {
        discoverTelegramChat(button);
      });
    });

    if (els.flowModalClose) {
      els.flowModalClose.addEventListener('click', closeFlowModal);
    }
    if (els.flowModalBackdrop) {
      els.flowModalBackdrop.addEventListener('click', (event) => {
        if (event.target === els.flowModalBackdrop) {
          closeFlowModal();
        }
      });
    }

    document.addEventListener('keydown', (event) => {
      if (event.key === 'Escape' && els.flowModalBackdrop && !els.flowModalBackdrop.hidden) {
        closeFlowModal();
      }
    });

    window.addEventListener('resize', () => {
      resizeCanvas();
      drawTripwireFrame();
    });
  }

  function init() {
    wireInputs();
    wireDropzone();

    if (els.tripwireCanvas) {
      resizeCanvas();
      drawTripwireFrame();
    }

    setCaptureState(false);
    updateInterfaceLabel('auto');
    setText(els.tripwireAcknowledged, 'ack: not yet');

    if (els.csvFileInputMirror) {
      els.csvFileInputMirror.value = 'No file selected';
    }

    if (els.ifaceSelect) {
      loadInterfaces();
      window.setInterval(loadInterfaces, 15000);
    }

    const needsLiveStatus = Boolean(
      els.eventRows || els.statusInterface || els.alertChannelPill || els.statPackets || els.captureChip || els.tripwirePanel
    );
    if (needsLiveStatus) {
      fetchLiveStatus();
      window.setInterval(fetchLiveStatus, 5000);
    }

    if (els.tripwireCanvas && !state.reduceMotion) {
      state.tripwireAnimationId = window.requestAnimationFrame(animateTripwire);
    }
  }

  init();
})();
