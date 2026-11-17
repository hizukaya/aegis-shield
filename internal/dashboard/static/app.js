let lastLogId = 0;

async function fetchStatus() {
  try {
    const res = await fetch('/api/status');
    if (!res.ok) return;
    const data = await res.json();

    // Stats
    document.getElementById('totalQueries').textContent = data.total_queries.toLocaleString();
    document.getElementById('blockedQueries').textContent = data.blocked_queries.toLocaleString();
    document.getElementById('rulesCount').textContent = data.rules_count.toLocaleString();
    
    const rate = data.block_rate.toFixed(1);
    document.getElementById('blockRate').textContent = rate + '%';
    document.getElementById('blockRateBar').style.width = Math.min(rate, 100) + '%';

    document.getElementById('blockedSub').textContent = `${data.blocked_queries} tracking requests prevented`;

    // Status Badge & Pause State
    const statusBadge = document.getElementById('statusBadge');
    const statusText = document.getElementById('statusText');
    const pauseBanner = document.getElementById('pauseBanner');

    if (data.paused) {
      statusBadge.className = 'status-indicator paused';
      statusText.textContent = 'PROTECTION PAUSED';
      pauseBanner.style.display = 'flex';
      const m = Math.floor(data.pause_remaining_sec / 60);
      const s = data.pause_remaining_sec % 60;
      document.getElementById('pauseCountdown').textContent = `${m}:${s < 10 ? '0' : ''}${s}`;
    } else {
      statusBadge.className = 'status-indicator';
      statusText.textContent = 'SHIELD ACTIVE';
      pauseBanner.style.display = 'none';
    }

    // Uptime
    const hours = Math.floor(data.uptime_seconds / 3600);
    const mins = Math.floor((data.uptime_seconds % 3600) / 60);
    const secs = data.uptime_seconds % 60;
    document.getElementById('uptimeDisplay').textContent = `Uptime: ${hours}h ${mins}m ${secs}s`;

    // Top Blocked
    const topContainer = document.getElementById('topBlockedList');
    if (data.top_blocked && data.top_blocked.length > 0) {
      topContainer.innerHTML = data.top_blocked.map(item => `
        <div class="top-item">
          <span class="top-domain" title="${escapeHtml(item.domain)}">${escapeHtml(item.domain)}</span>
          <span class="top-count">${item.count}</span>
        </div>
      `).join('');
    } else {
      topContainer.innerHTML = '<div class="text-muted text-center py-4">No blocked domains yet</div>';
    }

    // Interfaces
    const ifacesContainer = document.getElementById('interfacesList');
    if (data.interfaces && data.interfaces.length > 0) {
      ifacesContainer.innerHTML = data.interfaces.map(iface => `
        <div class="interface-item">
          <span><strong>${escapeHtml(iface.name)}</strong> (${iface.original_type})</span>
          <span class="text-emerald">${escapeHtml(iface.status)}</span>
        </div>
      `).join('');
    }

  } catch (err) {
    console.error('Status fetch error:', err);
  }
}

async function fetchLogs() {
  try {
    const res = await fetch('/api/logs');
    if (!res.ok) return;
    const logs = await res.json();
    if (!logs || logs.length === 0) return;

    const tbody = document.getElementById('queryTableBody');
    tbody.innerHTML = logs.map(log => {
      const timeStr = new Date(log.timestamp).toLocaleTimeString();
      const badgeClass = log.blocked ? 'badge-blocked' : 'badge-allowed';
      const actionText = log.blocked ? 'BLOCKED' : 'FORWARDED';
      const latency = log.duration_ms.toFixed(1) + 'ms';

      return `
        <tr>
          <td><span class="text-muted">${timeStr}</span></td>
          <td><code>${escapeHtml(log.type)}</code></td>
          <td><strong>${escapeHtml(log.domain)}</strong></td>
          <td><span class="${badgeClass}">${actionText}</span></td>
          <td><span class="text-muted">${latency}</span></td>
        </tr>
      `;
    }).join('');
  } catch (err) {
    console.error('Logs fetch error:', err);
  }
}

async function pauseShield(minutes) {
  try {
    await fetch('/api/pause', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ minutes })
    });
    fetchStatus();
  } catch (err) {
    alert('Failed to pause shield: ' + err);
  }
}

async function resumeShield() {
  try {
    await fetch('/api/resume', { method: 'POST' });
    fetchStatus();
  } catch (err) {
    alert('Failed to resume shield: ' + err);
  }
}

async function openFlushDNS() {
  try {
    const res = await fetch('/api/flush-dns', { method: 'POST' });
    const data = await res.json();
    alert('Windows DNS Cache Flushed Successfully!\n' + (data.message || ''));
  } catch (err) {
    alert('Failed to flush DNS: ' + err);
  }
}

async function addCustomRule(type) {
  const input = document.getElementById('customDomainInput');
  const domain = input.value.trim();
  if (!domain) {
    alert('Please enter a valid domain name');
    return;
  }

  try {
    const endpoint = type === 'blacklist' ? '/api/blacklist' : '/api/whitelist';
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain })
    });
    const data = await res.json();
    alert(data.message || 'Rule applied');
    input.value = '';
    fetchStatus();
  } catch (err) {
    alert('Failed to apply rule: ' + err);
  }
}

async function confirmQuit() {
  if (confirm('Are you sure you want to restore original DNS settings and quit AEGIS Shield?')) {
    try {
      await fetch('/api/restore-and-quit', { method: 'POST' });
      document.body.innerHTML = `
        <div style="text-align: center; padding: 80px 20px; font-family: sans-serif; color: #fff; background: #0b0f19; height: 100vh;">
          <h1 style="color: #10b981; font-size: 2rem;">DNS Restored Successfully</h1>
          <p style="margin-top: 14px; color: #9ca3af;">AEGIS Shield has restored all network adapters to their original state and exited cleanly.</p>
          <p style="margin-top: 8px; color: #6b7280;">You may safely close this browser tab.</p>
        </div>
      `;
    } catch (err) {
      alert('Quit signal sent.');
    }
  }
}

function escapeHtml(text) {
  if (!text) return '';
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// Initial fetch
fetchStatus();
fetchLogs();

// Poll intervals
setInterval(fetchStatus, 1500);
setInterval(fetchLogs, 1500);
