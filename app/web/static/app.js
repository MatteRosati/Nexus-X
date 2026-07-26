const keyInput = document.getElementById('api-key');
const saveKey = document.getElementById('save-key');
const forgetKey = document.getElementById('forget-key');
const apiStatus = document.getElementById('api-status');

const scanForm = document.getElementById('scan-form');
const domainInput = document.getElementById('domain');
const message = document.getElementById('message');

const scanList = document.getElementById('scan-list');
const reportList = document.getElementById('report-list');
const refreshButton = document.getElementById('refresh');
const refreshReportsButton = document.getElementById('refresh-reports');

const detailsPanel = document.getElementById('details-panel');
const detailsTitle = document.getElementById('details-title');
const closeDetailsButton = document.getElementById('close-details');
const collectorsBox = document.getElementById('collectors');
const findingsBox = document.getElementById('findings');
const assetsBox = document.getElementById('assets');

const navItems = document.querySelectorAll('.nav-item');
const views = document.querySelectorAll('.view');

let currentScanId = null;

/*
 * Navigation
 */
navItems.forEach(item => {
  item.addEventListener('click', () => {
    // Rimuovi active da tutti
    navItems.forEach(nav => nav.classList.remove('active'));
    views.forEach(view => view.classList.add('hidden'));

    // Aggiungi active al cliccato
    item.classList.add('active');
    const targetId = item.dataset.target;
    document.getElementById(targetId).classList.remove('hidden');
    
    // Aggiorna i dati in base alla view
    if(targetId === 'reports-view') {
      loadScans();
    }
  });
});

closeDetailsButton.addEventListener('click', () => {
  detailsPanel.classList.add('hidden');
});


function getKey() {
  return sessionStorage.getItem('easm_api_key') || '';
}

function headers() {
  return {
    'X-API-Key': getKey(),
    'Content-Type': 'application/json'
  };
}

function esc(value) {
  const node = document.createElement('div');
  node.textContent = String(value ?? '');
  return node.innerHTML;
}

function setMessage(text, type = '') {
  message.textContent = text;
  message.className = `message ${type}`;
}

async function api(path, options = {}) {
  const response = await fetch(
    path,
    {
      ...options,
      headers: {
        ...headers(),
        ...(options.headers || {})
      }
    }
  );

  if (!response.ok) {
    let detail = `${response.status} ${response.statusText}`;
    try {
      const body = await response.json();
      detail = body.detail || detail;
    } catch (_e) {}
    throw new Error(detail);
  }
  return response;
}

async function loadScans() {
  if (!getKey()) {
    scanList.innerHTML = "<tr><td colspan='6' class='muted text-center py-4'>Inserisci l'API key.</td></tr>";
    reportList.innerHTML = "<tr><td colspan='5' class='muted text-center py-4'>Inserisci l'API key.</td></tr>";
    return;
  }

  try {
    const response = await api('/api/v1/scans?limit=50');
    const scans = await response.json();

    apiStatus.textContent = 'Autenticata';
    apiStatus.className = 'badge ok';

    if (!scans.length) {
      scanList.innerHTML = '<tr><td colspan="6" class="muted text-center py-4">Nessuna scansione trovata.</td></tr>';
      reportList.innerHTML = '<tr><td colspan="5" class="muted text-center py-4">Nessun report disponibile.</td></tr>';
      return;
    }

    // Tabella Scansioni (Tutte)
    scanList.innerHTML = scans.map(scan => `
      <tr>
        <td><strong>${esc(scan.target)}</strong></td>
        <td><span class="badge status-${esc(scan.status)}">${esc(scan.status)}</span></td>
        <td class="muted">${new Date(scan.created_at).toLocaleString()}</td>
        <td>${esc(scan.summary.assets ?? '-')}</td>
        <td>${esc(scan.summary.findings ?? '-')}</td>
        <td>
          <button class="btn-secondary btn-icon detail-btn" data-id="${esc(scan.id)}">Dettagli</button>
        </td>
      </tr>
    `).join('');

    // Tabella Report (Solo completate)
    const completedScans = scans.filter(s => s.status === 'completed' || s.status === 'partial_failed');
    if(completedScans.length === 0) {
      reportList.innerHTML = '<tr><td colspan="5" class="muted text-center py-4">Nessun report disponibile (nessuna scansione completata).</td></tr>';
    } else {
      reportList.innerHTML = completedScans.map(scan => `
        <tr>
          <td><strong>${esc(scan.target)}</strong></td>
          <td class="muted">${new Date(scan.created_at).toLocaleString()}</td>
          <td>${esc(scan.summary.assets ?? '-')}</td>
          <td>${esc(scan.summary.findings ?? '-')}</td>
          <td>
            <button class="btn-primary btn-icon open-report-btn" data-id="${esc(scan.id)}">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path><polyline points="15 3 21 3 21 9"></polyline><line x1="10" y1="14" x2="21" y2="3"></line></svg>
              Apri HTML
            </button>
          </td>
        </tr>
      `).join('');
    }

    // Listeners
    document.querySelectorAll('.detail-btn').forEach(btn => {
      btn.addEventListener('click', () => loadDetails(btn.dataset.id));
    });
    document.querySelectorAll('.open-report-btn').forEach(btn => {
      btn.addEventListener('click', () => openReport(btn.dataset.id));
    });

  } catch (error) {
    apiStatus.textContent = 'Errore API';
    apiStatus.className = 'badge warn';
    setMessage(error.message, 'error');
  }
}

async function loadDetails(scanId) {
  try {
    const response = await api(`/api/v1/scans/${encodeURIComponent(scanId)}`);
    const scan = await response.json();
    currentScanId = scan.id;

    detailsTitle.textContent = `Dettagli: ${scan.target} (${scan.status})`;

    /* Collector */
    const collectorsHtml = scan.collector_runs.map(run => `
      <div class="collector">
        <strong>${esc(run.collector_name)}</strong> — 
        <span class="badge status-${esc(run.status)}">${esc(run.status)}</span>
        <div class="muted" style="margin-top:8px">${esc(run.item_count)} elementi estratti</div>
        ${run.error ? `<div class="message error" style="margin-top:8px">${esc(run.error)}</div>` : ''}
      </div>
    `).join('');
    collectorsBox.innerHTML = '<h3>Moduli Eseguiti</h3>' + (collectorsHtml || '<p class="muted">In attesa dei risultati.</p>');

    /* Finding */
    const findingsHtml = scan.findings.map(finding => `
      <div class="finding">
        <div style="display:flex; justify-content:space-between; align-items:flex-start">
          <strong>${esc(finding.title)}</strong>
          <span class="severity sev-${esc(finding.severity)}">SEV ${esc(finding.severity)}</span>
        </div>
        <div class="muted" style="margin-top:8px; margin-bottom:12px">
          ${esc(finding.category)} &bull; ${esc(finding.source)}
        </div>
        <p style="margin:0">${esc(finding.remediation)}</p>
      </div>
    `).join('');
    findingsBox.innerHTML = '<h3>Vulnerabilità (Findings)</h3>' + (findingsHtml || '<p class="muted">Nessun finding rilevato.</p>');

    /* Asset */
    const assetsHtml = scan.assets.slice(0, 500).map(asset => `
      <div class="asset">
        <strong>${esc(asset.value)}</strong>
        <div class="muted" style="margin-top:8px">
          Tipo: ${esc(asset.asset_type)} &bull; Sorgente: ${esc(asset.sources.join(', '))}
        </div>
      </div>
    `).join('');
    assetsBox.innerHTML = '<h3>Asset Scoperti</h3>' + (assetsHtml || '<p class="muted">Nessun asset rilevato.</p>');

    detailsPanel.classList.remove('hidden');
    detailsPanel.scrollIntoView({ behavior: 'smooth' });

  } catch (error) {
    setMessage(error.message, 'error');
  }
}

async function openReport(scanId) {
  try {
    const response = await api(`/api/v1/scans/${encodeURIComponent(scanId)}/report`);
    const html = await response.text();
    const blob = new Blob([html], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    window.open(url, '_blank', 'noopener');
    setTimeout(() => URL.revokeObjectURL(url), 60000);
  } catch (error) {
    alert("Errore apertura report: " + error.message);
  }
}

/*
 * Salvataggio / Rimozione API key
 */
saveKey.addEventListener('click', () => {
  sessionStorage.setItem('easm_api_key', keyInput.value);
  keyInput.value = '';
  // Vai alla tab scansioni
  navItems[0].click();
  loadScans();
});

forgetKey.addEventListener('click', () => {
  sessionStorage.removeItem('easm_api_key');
  apiStatus.textContent = 'Non autenticata';
  apiStatus.className = 'badge';
  detailsPanel.classList.add('hidden');
  loadScans();
});

/*
 * Aggiornamento manuale
 */
refreshButton.addEventListener('click', loadScans);
refreshReportsButton.addEventListener('click', loadScans);

/*
 * Creazione nuova scansione
 */
scanForm.addEventListener('submit', async event => {
  event.preventDefault();
  setMessage('');
  try {
    const response = await api('/api/v1/scans', {
      method: 'POST',
      body: JSON.stringify({ domain: domainInput.value })
    });
    const scan = await response.json();
    setMessage(`Scansione per ${scan.target} accodata con successo.`, 'ok');
    domainInput.value = '';
    await loadScans();
  } catch (error) {
    setMessage(error.message, 'error');
  }
});

/*
 * Avvio
 */
if(getKey()) {
  loadScans();
} else {
  // Se non c'è chiave, forza alla tab impostazioni
  navItems[2].click();
}

/*
 * Polling
 */
setInterval(() => {
  if (getKey()) {
    loadScans();
  }
}, 15000);