const keyInput = document.getElementById('api-key');
const saveKey = document.getElementById('save-key');
const forgetKey = document.getElementById('forget-key');
const apiStatus = document.getElementById('api-status');
const scanForm = document.getElementById('scan-form');
const domainInput = document.getElementById('domain');
const message = document.getElementById('message');
const scanList = document.getElementById('scan-list');
const refreshButton = document.getElementById('refresh');
const detailsPanel = document.getElementById('details-panel');
const detailsTitle = document.getElementById('details-title');
const collectorsBox = document.getElementById('collectors');
const findingsBox = document.getElementById('findings');
const assetsBox = document.getElementById('assets');
const reportButton = document.getElementById('report');

let currentScanId = null;


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
    } catch (_e) {
      // La risposta di errore non contiene JSON.
    }

    throw new Error(detail);
  }

  return response;
}


async function loadScans() {
  if (!getKey()) {
    scanList.innerHTML =
      "<tr><td colspan='6' class='muted'>Inserisci l'API key.</td></tr>";

    return;
  }

  try {
    const response = await api('/api/v1/scans?limit=50');
    const scans = await response.json();

    apiStatus.textContent = 'API autenticata';
    apiStatus.className = 'badge ok';

    if (!scans.length) {
      scanList.innerHTML =
        '<tr><td colspan="6" class="muted">Nessuna scansione.</td></tr>';

      return;
    }

    scanList.innerHTML = scans.map(scan => `
      <tr>
        <td>${esc(scan.target)}</td>

        <td class="status">
          ${esc(scan.status)}
        </td>

        <td>
          ${new Date(scan.created_at).toLocaleString()}
        </td>

        <td>
          ${esc(scan.summary.assets ?? '-')}
        </td>

        <td>
          ${esc(scan.summary.findings ?? '-')}
        </td>

        <td>
          <button
            class="secondary detail-btn"
            data-id="${esc(scan.id)}"
          >
            Dettagli
          </button>
        </td>
      </tr>
    `).join('');

    document
      .querySelectorAll('.detail-btn')
      .forEach(button => {
        button.addEventListener(
          'click',
          () => loadDetails(button.dataset.id)
        );
      });

  } catch (error) {
    apiStatus.textContent = 'Autenticazione fallita';
    apiStatus.className = 'badge warn';

    setMessage(error.message, 'error');
  }
}


async function loadDetails(scanId) {
  try {
    const response = await api(
      `/api/v1/scans/${encodeURIComponent(scanId)}`
    );

    const scan = await response.json();

    currentScanId = scan.id;

    detailsTitle.textContent =
      `Dettagli: ${scan.target} (${scan.status})`;


    /*
     * Collector
     */

    const collectorsHtml = scan.collector_runs.map(run => `
      <div class="collector">
        <strong>${esc(run.collector_name)}</strong>
        —
        ${esc(run.status)}
        ·
        ${esc(run.item_count)} elementi

        ${
          run.error
            ? `<br><span class="muted">${esc(run.error)}</span>`
            : ''
        }
      </div>
    `).join('');

    collectorsBox.innerHTML =
      '<h3>Collector</h3>' +
      (
        collectorsHtml ||
        '<p class="muted">In attesa del worker.</p>'
      );


    /*
     * Finding
     */

    const findingsHtml = scan.findings.map(finding => `
      <div class="finding">
        <span class="severity sev-${esc(finding.severity)}">
          ${esc(finding.severity)}/5
        </span>

        <strong>
          ${esc(finding.title)}
        </strong>

        <br>

        <span class="muted">
          ${esc(finding.category)}
          ·
          ${esc(finding.source)}
        </span>

        <p>
          ${esc(finding.remediation)}
        </p>
      </div>
    `).join('');

    findingsBox.innerHTML =
      findingsHtml ||
      '<p class="muted">Nessun finding.</p>';


    /*
     * Asset
     */

    const assetsHtml = scan.assets
      .slice(0, 500)
      .map(asset => `
        <div class="asset">
          <strong>
            ${esc(asset.value)}
          </strong>

          <br>

          <span class="muted">
            ${esc(asset.asset_type)}
            ·
            ${esc(asset.sources.join(', '))}
          </span>
        </div>
      `)
      .join('');

    assetsBox.innerHTML =
      assetsHtml ||
      '<p class="muted">Nessun asset.</p>';


    detailsPanel.classList.remove('hidden');

  } catch (error) {
    setMessage(error.message, 'error');
  }
}


/*
 * Salvataggio API key
 */

saveKey.addEventListener('click', () => {
  sessionStorage.setItem(
    'easm_api_key',
    keyInput.value
  );

  keyInput.value = '';

  loadScans();
});


/*
 * Rimozione API key
 */

forgetKey.addEventListener('click', () => {
  sessionStorage.removeItem('easm_api_key');

  apiStatus.textContent = 'API non autenticata';
  apiStatus.className = 'badge';

  detailsPanel.classList.add('hidden');

  loadScans();
});


/*
 * Aggiornamento manuale
 */

refreshButton.addEventListener(
  'click',
  loadScans
);


/*
 * Creazione nuova scansione
 */

scanForm.addEventListener('submit', async event => {
  event.preventDefault();

  setMessage('');

  try {
    const response = await api(
      '/api/v1/scans',
      {
        method: 'POST',
        body: JSON.stringify({
          domain: domainInput.value
        })
      }
    );

    const scan = await response.json();

    setMessage(
      `Scansione ${scan.id} accodata.`,
      'ok'
    );

    domainInput.value = '';

    await loadScans();

  } catch (error) {
    setMessage(error.message, 'error');
  }
});


/*
 * Apertura report HTML
 */

reportButton.addEventListener('click', async () => {
  if (!currentScanId) {
    return;
  }

  try {
    const response = await api(
      `/api/v1/scans/${encodeURIComponent(currentScanId)}/report`
    );

    const html = await response.text();

    const blob = new Blob(
      [html],
      {
        type: 'text/html'
      }
    );

    const url = URL.createObjectURL(blob);

    window.open(
      url,
      '_blank',
      'noopener'
    );

    setTimeout(
      () => URL.revokeObjectURL(url),
      60000
    );

  } catch (error) {
    setMessage(error.message, 'error');
  }
});


/*
 * Avvio dashboard
 */

loadScans();


/*
 * Aggiornamento automatico ogni 15 secondi
 */

setInterval(() => {
  if (getKey()) {
    loadScans();
  }
}, 15000);