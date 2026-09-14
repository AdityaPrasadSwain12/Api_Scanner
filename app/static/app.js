const api = '/api/v1';
const terminalStatuses = new Set(['COMPLETED', 'PARTIAL', 'FAILED', 'CANCELLED', 'TIMEOUT']);
let runtime = {auth_mode: 'disabled'};
let currentScanId = null;

function headers() {
  return {'Content-Type': 'application/json'};
}

function notice(message) {
  const element = document.querySelector('#notice');
  element.textContent = message;
  element.classList.remove('hidden');
  setTimeout(() => element.classList.add('hidden'), 7000);
}

async function errorMessage(response) {
  let body = {};
  try { body = await response.json(); } catch {}
  return body.detail?.message || body.error?.message || `HTTP ${response.status}`;
}

async function call(path, options = {}) {
  const response = await fetch(api + path, {
    ...options,
    headers: {...headers(), ...(options.headers || {})},
  });
  if (!response.ok) throw new Error(await errorMessage(response));
  return response.json();
}

function escapeHtml(value) {
  const node = document.createElement('div');
  node.textContent = value ?? '';
  return node.innerHTML;
}

function view(name) {
  document.querySelectorAll('.view').forEach(element => element.classList.remove('active'));
  document.querySelector(`#${name}`).classList.add('active');
  document.querySelectorAll('nav button').forEach(button => {
    button.classList.toggle('active', button.dataset.view === name);
  });
  document.querySelector('#title').textContent = ({
    dashboard: 'Dashboard',
    new: 'New Scan',
    history: 'Scan History',
    details: 'Scan Results',
  })[name];
  if (name === 'dashboard' || name === 'history') loadScans();
}

document.querySelectorAll('[data-view]').forEach(button => {
  button.onclick = () => view(button.dataset.view);
});
document.querySelector('#back').onclick = () => view('dashboard');

function statusBadge(value) {
  return `<span class="badge ${escapeHtml(value)}">${escapeHtml(value)}</span>`;
}

function coveragePercent(scan) {
  const coverage = scan.result_summary.coverage;
  if (!coverage) return undefined;
  const endpoints = coverage.endpoints || {};
  if ((endpoints.total || 0) > 0 && (endpoints.tested || 0) === 0) return undefined;
  return coverage.runtime_check_summary?.percent_attempted
    ?? coverage.security_check_summary?.percent_attempted
    ?? endpoints.percent_tested;
}

function assessmentStatus(scan) {
  const coverage = scan.result_summary.coverage;
  const explicit = coverage?.assessment?.status;
  if (explicit) return explicit;
  const endpoints = coverage?.endpoints || {};
  if ((endpoints.total || 0) > 0 && (endpoints.tested || 0) === 0) return 'INCOMPLETE';
  return undefined;
}

function coverageLabel(scan) {
  const status = assessmentStatus(scan);
  const percent = coveragePercent(scan);
  if (status === 'INCOMPLETE') return 'INCOMPLETE';
  if (status === 'PARTIAL') return `PARTIAL (${percent ?? 0}%)`;
  return percent === undefined ? '\u2014' : `${percent}%`;
}

async function loadScans({silent = false} = {}) {
  try {
    const data = await call('/scans?limit=50');
    document.querySelector('#totalScans').textContent = data.total;
    document.querySelector('#activeScans').textContent = data.items.filter(scan => !terminalStatuses.has(scan.status)).length;
    document.querySelector('#totalFindings').textContent = data.items.reduce((total, scan) => total + (scan.result_summary.finding_count || 0), 0);
    const coverage = data.items.map(coveragePercent).filter(value => value !== undefined);
    document.querySelector('#coverage').textContent = coverage.length
      ? `${Math.round(coverage.reduce((left, right) => left + right, 0) / coverage.length)}%`
      : '\u2014';
    const recent = data.items.map(scan =>
      `<tr data-id="${scan.id}"><td>${escapeHtml(scan.target_url || scan.result_summary.target || scan.target_id)}</td><td>${statusBadge(scan.status)}</td><td>${scan.progress}%</td><td>${scan.result_summary.finding_count || 0}</td></tr>`
    ).join('');
    const history = data.items.map(scan =>
      `<tr data-id="${scan.id}"><td>${escapeHtml(scan.target_url || scan.target_id)}</td><td>${new Date(scan.created_at).toLocaleString()}</td><td>${statusBadge(scan.status)}</td><td>${escapeHtml(coverageLabel(scan))}</td></tr>`
    ).join('');
    document.querySelector('#recentRows').innerHTML = recent || '<tr><td colspan="4">No scans yet.</td></tr>';
    document.querySelector('#historyRows').innerHTML = history || '<tr><td colspan="4">No scans yet.</td></tr>';
    document.querySelectorAll('tr[data-id]').forEach(row => {
      row.onclick = () => showScan(row.dataset.id);
    });
  } catch (error) {
    if (!silent) notice(error.message);
  }
}

function reportName(format) {
  if (format === 'PDF') return 'enterprise PDF';
  if (format === 'TECHNICAL_JSON') return 'full technical JSON';
  return 'pentest JSON';
}

async function showScan(id, {silent = false} = {}) {
  try {
    const [scan, findings, endpoints, reports] = await Promise.all([
      call(`/scans/${id}`),
      call(`/scans/${id}/findings?limit=100`),
      call(`/scans/${id}/endpoints?limit=100`),
      call(`/scans/${id}/reports`),
    ]);
    currentScanId = id;
    viewWithoutLoading('details');
    const running = !terminalStatuses.has(scan.status);
    const findingHtml = findings.items.map(finding =>
      `<article class="finding"><h3 class="${escapeHtml(finding.severity)}">${escapeHtml(finding.title)}</h3><p>${escapeHtml(finding.severity)} / ${escapeHtml(finding.confidence)} &middot; risk ${finding.risk_score} &middot; ${escapeHtml(finding.method || '')} ${escapeHtml(finding.endpoint || '')}</p><p>${escapeHtml(finding.description)}</p><details><summary>Evidence and remediation</summary><h4>Recommended remediation</h4><p>${escapeHtml(finding.remediation)}</p><h4>Evidence</h4><pre>${escapeHtml(JSON.stringify(finding.evidence, null, 2))}</pre></details></article>`
    ).join('') || `<p class="muted">${running ? 'Findings will appear here as the scan completes.' : 'No findings were reported. Review coverage before interpreting this result.'}</p>`;
    const reportOrder = {PDF: 0, JSON: 1, TECHNICAL_JSON: 2};
    const downloadable = reports.items
      .filter(report => ['PDF', 'JSON', 'TECHNICAL_JSON'].includes(report.format))
      .sort((left, right) => reportOrder[left.format] - reportOrder[right.format]);
    const reportHtml = downloadable.map(report =>
      `<a class="report-button" href="${report.download_url}" data-report data-format="${escapeHtml(report.format)}">Download ${reportName(report.format)}</a>`
    ).join('') || `<p class="muted">${running ? 'Enterprise PDF, pentest JSON, and technical JSON reports are generated after the scan finishes.' : 'Reports are not available for this scan.'}</p>`;
    const coverage = coverageLabel(scan);
    document.querySelector('#scanDetail').innerHTML = `
      <div class="result-heading"><div><h2>${escapeHtml(scan.target_url || scan.target_id)}</h2><p class="muted">${escapeHtml(scan.stage || 'Queued')}</p></div>${statusBadge(scan.status)}</div>
      <div class="progress-track"><span style="width:${Math.max(0, Math.min(100, scan.progress))}%"></span></div>
      <div class="metrics result-metrics"><article><label>Progress</label><strong>${scan.progress}%</strong></article><article><label>API endpoints</label><strong>${endpoints.total}</strong></article><article><label>Findings</label><strong>${findings.total}</strong></article><article><label>Runtime assessment</label><strong>${escapeHtml(coverage)}</strong></article></div>
      ${scan.error ? `<div class="error-box">${escapeHtml(scan.error)}</div>` : ''}
      <div class="detail-grid"><section class="panel"><h2>Reports</h2><div class="report-actions">${reportHtml}</div></section><section class="panel"><h2>Scan coverage</h2><pre>${escapeHtml(JSON.stringify(scan.result_summary.coverage || {status: running ? 'calculated after completion' : 'not available'}, null, 2))}</pre></section></div>
      <section class="panel"><h2>Vulnerability findings</h2>${findingHtml}</section>`;
    document.querySelectorAll('[data-report]').forEach(anchor => {
      anchor.onclick = event => downloadReport(event, anchor);
    });
  } catch (error) {
    if (!silent) notice(error.message);
  }
}

function viewWithoutLoading(name) {
  document.querySelectorAll('.view').forEach(element => element.classList.remove('active'));
  document.querySelector(`#${name}`).classList.add('active');
  document.querySelectorAll('nav button').forEach(button => button.classList.remove('active'));
  document.querySelector('#title').textContent = 'Scan Results';
}

async function downloadReport(event, anchor) {
  event.preventDefault();
  try {
    const response = await fetch(anchor.href, {headers: headers()});
    if (!response.ok) throw new Error(await errorMessage(response));
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const temporary = document.createElement('a');
    temporary.href = url;
    const extension = anchor.dataset.format === 'TECHNICAL_JSON' ? 'technical.json' : anchor.dataset.format.toLowerCase();
    temporary.download = `api-security-report.${extension}`;
    temporary.click();
    URL.revokeObjectURL(url);
  } catch (error) {
    notice(error.message);
  }
}

function updateDocumentFields() {
  const selected = document.querySelector('#documentSource').value;
  document.querySelectorAll('.document-field').forEach(element => {
    const active = element.dataset.source === selected;
    element.classList.toggle('hidden', !active);
    element.querySelectorAll('input, textarea').forEach(input => { input.required = active; });
  });
}

document.querySelector('#documentSource').onchange = updateDocumentFields;

document.querySelector('#scanForm').onsubmit = async event => {
  event.preventDefault();
  const formElement = event.target;
  const form = new FormData(formElement);
  const source = form.get('document_source');
  const button = document.querySelector('#startButton');
  const status = document.querySelector('#submitStatus');
  button.disabled = true;
  button.textContent = 'Verifying...';
  status.textContent = 'Checking the target URL, document format, server scope, and API paths.';
  status.classList.remove('hidden');
  try {
    const body = {
      target_url: String(form.get('target_url') || '').trim(),
      authorized: form.get('authorized') === 'on',
      profile: 'STANDARD',
      policy: {},
    };
    if (source === 'file') {
      const file = document.querySelector('#specFile').files[0];
      if (!file) throw new Error('Select an OpenAPI or Swagger file.');
      if (file.size > 5 * 1024 * 1024) throw new Error('The API document must be 5 MB or smaller.');
      body.specification = await file.text();
    } else if (source === 'url') {
      body.specification_url = String(form.get('specification_url') || '').trim();
    } else {
      body.specification = String(form.get('specification') || '').trim();
    }
    const result = await call('/scans', {method: 'POST', body: JSON.stringify(body)});
    notice('Scan accepted. The worker is now verifying endpoint reachability before active testing.');
    formElement.reset();
    updateDocumentFields();
    await showScan(result.scan_id);
  } catch (error) {
    notice(error.message);
  } finally {
    button.disabled = false;
    button.textContent = 'Verify and start scan';
    status.classList.add('hidden');
  }
};

async function bootstrap() {
  try {
    const response = await fetch('/ui-config');
    if (response.ok) runtime = await response.json();
  } catch {}
  if (runtime.auth_mode === 'api_key') {
    notice('Open this scanner through the main platform. Direct browser authentication is disabled.');
  }
  updateDocumentFields();
  loadScans();
}

setInterval(() => {
  if (document.querySelector('#dashboard').classList.contains('active')) loadScans({silent: true});
  if (document.querySelector('#details').classList.contains('active') && currentScanId) showScan(currentScanId, {silent: true});
}, 3000);

bootstrap();
