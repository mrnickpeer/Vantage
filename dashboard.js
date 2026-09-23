// Cross-browser API shim for Firefox and Chrome MV3
if (typeof browser === 'undefined') {
  var browser = globalThis.browser || globalThis.chrome || {};
}
if (!browser.storage || !browser.storage.local) {
  const _store = {};
  browser.storage = {
    local: {
      get: async (keys) => {
        const res = {};
        if (Array.isArray(keys)) {
          keys.forEach(k => { if (_store[k] !== undefined) res[k] = _store[k]; });
        } else if (typeof keys === 'string') {
          if (_store[keys] !== undefined) res[keys] = _store[keys];
        } else if (keys && typeof keys === 'object') {
          Object.keys(keys).forEach(k => { res[k] = _store[k] !== undefined ? _store[k] : keys[k]; });
        }
        return res;
      },
      set: async (obj) => { Object.assign(_store, obj); }
    },
    onChanged: { addListener: () => {} }
  };
}
if (!browser.tabs) {
  browser.tabs = { query: async () => [], create: async () => {} };
}
if (!browser.runtime) {
  browser.runtime = { getURL: (p) => p };
}

const TEMPLATE_VERSION = 4;

const DEFAULT_TEMPLATES = [
  {
    id: 't-env',
    category: 'Configuration & Secrets',
    name: 'Environment Config (.env)',
    description: 'Finds exposed environment configuration files containing database connection strings.',
    risk: 'Critical',
    whatItLeaks: 'Database credentials, API secret keys, cloud tokens, APP_KEY salts.',
    truePositive: 'Raw text file containing assignments like DB_PASSWORD= or SECRET_KEY= (not an HTML 404 page).',
    remediation: 'Configure web server (NGINX/Apache) to deny public requests to dotfiles (location ~ /\\. { deny all; }).',
    fields: { filetype: 'env', inurl: '', intitle: '', exact: 'DB_HOST, DATABASE_URL', exclude: '' }
  },
  {
    id: 't-admin',
    category: 'Admin & Portals',
    name: 'Admin & Login Portals',
    description: 'Identifies administrative dashboards, management consoles, and login interfaces.',
    risk: 'High',
    whatItLeaks: 'Administrative login interfaces, management portals, and internal consoles.',
    truePositive: 'Interactive username/password or SSO login forms for backend infrastructure (/admin, /wp-admin, /dashboard).',
    remediation: 'Restrict administrative access to VPN or allowlisted IPs and enforce multi-factor authentication (MFA).',
    fields: { filetype: '', inurl: 'admin, login, dashboard', intitle: 'login, admin', exact: '', exclude: '' }
  },
  {
    id: 't-open-dir',
    category: 'Server Exposures',
    name: 'Open Directory Index',
    description: 'Detects misconfigured web servers exposing raw directory index listings.',
    risk: 'High',
    whatItLeaks: 'Raw server directory trees exposing source code, config files, internal scripts, and logs.',
    truePositive: 'Directory listings showing "Index of /" with file tables and column headers like "Last modified" and "Size".',
    remediation: 'Disable directory indexing ("Options -Indexes" in Apache or remove "autoindex on" in NGINX).',
    fields: { filetype: '', inurl: '', intitle: 'index of /', exact: 'parent directory', exclude: '-inurl:html -inurl:htm -inurl:php' }
  },
  {
    id: 't-backups',
    category: 'Backups & Dumps',
    name: 'Database Backups (.sql, .dump)',
    description: 'Discovers publicly exposed database dumps and backup archives.',
    risk: 'Critical',
    whatItLeaks: 'Full database dumps, compressed archives (.tar.gz, .zip), and system backups.',
    truePositive: 'Direct download links to .sql, .dump, or .bak files containing CREATE TABLE or INSERT statements.',
    remediation: 'Never store backups inside public web root directories. Ship archives securely to private object storage.',
    fields: { filetype: 'sql, dump, bak', inurl: 'backup, dump', intitle: '', exact: '', exclude: '' }
  },
  {
    id: 't-cloud',
    category: 'Cloud Storage',
    name: 'Cloud Storage & S3 Buckets',
    description: 'Looks for references to Amazon S3 and Google Cloud storage objects.',
    risk: 'High',
    whatItLeaks: 'Publicly accessible Amazon S3 buckets and Google Cloud storage blobs.',
    truePositive: 'XML responses containing <ListBucketResult> or direct downloads of internal corporate files.',
    remediation: 'Enable S3 Block Public Access at the AWS account level and audit Google Cloud Storage IAM permissions.',
    fields: { filetype: '', inurl: 's3.amazonaws.com, storage.googleapis.com', intitle: '', exact: '', exclude: '' }
  },
  {
    id: 't-docs',
    category: 'Public Documents',
    name: 'Confidential Documents (.pdf, .xlsx)',
    description: 'Locates spreadsheets and PDF documents marked confidential or internal.',
    risk: 'Medium',
    whatItLeaks: 'Internal business plans, employee rosters, financial statements, and confidential client documents.',
    truePositive: 'PDF or Office documents containing watermarks or headers like "Confidential", "Internal Use Only", or "Do Not Disclose".',
    remediation: 'Audit public document repositories and verify that sensitive internal documents require authenticated portal access.',
    fields: { filetype: 'pdf, xlsx, docx', inurl: '', intitle: '', exact: 'confidential, internal use only', exclude: '' }
  },
  {
    id: 't-dev',
    category: 'Infrastructure',
    name: 'Staging & Dev Environments',
    description: 'Uncovers non-production test, staging, or sandbox web endpoints.',
    risk: 'Medium',
    whatItLeaks: 'Non-production staging, testing, sandbox, and UAT web applications.',
    truePositive: 'Staging environments with debug banners, verbose stack traces, or weaker dev authentication.',
    remediation: 'Place staging environments behind IP allowlists, VPNs, or HTTP Basic Authentication.',
    fields: { filetype: '', inurl: 'staging, dev, test, uat', intitle: '', exact: '', exclude: '' }
  },
  {
    id: 't-logs',
    category: 'Server Exposures',
    name: 'Server & Error Logs',
    description: 'Finds publicly accessible debug and application trace logs.',
    risk: 'High',
    whatItLeaks: 'Application error logs, debug stack traces, session tokens, and database queries.',
    truePositive: 'Raw log files with timestamps, PHP fatal errors, or Python tracebacks.',
    remediation: 'Disable display_errors in production and route application logs to secure centralized log management.',
    fields: { filetype: 'log', inurl: 'log, debug', intitle: '', exact: 'stack trace, fatal error', exclude: '' }
  },
  {
    id: 't-email-exposure',
    category: 'Identity & Contacts',
    name: 'Email & Contact Exposure',
    description: 'Surfaces exposed employee email addresses, contact directories, and staff listings.',
    risk: 'Medium',
    whatItLeaks: 'Employee email rosters, phone directories, and organizational charts.',
    truePositive: 'Staff spreadsheets or contact lists exposing employee full names and direct corporate emails.',
    remediation: 'Replace public direct email lists with web contact forms to reduce phishing exposure.',
    fields: { filetype: 'xlsx, csv, pdf', inurl: 'contact, team, staff, about', intitle: 'email, contact', exact: '', exclude: '' }
  },
  {
    id: 't-email-mentions',
    category: 'Identity & Contacts',
    name: 'External Email Mentions',
    description: 'Finds domain email addresses exposed on third-party forums, paste sites, and public files.',
    risk: 'Medium',
    whatItLeaks: 'Domain email addresses leaked on pastebins, public code repositories, or third-party forums.',
    truePositive: 'Third-party forum posts, GitHub issues, or paste sites referencing corporate email addresses.',
    remediation: 'Educate staff on avoiding corporate email use on public developer boards and monitor paste sites.',
    fields: { filetype: '', inurl: '', intitle: '', exact: 'email, contact', exclude: '' }
  }
];

let state = {
  templates: [],
  profiles: [],
  auditLogs: [],
  lastState: {},
  showGuidance: true,
  currentTimeFilter: 'any',
  verbatimMode: true,
  dorksRun: 0,
  activeTemplateId: null,
  checklistCollapsed: false,
  shodanApiKey: ''
};

let currentCrtHosts = [];
let currentDiscoveredEmails = [];
let currentRelatedDomains = [];
let currentNetblocks = [];
let currentDnsZone = null;
let toastTimeout = null;

const els = {
  domain: document.getElementById('f-domain'),
  filetype: document.getElementById('f-filetype'),
  inurl: document.getElementById('f-inurl'),
  intitle: document.getElementById('f-intitle'),
  exact: document.getElementById('f-exact'),
  exclude: document.getElementById('f-exclude'),
  engines: document.getElementsByName('engine'),
  output: document.getElementById('query-output'),
  linter: document.getElementById('linter-warnings'),
  tokenCount: document.getElementById('token-count'),
  preset: document.getElementById('f-preset'),
  templateCatFilter: document.getElementById('template-cat-filter'),
  auditCount: document.getElementById('audit-count'),
  auditQuery: document.getElementById('a-query'),
  auditFilterStatus: document.getElementById('audit-filter-status'),
  btnFetchCrt: document.getElementById('btn-fetch-crt'),
  crtStatus: document.getElementById('crt-status'),
  crtActionsBar: document.getElementById('crt-actions-bar'),
  crtFilter: document.getElementById('crt-filter'),
  crtResults: document.getElementById('crt-results'),
  btnCancelCrt: document.getElementById('btn-cancel-crt'),
  emailStatus: document.getElementById('email-status'),
  emailActionsBar: document.getElementById('email-actions-bar'),
  emailFilter: document.getElementById('email-filter'),
  emailResults: document.getElementById('email-results'),
  toast: document.getElementById('toast'),
  toggleGuidance: document.getElementById('toggle-guidance'),
  exposureCard: document.getElementById('exposure-card'),
  expRiskBadge: document.getElementById('exp-risk-badge'),
  expTemplateTitle: document.getElementById('exp-template-title'),
  expWhatLeaks: document.getElementById('exp-what-leaks'),
  expTruePositive: document.getElementById('exp-true-positive'),
  expRemediation: document.getElementById('exp-remediation'),
  verbatimCheck: document.getElementById('f-verbatim'),
  emailPatternBanner: document.getElementById('email-pattern-banner'),
  patternScheme: document.getElementById('pattern-scheme'),
  patternConfidence: document.getElementById('pattern-confidence'),
  btnDorkPattern: document.getElementById('btn-dork-pattern'),
  checklistProgressText: document.getElementById('checklist-progress-text'),
  btnToggleChecklist: document.getElementById('btn-toggle-checklist'),
  checklistSteps: document.getElementById('checklist-steps'),
  infraKeyword: document.getElementById('infra-keyword'),
  infraStatus: document.getElementById('infra-status'),
  infraDomainsCount: document.getElementById('infra-domains-count'),
  infraDomainsList: document.getElementById('infra-domains-list'),
  infraNetsCount: document.getElementById('infra-nets-count'),
  infraNetsList: document.getElementById('infra-nets-list'),
  infraNetActions: document.getElementById('infra-net-actions'),
  btnFetchInfra: document.getElementById('btn-fetch-infra'),
  btnInfraCustomSearch: document.getElementById('btn-infra-custom-search'),
  btnCopyNetblocks: document.getElementById('btn-copy-netblocks'),
  btnNetsToAudit: document.getElementById('btn-nets-to-audit'),
  btnToggleShodan: document.getElementById('btn-toggle-shodan-settings'),
  shodanActiveBadge: document.getElementById('shodan-active-badge'),
  shodanDrawer: document.getElementById('shodan-settings-drawer'),
  btnCloseShodanDrawer: document.getElementById('btn-close-shodan-drawer'),
  shodanKeyInput: document.getElementById('f-shodan-key'),
  btnSaveShodanKey: document.getElementById('btn-save-shodan-key'),
  btnClearShodanKey: document.getElementById('btn-clear-shodan-key'),
  shodanKeyStatus: document.getElementById('shodan-key-status'),
  dnsZoneSection: document.getElementById('dns-zone-section'),
  dnsRecordsCount: document.getElementById('dns-records-count'),
  btnCopyDns: document.getElementById('btn-copy-dns'),
  btnDnsToAudit: document.getElementById('btn-dns-to-audit'),
  dnsSaasBanner: document.getElementById('dns-saas-banner'),
  dnsSaasTags: document.getElementById('dns-saas-tags'),
  dnsNsList: document.getElementById('dns-ns-list'),
  dnsNsCount: document.getElementById('dns-ns-count'),
  dnsMxList: document.getElementById('dns-mx-list'),
  dnsMxCount: document.getElementById('dns-mx-count'),
  dnsApexList: document.getElementById('dns-apex-list'),
  dnsTxtList: document.getElementById('dns-txt-list'),
  dnsTxtCount: document.getElementById('dns-txt-count')
};

function updateShodanUiState() {
  const hasKey = Boolean(state.shodanApiKey && state.shodanApiKey.trim());
  if (els.btnToggleShodan) {
    if (hasKey) {
      els.btnToggleShodan.classList.add('has-key');
    } else {
      els.btnToggleShodan.classList.remove('has-key');
    }
  }
  if (els.shodanActiveBadge) {
    els.shodanActiveBadge.style.display = hasKey ? 'inline-block' : 'none';
  }
  if (els.shodanKeyStatus) {
    if (hasKey) {
      const masked = state.shodanApiKey.length > 8 
        ? `${state.shodanApiKey.slice(0, 4)}••••••••${state.shodanApiKey.slice(-4)}`
        : '••••••••';
      els.shodanKeyStatus.style.display = 'block';
      els.shodanKeyStatus.className = 'shodan-key-status success';
      els.shodanKeyStatus.innerHTML = `🔑 <strong>Personal Shodan Key Active:</strong> <code>${escapeHtml(masked)}</code> &mdash; Deep API queries enabled.`;
    } else {
      els.shodanKeyStatus.style.display = 'none';
      els.shodanKeyStatus.innerHTML = '';
    }
  }
}

async function init() {
  const data = await browser.storage.local.get([
    'templates', 'profiles', 'auditLogs', 'lastState', 'templateVersion',
    'showGuidance', 'currentTimeFilter', 'verbatimMode', 'dorksRun', 'shodanApiKey'
  ]);
  
  if (typeof data.showGuidance === 'boolean') {
    state.showGuidance = data.showGuidance;
  } else {
    state.showGuidance = true;
  }
  setGuidance(state.showGuidance);

  if (data.currentTimeFilter) {
    state.currentTimeFilter = data.currentTimeFilter;
  }
  if (typeof data.verbatimMode === 'boolean') {
    state.verbatimMode = data.verbatimMode;
  }
  state.dorksRun = data.dorksRun || 0;
  if (data.shodanApiKey) {
    state.shodanApiKey = data.shodanApiKey;
    if (els.shodanKeyInput) els.shodanKeyInput.value = data.shodanApiKey;
  }
  updateShodanUiState();

  // Migrate to rich beginner-friendly templates if uninitialized or older version
  if (!data.templates || data.templateVersion !== TEMPLATE_VERSION) {
    const userCustom = (data.templates || []).filter(t => t.id && t.id.startsWith('t_'));
    state.templates = [...DEFAULT_TEMPLATES, ...userCustom];
    await browser.storage.local.set({
      templates: state.templates,
      templateVersion: TEMPLATE_VERSION
    });
  } else {
    state.templates = data.templates;
  }

  state.profiles = data.profiles || [];
  state.auditLogs = data.auditLogs || [];
  state.lastState = data.lastState || {};

  if (state.lastState.engine) {
    const radio = document.querySelector(`input[name="engine"][value="${state.lastState.engine}"]`);
    if (radio) radio.checked = true;
  }
  els.domain.value = state.lastState.domain || '';
  els.filetype.value = state.lastState.filetype || '';
  els.inurl.value = state.lastState.inurl || '';
  els.intitle.value = state.lastState.intitle || '';
  els.exact.value = state.lastState.exact || '';
  els.exclude.value = state.lastState.exclude || '';
  if (els.verbatimCheck) els.verbatimCheck.checked = state.verbatimMode;

  // Update temporal chips
  document.querySelectorAll('.temporal-chip').forEach(chip => {
    if (chip.dataset.time === state.currentTimeFilter) {
      chip.classList.add('active');
    } else {
      chip.classList.remove('active');
    }
  });

  bindEvents();
  updatePresetDropdown();
  updateCategoryFilterDropdown();
  renderTemplates();
  renderProfiles();
  renderAuditLogs();
  updateQuery();
  updateChecklist();

  // Reactive listener for audit logs added via context menu
  browser.storage.onChanged.addListener((changes, area) => {
    if (area === 'local' && changes.auditLogs) {
      state.auditLogs = changes.auditLogs.newValue || [];
      renderAuditLogs();
      updateChecklist();
      showToast('Audit log updated from browser context menu!');
    }
  });
}

function bindEvents() {
  ['domain', 'filetype', 'inurl', 'intitle', 'exact', 'exclude'].forEach(id => {
    els[id].addEventListener('input', updateQuery);
  });
  els.engines.forEach(el => el.addEventListener('change', updateQuery));

  // Guidance Toggle
  if (els.toggleGuidance) {
    els.toggleGuidance.addEventListener('change', (e) => setGuidance(e.target.checked));
  }

  // Temporal Filter Chips
  document.querySelectorAll('.temporal-chip').forEach(chip => {
    chip.addEventListener('click', (e) => {
      document.querySelectorAll('.temporal-chip').forEach(c => c.classList.remove('active'));
      e.target.classList.add('active');
      state.currentTimeFilter = e.target.dataset.time;
      browser.storage.local.set({ currentTimeFilter: state.currentTimeFilter });
      showToast(`Time filter set to: ${e.target.textContent}`);
    });
  });

  // Verbatim Mode Toggle
  if (els.verbatimCheck) {
    els.verbatimCheck.addEventListener('change', (e) => {
      state.verbatimMode = e.target.checked;
      browser.storage.local.set({ verbatimMode: state.verbatimMode });
      showToast(state.verbatimMode ? 'Verbatim search enabled (&tbs=li:1)' : 'Verbatim search disabled');
    });
  }

  // Guided Audit Checklist Action Buttons
  const btnStepTarget = document.getElementById('step-btn-target');
  if (btnStepTarget) btnStepTarget.addEventListener('click', useActiveTab);

  const btnStepCrt = document.getElementById('step-btn-crt');
  if (btnStepCrt) btnStepCrt.addEventListener('click', () => {
    switchTab('tab-crt');
    if (els.domain.value.trim() && !currentCrtHosts.length) fetchCrt();
  });

  const btnStepInfra = document.getElementById('step-btn-infra');
  if (btnStepInfra) btnStepInfra.addEventListener('click', () => {
    switchTab('tab-infra');
    if (els.domain.value.trim() && !currentRelatedDomains.length && !currentNetblocks.length) fetchInfra();
  });

  const btnStepEmails = document.getElementById('step-btn-emails');
  if (btnStepEmails) btnStepEmails.addEventListener('click', () => {
    switchTab('tab-emails');
    if (els.domain.value.trim() && !currentDiscoveredEmails.length) fetchEmails();
  });

  const btnStepDorks = document.getElementById('step-btn-dorks');
  if (btnStepDorks) btnStepDorks.addEventListener('click', () => {
    loadTemplate('t-env');
  });

  const btnStepExport = document.getElementById('step-btn-export');
  if (btnStepExport) btnStepExport.addEventListener('click', () => {
    switchTab('tab-audit');
  });

  const btnToggleChecklist = document.getElementById('btn-toggle-checklist');
  if (btnToggleChecklist) btnToggleChecklist.addEventListener('click', toggleChecklistCollapse);

  // Methodology Help Icons & Modal
  document.querySelectorAll('.step-help-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const step = parseInt(btn.dataset.step, 10) || 1;
      openMethodologyModal(step);
    });
  });

  const btnCloseMethodologyModal = document.getElementById('btn-close-methodology-modal');
  if (btnCloseMethodologyModal) btnCloseMethodologyModal.addEventListener('click', closeMethodologyModal);

  const btnCloseModalSecondary = document.getElementById('btn-close-modal-secondary');
  if (btnCloseModalSecondary) btnCloseModalSecondary.addEventListener('click', closeMethodologyModal);

  const methodologyModal = document.getElementById('methodology-modal');
  if (methodologyModal) {
    methodologyModal.addEventListener('click', (e) => {
      if (e.target === methodologyModal) closeMethodologyModal();
    });
  }

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeMethodologyModal();
  });

  // Email Pattern Dork Button
  if (els.btnDorkPattern) {
    els.btnDorkPattern.addEventListener('click', loadEmailPatternDork);
  }

  // Quick Preset Selector in Composer
  els.preset.addEventListener('change', (e) => {
    const id = e.target.value;
    if (!id) {
      state.activeTemplateId = null;
      if (els.exposureCard) els.exposureCard.style.display = 'none';
      return;
    }
    loadTemplate(id);
  });

  // Current Tab domain grabber
  document.getElementById('btn-use-tab').addEventListener('click', useActiveTab);

  // Actions
  document.getElementById('btn-reset').addEventListener('click', () => {
    ['domain', 'filetype', 'inurl', 'intitle', 'exact', 'exclude'].forEach(id => els[id].value = '');
    els.preset.value = '';
    state.activeTemplateId = null;
    if (els.exposureCard) els.exposureCard.style.display = 'none';
    updateQuery();
    showToast('Composer fields cleared.');
  });

  document.getElementById('btn-copy').addEventListener('click', () => {
    navigator.clipboard.writeText(els.output.value);
    const btn = document.getElementById('btn-copy');
    const orig = btn.textContent;
    btn.textContent = 'Copied!';
    setTimeout(() => { btn.textContent = orig; }, 1200);
    showToast('Query copied to clipboard!');
  });

  document.getElementById('btn-search').addEventListener('click', () => {
    const q = els.output.value.trim();
    if (!q) {
      alert('Query is empty. Choose a template or enter operators first.');
      return;
    }

    state.dorksRun = (state.dorksRun || 0) + 1;
    browser.storage.local.set({ dorksRun: state.dorksRun });
    updateChecklist();

    const engine = Array.from(els.engines).find(e => e.checked).value;
    let url = '';
    if (engine === 'google') {
      url = `https://www.google.com/search?q=${encodeURIComponent(q)}`;
      const tbs = [];
      if (state.verbatimMode) tbs.push('li:1');
      if (state.currentTimeFilter && state.currentTimeFilter !== 'any') {
        tbs.push(`qdr:${state.currentTimeFilter}`);
      }
      if (tbs.length) url += `&tbs=${tbs.join(',')}`;
    }
    if (engine === 'bing') {
      url = `https://www.bing.com/search?q=${encodeURIComponent(q)}`;
      const bingTime = { d: 'age-1d', w: 'age-1w', m: 'age-1m', y: 'age-1y' };
      if (state.currentTimeFilter !== 'any' && bingTime[state.currentTimeFilter]) {
        url += `&qft=+filterui:${bingTime[state.currentTimeFilter]}`;
      }
    }
    if (engine === 'ddg') {
      url = `https://duckduckgo.com/?q=${encodeURIComponent(q)}`;
      if (state.currentTimeFilter !== 'any') {
        url += `&df=${state.currentTimeFilter}`;
      }
    }
    window.open(url, '_blank');
  });

  document.getElementById('btn-save-profile').addEventListener('click', saveProfile);
  document.getElementById('btn-save-template').addEventListener('click', saveComposerAsTemplate);
  document.getElementById('btn-wayback').addEventListener('click', openWayback);
  document.getElementById('btn-urlscan').addEventListener('click', openUrlscan);

  // Tab switching
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
      e.target.classList.add('active');
      const targetId = e.target.dataset.target;
      document.getElementById(targetId).classList.add('active');

      if (targetId === 'tab-audit') {
        if (!els.auditQuery.value) els.auditQuery.value = els.output.value;
      }
      if (targetId === 'tab-infra') {
        if (els.infraKeyword && !els.infraKeyword.value.trim() && els.domain.value.trim()) {
          els.infraKeyword.value = els.domain.value.trim();
        }
      }
    });
  });

  // Templates Management
  els.templateCatFilter.addEventListener('change', renderTemplates);
  document.getElementById('btn-new-template').addEventListener('click', () => {
    document.getElementById('new-template-form').style.display = 'block';
  });
  document.getElementById('btn-cancel-new-template').addEventListener('click', () => {
    document.getElementById('new-template-form').style.display = 'none';
  });
  document.getElementById('btn-save-new-template').addEventListener('click', createCustomTemplate);
  document.getElementById('btn-reset-defaults').addEventListener('click', restoreDefaultTemplates);

  // CRT.SH Scope
  if (els.btnFetchCrt) els.btnFetchCrt.addEventListener('click', () => fetchCrt('wildcard'));
  if (els.crtFilter) els.crtFilter.addEventListener('input', filterCrtResults);
  const btnCrtSelectAll = document.getElementById('btn-crt-select-all');
  if (btnCrtSelectAll) btnCrtSelectAll.addEventListener('click', () => toggleCrtSelection(true));
  const btnCrtDeselectAll = document.getElementById('btn-crt-deselect-all');
  if (btnCrtDeselectAll) btnCrtDeselectAll.addEventListener('click', () => toggleCrtSelection(false));
  const btnAppendCrt = document.getElementById('btn-append-crt');
  if (btnAppendCrt) btnAppendCrt.addEventListener('click', appendCrtExclusions);
  const btnCrtToAudit = document.getElementById('btn-crt-to-audit');
  if (btnCrtToAudit) btnCrtToAudit.addEventListener('click', sendCrtToAuditLog);
  if (els.btnCancelCrt) els.btnCancelCrt.addEventListener('click', cancelCrtFetch);

  // DNS Zone Intelligence
  if (els.btnCopyDns) els.btnCopyDns.addEventListener('click', copyDnsSummary);
  if (els.btnDnsToAudit) els.btnDnsToAudit.addEventListener('click', sendDnsToAuditLog);
  if (els.dnsApexList) els.dnsApexList.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-action="check-apex-shodan"]');
    if (btn && btn.dataset.ip) checkSingleIpShodan(btn.dataset.ip, btn);
  });

  // Infrastructure & Global Netblock Scope
  if (els.btnFetchInfra) els.btnFetchInfra.addEventListener('click', () => fetchInfra());
  if (els.btnInfraCustomSearch) els.btnInfraCustomSearch.addEventListener('click', () => fetchInfra(true));
  if (els.infraKeyword) els.infraKeyword.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      fetchInfra(true);
    }
  });
  if (els.btnCopyNetblocks) els.btnCopyNetblocks.addEventListener('click', copyAllNetblocks);
  if (els.btnNetsToAudit) els.btnNetsToAudit.addEventListener('click', sendAllNetsToAuditLog);
  if (els.infraDomainsList) els.infraDomainsList.addEventListener('click', handleDomainAction);
  if (els.infraNetsList) els.infraNetsList.addEventListener('click', handleNetAction);

  // Shodan BYOK Settings
  if (els.btnToggleShodan) {
    els.btnToggleShodan.addEventListener('click', () => {
      if (els.shodanDrawer) {
        const isHidden = els.shodanDrawer.style.display === 'none';
        els.shodanDrawer.style.display = isHidden ? 'block' : 'none';
        if (isHidden) {
          updateShodanUiState();
          if (els.shodanKeyInput && state.shodanApiKey) {
            els.shodanKeyInput.value = state.shodanApiKey;
          }
        }
      }
    });
  }
  if (els.btnCloseShodanDrawer) {
    els.btnCloseShodanDrawer.addEventListener('click', () => {
      if (els.shodanDrawer) els.shodanDrawer.style.display = 'none';
    });
  }
  if (els.btnSaveShodanKey) {
    els.btnSaveShodanKey.addEventListener('click', async () => {
      const key = (els.shodanKeyInput?.value || '').trim();
      if (!key) {
        state.shodanApiKey = '';
        await browser.storage.local.set({ shodanApiKey: '' });
        updateShodanUiState();
        showToast('Shodan API Key cleared. Defaulted to free InternetDB mode.');
        return;
      }

      const origText = els.btnSaveShodanKey.textContent;
      els.btnSaveShodanKey.disabled = true;
      els.btnSaveShodanKey.textContent = 'Validating Key...';

      try {
        const res = await fetch(`https://api.shodan.io/api-info?key=${encodeURIComponent(key)}`);
        if (res.ok) {
          const info = await res.json().catch(() => ({}));
          state.shodanApiKey = key;
          await browser.storage.local.set({ shodanApiKey: key });
          updateShodanUiState();
          if (els.shodanKeyStatus) {
            els.shodanKeyStatus.style.display = 'block';
            els.shodanKeyStatus.className = 'shodan-key-status success';
            els.shodanKeyStatus.innerHTML = `✅ <strong>Key Verified!</strong> Plan: <code>${escapeHtml(info.plan || 'Registered')}</code> &bull; Query Credits: <strong>${info.query_credits ?? 'N/A'}</strong> &bull; Scan Credits: <strong>${info.scan_credits ?? 'N/A'}</strong>`;
          }
          showToast('Shodan API Key validated and saved!');
        } else if (res.status === 401) {
          if (els.shodanKeyStatus) {
            els.shodanKeyStatus.style.display = 'block';
            els.shodanKeyStatus.className = 'shodan-key-status error';
            els.shodanKeyStatus.innerHTML = `❌ <strong>Invalid Key (401 Unauthorized):</strong> Shodan rejected this key. Please check your key at <a href="https://account.shodan.io" target="_blank" rel="noopener noreferrer" style="color: #fca5a5; text-decoration: underline;">account.shodan.io</a>.`;
          }
          showToast('Shodan returned 401 Unauthorized for this key.');
        } else {
          state.shodanApiKey = key;
          await browser.storage.local.set({ shodanApiKey: key });
          updateShodanUiState();
          showToast('Key saved (could not reach Shodan to verify).');
        }
      } catch (err) {
        state.shodanApiKey = key;
        await browser.storage.local.set({ shodanApiKey: key });
        updateShodanUiState();
        showToast('Key saved (network offline during validation check).');
      } finally {
        els.btnSaveShodanKey.disabled = false;
        els.btnSaveShodanKey.textContent = origText;
      }
    });
  }
  if (els.btnClearShodanKey) {
    els.btnClearShodanKey.addEventListener('click', async () => {
      if (els.shodanKeyInput) els.shodanKeyInput.value = '';
      state.shodanApiKey = '';
      await browser.storage.local.set({ shodanApiKey: '' });
      updateShodanUiState();
      showToast('Shodan API Key cleared. Reverted to free InternetDB mode.');
    });
  }

  // Email Discovery Scope
  document.getElementById('btn-fetch-emails').addEventListener('click', fetchEmails);
  document.getElementById('email-filter').addEventListener('input', filterEmailResults);
  document.getElementById('btn-email-select-all').addEventListener('click', () => toggleEmailSelection(true));
  document.getElementById('btn-email-deselect-all').addEventListener('click', () => toggleEmailSelection(false));
  document.getElementById('btn-email-to-audit').addEventListener('click', sendEmailsToAuditLog);
  document.getElementById('btn-email-copy').addEventListener('click', copySelectedEmails);

  // Audit Logs
  document.getElementById('btn-log-finding').addEventListener('click', logFinding);
  document.getElementById('btn-clear-audit').addEventListener('click', clearAuditLogs);
  document.getElementById('btn-clear-fp').addEventListener('click', clearFalsePositives);
  document.getElementById('btn-clear-fixed').addEventListener('click', clearFixedItems);
  document.getElementById('btn-export-obsidian').addEventListener('click', exportObsidian);
  if (els.auditFilterStatus) {
    els.auditFilterStatus.addEventListener('change', renderAuditLogs);
  }
  const btnFormUrlscan = document.getElementById('btn-audit-urlscan-form');
  if (btnFormUrlscan) {
    btnFormUrlscan.addEventListener('click', openFormUrlscan);
  }

  // Backup & Restore
  document.getElementById('btn-export-data').addEventListener('click', exportData);
  document.getElementById('btn-import-data').addEventListener('click', () => document.getElementById('import-file').click());
  document.getElementById('import-file').addEventListener('change', importData);

  // Event Delegation for dynamically rendered lists (CSP compliant, no inline onclick)
  document.getElementById('templates-list').addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-action]');
    if (!btn) return;
    const action = btn.dataset.action;
    const id = btn.dataset.id;
    if (action === 'load') loadTemplate(id);
    else if (action === 'delete') deleteTemplate(id);
  });

  document.getElementById('profiles-list').addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-action]');
    if (!btn) return;
    const action = btn.dataset.action;
    const id = btn.dataset.id;
    if (action === 'load') loadProfile(id);
    else if (action === 'delete') deleteProfile(id);
  });

  document.getElementById('audit-list').addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-action]');
    if (!btn) return;
    const action = btn.dataset.action;
    const id = btn.dataset.id;
    if (action === 'delete') deleteAuditFinding(id);
    else if (action === 'urlscan') openAuditUrlscan(id);
  });

  document.getElementById('audit-list').addEventListener('change', (e) => {
    if (e.target.dataset.action === 'change-status') {
      const id = e.target.dataset.id;
      const newStatus = e.target.value;
      updateAuditStatus(id, newStatus);
    }
  });
}

function showToast(message) {
  if (!els.toast) return;
  els.toast.textContent = message;
  els.toast.classList.add('show');
  if (toastTimeout) clearTimeout(toastTimeout);
  toastTimeout = setTimeout(() => {
    els.toast.classList.remove('show');
  }, 2400);
}

function parseInputList(str) {
  return str.split(',').map(s => s.trim()).filter(s => s.length > 0);
}

function buildGroup(prefix, values) {
  if (!values.length) return '';
  if (values.length === 1) return `${prefix}${values[0]}`;
  return `(${values.map(v => `${prefix}${v}`).join(' OR ')})`;
}

function updateQuery() {
  const engine = Array.from(els.engines).find(e => e.checked).value;
  const parts = [];

  const domain = els.domain.value.trim();
  if (domain) parts.push(`site:${domain}`);

  const fTypes = parseInputList(els.filetype.value);
  if (fTypes.length) parts.push(buildGroup(engine === 'bing' ? 'ext:' : 'filetype:', fTypes));

  const iUrls = parseInputList(els.inurl.value);
  if (iUrls.length) parts.push(buildGroup('inurl:', iUrls));

  const iTitles = parseInputList(els.intitle.value);
  if (iTitles.length) parts.push(buildGroup('intitle:', iTitles));

  const exacts = parseInputList(els.exact.value);
  if (exacts.length) {
    if (exacts.length === 1) {
      parts.push(`"${exacts[0]}"`);
    } else {
      parts.push(`(${exacts.map(e => `"${e}"`).join(' OR ')})`);
    }
  }

  const excludes = els.exclude.value.split(/[\s,]+/).map(s => s.trim()).filter(s => s.length > 0);
  if (excludes.length) parts.push(excludes.map(e => (e.startsWith('-') ? e : `-${e}`)).join(' '));

  const query = parts.join(' ');
  els.output.value = query;

  lintQuery(query);
  persistState();
}

function lintQuery(query) {
  let warnings = [];
  const words = query.trim() ? query.trim().split(/\s+/).length : 0;
  
  if (!els.domain.value.trim()) {
    warnings.push('Tip: Add a Target Domain (e.g. site:example.com) to restrict search scope, or leave blank for a web-wide search.');
  }
  if (/(site|filetype|ext|inurl|intitle):\s+/i.test(query)) {
    warnings.push('Malformed operator: Remove whitespace after colon (e.g. "site:example.com").');
  }
  if ((query.match(/"/g) || []).length % 2 !== 0) {
    warnings.push('Unclosed quotation marks detected.');
  }
  
  els.linter.innerHTML = warnings.map(w => w.startsWith('Tip:') ? `<span class="linter-tip">${w}</span>` : `<span class="linter-err">${w}</span>`).join('<br>');
  els.tokenCount.innerText = `${words} words`;
  
  if (words > 32) els.tokenCount.classList.add('warn');
  else els.tokenCount.classList.remove('warn');
}

async function persistState() {
  state.lastState = {
    engine: Array.from(els.engines).find(e => e.checked).value,
    domain: els.domain.value,
    filetype: els.filetype.value,
    inurl: els.inurl.value,
    intitle: els.intitle.value,
    exact: els.exact.value,
    exclude: els.exclude.value
  };
  await browser.storage.local.set({ lastState: state.lastState });
}

// Active Browser Tab Grabber
async function useActiveTab() {
  try {
    const tabs = await browser.tabs.query({ currentWindow: true });
    const extPrefix = browser.runtime.getURL('');
    const webTabs = tabs.filter(t => t.url && !t.url.startsWith(extPrefix) && /^https?:\/\//i.test(t.url));

    let targetTab = webTabs.find(t => t.active);
    if (!targetTab && webTabs.length > 0) {
      webTabs.sort((a, b) => (b.lastAccessed || 0) - (a.lastAccessed || 0));
      targetTab = webTabs[0];
    }

    if (targetTab && targetTab.url) {
      const u = new URL(targetTab.url);
      els.domain.value = u.hostname.replace(/^www\./i, '');
      updateQuery();
      showToast(`Domain set to ${els.domain.value}`);
    } else {
      alert('No active website found in this window. Open a site in another tab and try again.');
    }
  } catch (err) {
    console.error('Failed to grab active tab:', err);
    alert('Unable to inspect active tab: ' + err.message);
  }
}

// Wayback Machine Shortcut
function openWayback() {
  const domain = els.domain.value.trim();
  if (!domain) {
    alert('Please enter a target domain first.');
    return;
  }
  const url = `https://web.archive.org/web/*/${encodeURIComponent(domain)}`;
  window.open(url, '_blank');
}

// urlscan.io Historical Search Shortcut (Spot A)
function openUrlscan() {
  const raw = els.domain.value.trim();
  if (!raw) {
    alert('Please enter a target domain first.');
    return;
  }
  const cleanDomain = raw.replace(/^https?:\/\//i, '').replace(/[\/:]+.*$/, '').trim().toLowerCase();
  if (!cleanDomain) {
    alert('Please enter a valid target domain.');
    return;
  }
  const url = `https://urlscan.io/search/#domain:${encodeURIComponent(cleanDomain)}`;
  window.open(url, '_blank');
  showToast(`Opening urlscan search for ${cleanDomain}`);
}

// Dropdowns & Templates
function updatePresetDropdown() {
  const cats = {};
  state.templates.forEach(t => {
    const cat = t.category || 'General';
    if (!cats[cat]) cats[cat] = [];
    cats[cat].push(t);
  });
  
  let html = '<option value="">-- Choose an Intent Template --</option>';
  Object.keys(cats).sort().forEach(cat => {
    html += `<optgroup label="${escapeHtml(cat)}">`;
    cats[cat].forEach(t => {
      html += `<option value="${escapeHtml(t.id)}">${escapeHtml(t.name)}</option>`;
    });
    html += `</optgroup>`;
  });
  els.preset.innerHTML = html;
}

function updateCategoryFilterDropdown() {
  const categories = Array.from(new Set(state.templates.map(t => t.category || 'General'))).sort();
  const currentVal = els.templateCatFilter.value;
  els.templateCatFilter.innerHTML = '<option value="all">All Categories</option>' + 
    categories.map(c => `<option value="${escapeHtml(c)}">${escapeHtml(c)}</option>`).join('');
  if (categories.includes(currentVal)) {
    els.templateCatFilter.value = currentVal;
  }
}

function renderTemplates() {
  const container = document.getElementById('templates-list');
  const filter = els.templateCatFilter.value;
  const filtered = filter === 'all' ? state.templates : state.templates.filter(t => t.category === filter);

  if (!filtered.length) {
    container.innerHTML = `<p style="color: var(--text-muted); grid-column: span 2;">No templates found for this filter.</p>`;
    return;
  }

  container.innerHTML = filtered.map(t => {
    const riskBadge = t.risk ? `<span class="risk-badge risk-${escapeHtml((t.risk || '').toLowerCase())}">${escapeHtml(t.risk)}</span>` : '';
    const fields = t.fields || {};
    return `
      <div class="card">
        <div class="card-top">
          <h4>${escapeHtml(t.name)}</h4>
          <div style="display: flex; align-items: center; gap: 0.35rem;">
            ${riskBadge}
            <span class="tag">${escapeHtml(t.category)}</span>
          </div>
        </div>
        ${t.description ? `<p class="card-desc">${escapeHtml(t.description)}</p>` : ''}
        <div class="card-fields">
          ${fields.filetype ? `<div><strong>filetype:</strong> <code>${escapeHtml(fields.filetype)}</code></div>` : ''}
          ${fields.inurl ? `<div><strong>inurl:</strong> <code>${escapeHtml(fields.inurl)}</code></div>` : ''}
          ${fields.intitle ? `<div><strong>intitle:</strong> <code>${escapeHtml(fields.intitle)}</code></div>` : ''}
          ${fields.exact ? `<div><strong>exact:</strong> <code>"${escapeHtml(fields.exact)}"</code></div>` : ''}
          ${fields.exclude ? `<div><strong>exclude:</strong> <code>${escapeHtml(fields.exclude)}</code></div>` : ''}
        </div>
        <div class="card-actions" style="margin-top: auto; padding-top: 0.5rem;">
          <button class="primary" data-action="load" data-id="${escapeHtml(t.id)}">Load to Composer</button>
          <button data-action="delete" data-id="${escapeHtml(t.id)}">Delete</button>
        </div>
      </div>
    `;
  }).join('');
}

window.loadTemplate = (id) => {
  const t = state.templates.find(x => x.id === id);
  if (!t) return;
  
  state.activeTemplateId = id;
  updateExposureCard(id);

  els.filetype.value = t.fields.filetype || '';
  els.inurl.value = t.fields.inurl || '';
  els.intitle.value = t.fields.intitle || '';
  els.exact.value = t.fields.exact || '';
  els.exclude.value = t.fields.exclude || '';
  els.preset.value = id;
  
  updateQuery();
  updateChecklist();

  // Subtle visual highlight on the composer
  const composer = document.querySelector('.composer');
  if (composer) {
    composer.classList.add('highlight');
    setTimeout(() => composer.classList.remove('highlight'), 1200);
  }

  showToast(`Loaded template: ${t.name}`);
};

window.deleteTemplate = async (id) => {
  if (!confirm('Are you sure you want to delete this template?')) return;
  state.templates = state.templates.filter(x => x.id !== id);
  await browser.storage.local.set({ templates: state.templates });
  updatePresetDropdown();
  updateCategoryFilterDropdown();
  renderTemplates();
  showToast('Template deleted.');
};

async function restoreDefaultTemplates() {
  if (!confirm('Restore all default templates? This will reload the standard beginner-friendly templates.')) return;
  const userCustom = state.templates.filter(t => t.id && t.id.startsWith('t_'));
  state.templates = [...DEFAULT_TEMPLATES, ...userCustom];
  await browser.storage.local.set({
    templates: state.templates,
    templateVersion: TEMPLATE_VERSION
  });
  updatePresetDropdown();
  updateCategoryFilterDropdown();
  renderTemplates();
  showToast('Default templates restored!');
}

async function saveComposerAsTemplate() {
  const name = prompt('Enter a name for this template:');
  if (!name || !name.trim()) return;
  const category = prompt('Enter a category (e.g. Secrets, Admin, Storage):', 'Custom') || 'Custom';
  
  const newTmpl = {
    id: 't_' + Date.now(),
    category: category.trim(),
    name: name.trim(),
    description: 'Custom user template',
    fields: {
      filetype: els.filetype.value,
      inurl: els.inurl.value,
      intitle: els.intitle.value,
      exact: els.exact.value,
      exclude: els.exclude.value
    }
  };

  state.templates.push(newTmpl);
  await browser.storage.local.set({ templates: state.templates });
  updatePresetDropdown();
  updateCategoryFilterDropdown();
  renderTemplates();
  showToast(`Template "${name}" saved!`);
}

async function createCustomTemplate() {
  const name = document.getElementById('t-name').value.trim();
  const category = document.getElementById('t-category').value.trim() || 'Custom';
  if (!name) {
    alert('Please provide a Template Name.');
    return;
  }

  const newTmpl = {
    id: 't_' + Date.now(),
    category,
    name,
    description: 'Custom user template',
    fields: {
      filetype: document.getElementById('t-filetype').value.trim(),
      inurl: document.getElementById('t-inurl').value.trim(),
      intitle: document.getElementById('t-intitle').value.trim(),
      exact: document.getElementById('t-exact').value.trim(),
      exclude: document.getElementById('t-exclude').value.trim()
    }
  };

  state.templates.push(newTmpl);
  await browser.storage.local.set({ templates: state.templates });

  ['t-name', 't-category', 't-filetype', 't-inurl', 't-intitle', 't-exact', 't-exclude'].forEach(id => {
    document.getElementById(id).value = '';
  });
  document.getElementById('new-template-form').style.display = 'none';

  updatePresetDropdown();
  updateCategoryFilterDropdown();
  renderTemplates();
  showToast(`Template "${name}" created!`);
}

// Profiles Management
async function saveProfile() {
  const name = prompt('Enter Profile Name:');
  if (!name || !name.trim()) return;
  const p = { id: Date.now().toString(), name: name.trim(), state: { ...state.lastState } };
  state.profiles.push(p);
  await browser.storage.local.set({ profiles: state.profiles });
  renderProfiles();
  showToast(`Profile "${name}" saved!`);
}

function renderProfiles() {
  const container = document.getElementById('profiles-list');
  if (!state.profiles.length) {
    container.innerHTML = `<p style="color: var(--text-muted); grid-column: span 2;">No saved profiles yet. Click "Save Profile" in the composer to save current target settings.</p>`;
    return;
  }

  container.innerHTML = state.profiles.map(p => `
    <div class="card">
      <div class="card-top">
        <h4>${escapeHtml(p.name)}</h4>
        <span class="tag">${escapeHtml(((p.state && p.state.engine) || '').toUpperCase())}</span>
      </div>
      <p>Target: <code>${escapeHtml((p.state && p.state.domain) || 'All Domains')}</code></p>
      <div class="card-actions">
        <button data-action="load" data-id="${escapeHtml(p.id)}">Load Profile</button>
        <button data-action="delete" data-id="${escapeHtml(p.id)}">Delete</button>
      </div>
    </div>
  `).join('');
}

window.loadProfile = (id) => {
  const p = state.profiles.find(x => x.id === id);
  if (!p) return;
  const radio = document.querySelector(`input[name="engine"][value="${p.state.engine}"]`);
  if (radio) radio.checked = true;
  els.domain.value = p.state.domain || '';
  els.filetype.value = p.state.filetype || '';
  els.inurl.value = p.state.inurl || '';
  els.intitle.value = p.state.intitle || '';
  els.exact.value = p.state.exact || '';
  els.exclude.value = p.state.exclude || '';
  updateQuery();
  showToast(`Loaded profile: ${p.name}`);
};

window.deleteProfile = async (id) => {
  if (!confirm('Are you sure you want to delete this profile?')) return;
  state.profiles = state.profiles.filter(x => x.id !== id);
  await browser.storage.local.set({ profiles: state.profiles });
  renderProfiles();
  showToast('Profile deleted.');
};

// CRT.SH Certificate Transparency
let crtAbortController = null;
let crtTimerInterval = null;

function cancelCrtFetch() {
  if (crtAbortController) {
    crtAbortController.abort();
    crtAbortController = null;
  }
  if (crtTimerInterval) {
    clearInterval(crtTimerInterval);
    crtTimerInterval = null;
  }
  const status = document.getElementById('crt-status') || els.crtStatus;
  if (status) {
    status.className = 'crt-status-text';
    status.innerText = 'Request cancelled by user.';
  }
  const cancelBtn = document.getElementById('btn-cancel-crt') || els.btnCancelCrt;
  if (cancelBtn) cancelBtn.style.display = 'none';
  const fetchBtn = document.getElementById('btn-fetch-crt') || els.btnFetchCrt;
  if (fetchBtn) {
    fetchBtn.disabled = false;
    fetchBtn.innerHTML = 'Fetch Subdomains';
  }
}

async function fetchCrt(queryMode = 'wildcard') {
  if (crtAbortController) {
    crtAbortController.abort();
    crtAbortController = null;
  }
  if (crtTimerInterval) {
    clearInterval(crtTimerInterval);
    crtTimerInterval = null;
  }

  const rawDomain = els.domain ? els.domain.value.trim() : '';
  const domain = extractApexDomain(rawDomain) || rawDomain.toLowerCase().replace(/^https?:\/\//i, '').split('/')[0].split(':')[0];

  const status = document.getElementById('crt-status') || els.crtStatus;
  const actionsBar = document.getElementById('crt-actions-bar') || els.crtActionsBar;
  const results = document.getElementById('crt-results') || els.crtResults;
  const cancelBtn = document.getElementById('btn-cancel-crt') || els.btnCancelCrt;
  const fetchBtn = document.getElementById('btn-fetch-crt') || els.btnFetchCrt;

  if (!domain) {
    if (status) {
      status.className = 'crt-status-text error';
      status.innerText = 'Target domain is required (enter in composer).';
    }
    if (results) {
      results.innerHTML = `
        <div class="crt-empty-state">
          <span class="crt-empty-icon">⚠️</span>
          <p>Please enter a target domain in the left panel first (e.g. <code>example.com</code>).</p>
        </div>
      `;
    }
    return;
  }

  if (actionsBar) actionsBar.style.display = 'none';
  if (fetchBtn) {
    fetchBtn.disabled = true;
    fetchBtn.innerHTML = `<span class="spinner-inline"></span> Fetching...`;
  }
  if (cancelBtn) cancelBtn.style.display = 'inline-block';

  const isWildcard = queryMode === 'wildcard';
  const queryUrl = isWildcard
    ? `https://crt.sh/?q=%.${encodeURIComponent(domain)}&output=json`
    : `https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`;

  const modeLabel = isWildcard ? `wildcard log index (%.${domain})` : `apex & SAN index (${domain})`;
  const startTime = Date.now();

  if (status) {
    status.className = 'crt-status-text loading';
    status.innerHTML = `<span class="spinner-inline"></span> Querying crt.sh ${escapeHtml(modeLabel)}... <strong id="crt-elapsed-sec">0s</strong>`;
  }

  if (results) {
    results.innerHTML = `
      <div class="crt-empty-state">
        <span class="spinner-inline" style="width: 24px; height: 24px; border-width: 3px;"></span>
        <p>Connecting to public Certificate Transparency logs for <strong>${escapeHtml(domain)}</strong>...</p>
        <span style="font-size: 0.8rem; color: var(--text-muted); max-width: 480px;">
          ${isWildcard ? 'Wildcard log searches can take 15–30 seconds during high traffic. Please keep this tab open.' : 'Performing fast indexed certificate query...'}
        </span>
      </div>
    `;
  }

  // Update elapsed seconds live
  crtTimerInterval = setInterval(() => {
    const elapsed = Math.round((Date.now() - startTime) / 1000);
    const secEl = document.getElementById('crt-elapsed-sec');
    if (secEl) secEl.innerText = `${elapsed}s`;

    const subtextEl = document.getElementById('crt-status-subtext');
    if (elapsed >= 10 && elapsed < 20) {
      if (!subtextEl && status) {
        const span = document.createElement('span');
        span.id = 'crt-status-subtext';
        span.style.cssText = 'font-size: 0.75rem; color: #fbbf24; margin-left: 0.5rem;';
        span.innerText = '(Server busy, still scanning records...)';
        status.appendChild(span);
      }
    } else if (elapsed >= 20) {
      if (subtextEl) {
        subtextEl.innerText = '(crt.sh PostgreSQL engine running deep query; hanging tight...)';
      }
    }
  }, 1000);

  crtAbortController = new AbortController();
  const timeoutMs = isWildcard ? 35000 : 15000;
  const timeoutId = setTimeout(() => {
    if (crtAbortController) crtAbortController.abort();
  }, timeoutMs);

  try {
    const res = await fetch(queryUrl, {
      signal: crtAbortController.signal
    });
    clearTimeout(timeoutId);

    if (!res.ok) {
      if (res.status === 502 || res.status === 504) {
        throw new Error(`crt.sh server is overloaded (HTTP ${res.status} Gateway Timeout). Sectigo database query exceeded time limits.`);
      }
      if (res.status === 429) {
        throw new Error('crt.sh rate limit encountered (HTTP 429). Please wait 30 seconds before querying again.');
      }
      throw new Error(`crt.sh responded with HTTP ${res.status}`);
    }

    const text = await res.text();
    let data;
    try {
      data = JSON.parse(text);
    } catch (_) {
      if (text.includes('502 Bad Gateway') || text.includes('504 Gateway Time-out') || text.includes('Database Error')) {
        throw new Error('crt.sh upstream gateway timed out while compiling certificate tables.');
      }
      throw new Error('crt.sh returned a non-JSON response (likely an upstream rate limit or HTML gateway error page).');
    }

    if (!Array.isArray(data)) {
      throw new Error('Unexpected response format from crt.sh.');
    }

    const subs = new Set();
    data.forEach(cert => {
      if (cert.common_name) {
        cert.common_name.split('\n').forEach(sub => {
          const cleaned = sub.toLowerCase().trim().replace(/^\*\./, '');
          if (cleaned === domain || cleaned.endsWith('.' + domain)) {
            subs.add(cleaned);
          }
        });
      }
      if (cert.name_value) {
        cert.name_value.split('\n').forEach(sub => {
          const cleaned = sub.toLowerCase().trim().replace(/^\*\./, '');
          if (cleaned === domain || cleaned.endsWith('.' + domain)) {
            subs.add(cleaned);
          }
        });
      }
    });

    currentCrtHosts = Array.from(subs).sort();
    if (typeof updateGraph === 'function') updateGraph();
    const elapsedSec = ((Date.now() - startTime) / 1000).toFixed(1);

    if (!currentCrtHosts.length) {
      if (status) {
        status.className = 'crt-status-text';
        status.innerText = `No certificate records found for ${domain} (${elapsedSec}s).`;
      }
      if (results) {
        results.innerHTML = `
          <div class="crt-empty-state">
            <span class="crt-empty-icon">ℹ️</span>
            <p>No matching certificate records found on crt.sh for <code>${escapeHtml(domain)}</code>.</p>
            <span style="font-size: 0.8rem; color: var(--text-muted);">
              The domain may not have public CT logs recorded under this exact apex, or uses a private CA.
            </span>
          </div>
        `;
      }
      return;
    }

    if (status) {
      status.className = 'crt-status-text success';
      status.innerText = `Discovered ${currentCrtHosts.length} unique subdomains (${elapsedSec}s)${isWildcard ? '' : ' via fast SAN scan'}.`;
    }
    if (actionsBar) actionsBar.style.display = 'flex';
    const filterInput = document.getElementById('crt-filter');
    if (filterInput) filterInput.value = '';
    renderCrtList(currentCrtHosts);
    updateChecklist();
    showToast(`Discovered ${currentCrtHosts.length} subdomains via crt.sh!`);

  } catch (err) {
    clearTimeout(timeoutId);
    const elapsedSec = Math.round((Date.now() - startTime) / 1000);
    const isTimeout = err.name === 'AbortError';

    let errorDetail = err.message;
    if (isTimeout) {
      errorDetail = `crt.sh request timed out after ${elapsedSec}s. The public server is experiencing high traffic.`;
    }

    if (status) {
      status.className = 'crt-status-text error';
      status.innerText = isTimeout ? `Timed out after ${elapsedSec}s.` : `Lookup failed: ${err.message}`;
    }

    // Render interactive recovery card
    if (results) {
      results.innerHTML = `
        <div class="crt-error-card">
          <div class="crt-error-header">
            <span class="crt-error-icon">⚠️</span>
            <div style="flex: 1;">
              <div class="crt-error-title">${isTimeout ? 'Query Timed Out' : 'crt.sh Service Error'}</div>
              <div class="crt-error-msg">${escapeHtml(errorDetail)}</div>
            </div>
          </div>
          <div class="crt-error-body">
            <p style="font-size: 0.82rem; color: var(--text-muted); margin: 0 0 0.75rem 0;">
              Public CT servers (<code>crt.sh</code>) periodically experience high PostgreSQL query latency when handling full wildcard queries (<code>%.${escapeHtml(domain)}</code>).
            </p>
            <div class="crt-error-actions">
              <button type="button" id="btn-crt-retry-wildcard" class="primary" style="font-size: 0.8rem; padding: 0.35rem 0.75rem;">
                🔄 Retry Wildcard (%.${escapeHtml(domain)})
              </button>
              ${isWildcard ? `
              <button type="button" id="btn-crt-try-fast" style="font-size: 0.8rem; padding: 0.35rem 0.75rem; background: #3b82f6; color: white;">
                ⚡ Try Fast Query (Apex & SANs)
              </button>
              ` : ''}
              <a href="https://crt.sh/?q=%25.${encodeURIComponent(domain)}" target="_blank" rel="noopener noreferrer" class="btn-ghost" style="font-size: 0.8rem; padding: 0.35rem 0.75rem; text-decoration: none; display: inline-flex; align-items: center; gap: 0.3rem;">
                <span>↗️ Open crt.sh in Browser Tab</span>
              </a>
            </div>
          </div>
        </div>
      `;

      // Bind recovery action buttons
      const retryWildcardBtn = document.getElementById('btn-crt-retry-wildcard');
      if (retryWildcardBtn) {
        retryWildcardBtn.addEventListener('click', () => fetchCrt('wildcard'));
      }
      const tryFastBtn = document.getElementById('btn-crt-try-fast');
      if (tryFastBtn) {
        tryFastBtn.addEventListener('click', () => fetchCrt('fast'));
      }
    }

  } finally {
    if (crtTimerInterval) {
      clearInterval(crtTimerInterval);
      crtTimerInterval = null;
    }
    crtAbortController = null;
    if (fetchBtn) {
      fetchBtn.disabled = false;
      fetchBtn.innerHTML = 'Fetch Subdomains';
    }
    if (cancelBtn) cancelBtn.style.display = 'none';
  }
}

function renderCrtList(hosts) {
  const results = document.getElementById('crt-results');
  if (!results) return;
  if (!hosts || !hosts.length) {
    results.innerHTML = `<p style="color: var(--text-muted); padding: 0.5rem; grid-column: 1 / -1;">No matching subdomains.</p>`;
    return;
  }
  results.innerHTML = hosts.map(s => `
    <label class="crt-item">
      <input type="checkbox" value="${escapeHtml(s)}"> ${escapeHtml(s)}
    </label>
  `).join('');
}

function filterCrtResults(e) {
  const term = e.target.value.toLowerCase().trim();
  const filtered = term ? currentCrtHosts.filter(h => h.includes(term)) : currentCrtHosts;
  renderCrtList(filtered);
}

function toggleCrtSelection(checked) {
  document.querySelectorAll('#crt-results input[type="checkbox"]').forEach(cb => {
    cb.checked = checked;
  });
}

function appendCrtExclusions() {
  const checked = Array.from(document.querySelectorAll('#crt-results input:checked')).map(el => `-site:${el.value}`);
  if (!checked.length) {
    alert('Please select at least one subdomain to exclude.');
    return;
  }
  const current = els.exclude.value.trim();
  els.exclude.value = current ? current + ' ' + checked.join(' ') : checked.join(' ');
  updateQuery();
  showToast(`Appended ${checked.length} subdomain exclusions.`);
}

async function sendCrtToAuditLog() {
  const checked = Array.from(document.querySelectorAll('#crt-results input:checked'));
  if (!checked.length) {
    alert('Please select at least one subdomain to send to the Audit Log.');
    return;
  }

  const targetDomain = els.domain.value.trim() || 'target';
  let addedCount = 0;
  const now = new Date().toISOString();

  checked.forEach((cb, idx) => {
    const host = cb.value;
    const url = `https://${host}`;
    const exists = state.auditLogs.some(a => a.url === url);
    if (!exists) {
      state.auditLogs.push({
        id: (Date.now() + idx).toString(),
        url,
        status: 'investigating',
        notes: `Discovered via Certificate Transparency log query for ${targetDomain}.`,
        query: `crt.sh: %.${targetDomain}`,
        engine: 'crt.sh',
        timestamp: now
      });
      addedCount++;
    }
  });

  if (addedCount > 0) {
    await browser.storage.local.set({ auditLogs: state.auditLogs });
    renderAuditLogs();
    updateChecklist();
    const skipped = checked.length - addedCount;
    if (skipped > 0) {
      showToast(`Added ${addedCount} subdomains to Audit Log (${skipped} already logged).`);
    } else {
      showToast(`Added ${addedCount} subdomains to Audit Log.`);
    }
  } else {
    showToast(`All ${checked.length} selected subdomains are already in the Audit Log.`);
  }
}

// Email Discovery (Public PGP Keyservers)
async function fetchEmails() {
  const domain = els.domain.value.trim();
  if (!domain) {
    els.emailStatus.innerText = 'Target domain is required.';
    return;
  }

  els.emailStatus.innerText = 'Querying public PGP keyserver registry (keyserver.ubuntu.com)...';
  els.emailResults.innerHTML = '';
  els.emailActionsBar.style.display = 'none';
  if (els.emailPatternBanner) els.emailPatternBanner.style.display = 'none';

  const keyservers = [
    { name: 'Ubuntu PGP Keyserver', host: 'keyserver.ubuntu.com', url: `https://keyserver.ubuntu.com/pks/lookup?search=${encodeURIComponent(domain)}&op=index&options=mr` },
    { name: 'SURFnet PGP Keyserver', host: 'pgp.surf.nl', url: `https://pgp.surf.nl/pks/lookup?search=${encodeURIComponent(domain)}&op=index&options=mr` }
  ];

  let text = null;
  let usedServer = null;
  let lastError = null;
  let hadTimeoutOr500 = false;

  for (let i = 0; i < keyservers.length; i++) {
    const server = keyservers[i];
    if (i > 0) {
      els.emailStatus.innerText = `Primary keyserver timed out or returned an error; querying fallback (${server.host})...`;
    } else {
      els.emailStatus.innerText = `Querying public PGP keyserver (${server.host})...`;
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 8000);

    try {
      const res = await fetch(server.url, { signal: controller.signal });
      clearTimeout(timeoutId);

      if (res.status === 404) {
        lastError = new Error('No public PGP key records found for this domain.');
        continue;
      }

      if (res.status >= 500) {
        hadTimeoutOr500 = true;
        lastError = new Error(`Server ${server.host} responded with HTTP ${res.status}`);
        continue;
      }

      if (!res.ok) {
        lastError = new Error(`Server ${server.host} responded with HTTP ${res.status}`);
        continue;
      }

      text = await res.text();
      usedServer = server;
      break;
    } catch (err) {
      clearTimeout(timeoutId);
      if (err.name === 'AbortError') {
        hadTimeoutOr500 = true;
        lastError = new Error(`Connection to ${server.host} timed out`);
      } else {
        lastError = err;
      }
    }
  }

  if (!text) {
    if (hadTimeoutOr500) {
      els.emailStatus.innerText = 'Lookup failed: Keyserver query timed out or failed. Large enterprise domains (e.g. google.com, microsoft.com) often exceed public keyserver database query limits.';
    } else if (lastError && lastError.message.includes('No public PGP key records')) {
      els.emailStatus.innerText = 'No public PGP key records found for this domain.';
    } else {
      els.emailStatus.innerText = `Lookup failed: ${lastError ? lastError.message : 'Unknown keyserver error'}`;
    }
    return;
  }

  try {
    const emailsMap = new Map();
    const lines = text.split('\n');
    let currentKeyYear = null;
    let currentKeyTimestamp = null;

    lines.forEach(line => {
      if (line.startsWith('pub:')) {
        currentKeyYear = null;
        currentKeyTimestamp = null;
        const parts = line.split(':');
        if (parts[4] && /^\d+$/.test(parts[4])) {
          const ts = parseInt(parts[4], 10);
          if (ts > 0) {
            currentKeyYear = new Date(ts * 1000).getFullYear();
            currentKeyTimestamp = ts;
          }
        }
      } else if (line.startsWith('uid:')) {
        try {
          const rawUid = line.slice(4);
          const parts = rawUid.split(':');
          const decodedUid = decodeURIComponent(parts[0] || '');
          let year = currentKeyYear;
          let timestamp = currentKeyTimestamp;
          if (parts[1] && /^\d+$/.test(parts[1])) {
            const ts = parseInt(parts[1], 10);
            if (ts > 0) {
              year = new Date(ts * 1000).getFullYear();
              timestamp = ts;
            }
          }

          const match = decodedUid.match(/^(.*?)(?:<([^>]+@[^>]+)>)?$/);
          if (match) {
            let email = match[2] ? match[2].trim() : (decodedUid.includes('@') ? decodedUid.trim() : null);
            let name = match[1] ? match[1].trim() : '';
            if (email && email.toLowerCase().includes(domain.toLowerCase())) {
              const cleanEmail = email.toLowerCase().replace(/^[<"']+|[>"']+$/g, '');
              if (!emailsMap.has(cleanEmail)) {
                emailsMap.set(cleanEmail, { email: cleanEmail, name, year, timestamp });
              } else {
                const existing = emailsMap.get(cleanEmail);
                if (timestamp && (!existing.timestamp || timestamp > existing.timestamp)) {
                  existing.timestamp = timestamp;
                  existing.year = year;
                } else if (year && (!existing.year || year > existing.year)) {
                  existing.year = year;
                }
                if (name && !existing.name) existing.name = name;
              }
            }
          }
        } catch (_) {}
      }
    });

    // Sort from newest to oldest (by creation timestamp / year descending, ties broken alphabetically)
    currentDiscoveredEmails = Array.from(emailsMap.values()).sort((a, b) => {
      const timeA = a.timestamp || (a.year ? new Date(a.year, 0, 1).getTime() / 1000 : 0);
      const timeB = b.timestamp || (b.year ? new Date(b.year, 0, 1).getTime() / 1000 : 0);
      if (timeB !== timeA) {
        return timeB - timeA;
      }
      return a.email.localeCompare(b.email);
    });

    if (!currentDiscoveredEmails.length) {
      els.emailStatus.innerText = 'No matching domain emails found in public PGP records.';
      return;
    }

    const fallbackNotice = usedServer && usedServer.host !== 'keyserver.ubuntu.com' ? ` (via ${usedServer.host} fallback)` : '';
    els.emailStatus.innerText = `Discovered ${currentDiscoveredEmails.length} unique email identities${fallbackNotice}.`;
    els.emailActionsBar.style.display = 'flex';
    els.emailFilter.value = '';
    renderEmailList(currentDiscoveredEmails);
    detectEmailPattern(currentDiscoveredEmails);
    updateChecklist();

  } catch (err) {
    els.emailStatus.innerText = `Lookup failed: ${err.message}`;
  }
}

function renderEmailList(items) {
  if (!items.length) {
    els.emailResults.innerHTML = `<p style="color: var(--text-muted); padding: 0.5rem;">No matching email addresses found.</p>`;
    return;
  }

  els.emailResults.innerHTML = items.map(item => `
    <label class="crt-item">
      <input type="checkbox" value="${escapeHtml(item.email)}" data-name="${escapeHtml(item.name || '')}">
      <strong>${escapeHtml(item.email)}</strong>
      ${item.name ? `<span class="email-name-tag">(${escapeHtml(item.name)})</span>` : ''}
      ${item.year ? `<span class="key-age-tag ${item.year >= 2022 ? 'tag-recent' : 'tag-legacy'}" title="Public key creation year">${escapeHtml(item.year)}</span>` : ''}
    </label>
  `).join('');
}

function filterEmailResults(e) {
  const term = e.target.value.toLowerCase().trim();
  const filtered = term
    ? currentDiscoveredEmails.filter(i => i.email.includes(term) || (i.name && i.name.toLowerCase().includes(term)))
    : currentDiscoveredEmails;
  renderEmailList(filtered);
}

function toggleEmailSelection(checked) {
  document.querySelectorAll('#email-results input[type="checkbox"]').forEach(cb => {
    cb.checked = checked;
  });
}

async function sendEmailsToAuditLog() {
  const checked = Array.from(document.querySelectorAll('#email-results input:checked'));
  if (!checked.length) {
    alert('Please select at least one email address to send to the Audit Log.');
    return;
  }

  const targetDomain = els.domain.value.trim() || 'target';
  let addedCount = 0;
  const now = new Date().toISOString();

  checked.forEach((cb, idx) => {
    const email = cb.value;
    const name = cb.dataset.name || '';
    const url = `mailto:${email}`;
    const exists = state.auditLogs.some(a => a.url === url);
    if (!exists) {
      state.auditLogs.push({
        id: (Date.now() + idx).toString(),
        url,
        status: 'investigating',
        notes: `Discovered in public PGP key registry for ${targetDomain}.${name ? ' Associated identity: ' + name : ''}`,
        query: `keyserver: ${targetDomain}`,
        engine: 'keyserver',
        timestamp: now
      });
      addedCount++;
    }
  });

  if (addedCount > 0) {
    await browser.storage.local.set({ auditLogs: state.auditLogs });
    renderAuditLogs();
    const skipped = checked.length - addedCount;
    if (skipped > 0) {
      showToast(`Added ${addedCount} emails to Audit Log (${skipped} already logged).`);
    } else {
      showToast(`Added ${addedCount} emails to Audit Log.`);
    }
  } else {
    showToast(`All ${checked.length} selected emails are already in the Audit Log.`);
  }
}

function copySelectedEmails() {
  const checked = Array.from(document.querySelectorAll('#email-results input:checked')).map(cb => cb.value);
  if (!checked.length) {
    alert('Please select at least one email to copy.');
    return;
  }
  navigator.clipboard.writeText(checked.join(', '));
  showToast(`Copied ${checked.length} emails to clipboard.`);
}

// ==========================================
// Infrastructure & ARIN Reconnaissance Scope
// ==========================================

const THIRD_PARTY_PROVIDERS = new Set([
  'cloudflare.com', 'cloudflare.net',
  'amazonaws.com', 'cloudfront.net', 'aws.com',
  'azure-dns.com', 'azure-dns.net', 'azure-dns.org', 'azure-dns.info', 'azureedge.net', 'trafficmanager.net', 'windows.net',
  'google.com', 'googledomains.com', '1e100.net',
  'akamai.net', 'akamaiedge.net', 'akamai.com', 'edgekey.net',
  'fastly.net', 'fastlylb.net',
  'domaincontrol.com', 'registrar-servers.com', 'dnsmadeeasy.com',
  'ultradns.net', 'ultradns.com', 'ultradns.biz', 'ultradns.org',
  'dynect.net', 'nsone.net',
  'incapsula.com', 'impervadns.net', 'imperva.com',
  'exacttarget.com', 'salesforce.com', 'marketo.com', 'hubspot.com', 'zendesk.com',
  'fireeyecloud.com', 'pphosted.com', 'mimecast.com', 'messagelabs.com', 'outlook.com', 'googlemail.com',
  'sectigo.com', 'digicert.com', 'letsencrypt.org', 'entrust.net', 'verisign.com', 'jomax.net'
]);

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function extractApexDomain(hostname) {
  if (!hostname) return '';
  let host = hostname.toLowerCase().trim().replace(/\.$/, '');
  if (host.includes('://')) {
    try {
      host = new URL(host).hostname;
    } catch (_) {
      host = host.split('://')[1].split('/')[0];
    }
  }
  host = host.split(':')[0];
  const parts = host.split('.');
  if (parts.length <= 2) return host;

  const twoPartTlds = [
    'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'me.uk', 'ltd.uk',
    'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
    'co.nz', 'net.nz', 'org.nz',
    'co.jp', 'ne.jp', 'or.jp',
    'com.br', 'net.br', 'org.br',
    'co.za', 'org.za',
    'com.sg', 'edu.sg',
    'com.mx', 'edu.mx', 'gob.mx',
    'co.in', 'net.in', 'org.in', 'gen.in',
    'com.tr', 'edu.tr', 'gov.tr',
    'com.ar', 'com.co'
  ];

  const lastTwo = parts.slice(-2).join('.');
  if (twoPartTlds.includes(lastTwo)) {
    return parts.length >= 3 ? parts.slice(-3).join('.') : host;
  }
  return parts.slice(-2).join('.');
}

function ipRangeToCidr(startIp, endIp) {
  if (!startIp) return '';
  if (!endIp || startIp === endIp) return `${startIp}/32`;

  const ipToLong = (ip) => {
    return ip.split('.').reduce((acc, octet) => ((acc << 8) + parseInt(octet, 10)) >>> 0, 0);
  };

  try {
    const start = ipToLong(startIp);
    const end = ipToLong(endIp);
    if (end < start) return `${startIp} - ${endIp}`;
    const count = end - start + 1;
    if ((count & (count - 1)) === 0) {
      const prefix = 32 - Math.log2(count);
      return `${startIp}/${prefix}`;
    }
  } catch (_) {}
  return `${startIp} - ${endIp}`;
}

function getArinVal(obj, key) {
  if (!obj) return '';
  const val = obj[key] !== undefined ? obj[key] : obj[`@${key}`];
  if (val === undefined || val === null) return '';
  if (typeof val === 'string') return val;
  if (typeof val === 'object' && val['$'] !== undefined) return String(val['$']);
  return String(val);
}

// Query DNS via Google DoH (no custom headers, no preflight, full CORS support), fallback to Cloudflare DoH
async function queryDns(name, type) {
  const cleanName = name.replace(/\.$/, '');
  try {
    const res = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(cleanName)}&type=${encodeURIComponent(type)}`);
    if (res.ok) {
      const data = await res.json().catch(() => null);
      if (data && Array.isArray(data.Answer)) return data.Answer;
    }
  } catch (_) {}

  try {
    const res = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(cleanName)}&type=${encodeURIComponent(type)}`, {
      headers: { 'Accept': 'application/dns-json' }
    });
    if (res.ok) {
      const data = await res.json().catch(() => null);
      if (data && Array.isArray(data.Answer)) return data.Answer;
    }
  } catch (_) {}

  return [];
}

// Fetch ARIN Whois-RWS JSON using native .json suffix (simple GET, no custom headers, no CORS preflight block)
async function fetchArinJson(url) {
  try {
    const res = await fetch(url);
    if (!res.ok) return null;
    return await res.json().catch(() => null);
  } catch (_) {
    return null;
  }
}

// ==========================================
// DNS Zone Intelligence (NS, MX, TXT, DMARC, A, SOA)
// ==========================================

const SAAS_VENDOR_PATTERNS = [
  { name: 'Google Workspace', match: /google-site-verification|_spf\.google\.com|_netblocks.*\.google\.com/i },
  { name: 'Microsoft 365 / Outlook', match: /protection\.outlook\.com|\bMS=ms|\bMS=[0-9A-F]{30,}|microsoft-domain-verification/i },
  { name: 'Atlassian (Jira/Confluence)', match: /atlassian-domain-verification|atlassian/i },
  { name: 'Salesforce', match: /_spf\.salesforce\.com|salesforce/i },
  { name: 'Zendesk', match: /zendesk\.com|zendesk/i },
  { name: 'SendGrid / Twilio', match: /sendgrid\.net|sendgrid/i },
  { name: 'Mailchimp / Mandrill', match: /servers\.mcsv\.net|mandrillapp\.com/i },
  { name: 'Marketo', match: /mktomail\.com/i },
  { name: 'HubSpot', match: /hubspot\.com|hubspot/i },
  { name: 'Mailgun', match: /mailgun\.org/i },
  { name: 'Postmark', match: /postmarkapp\.com/i },
  { name: 'Stripe', match: /stripe-verification/i },
  { name: 'Shopify', match: /shopify-verification/i },
  { name: 'DocuSign', match: /docusign=/i },
  { name: 'Apple Services', match: /apple-domain-verification/i },
  { name: 'Adobe Cloud', match: /adobe-idp-site-verification|adobe-sign-verification/i },
  { name: 'Jamf MDM', match: /jamf-site-verification/i },
  { name: 'Tailscale VPN', match: /TAILSCALE-/i },
  { name: 'Calendly', match: /calendly-site-verification/i },
  { name: 'Slack', match: /slack-domain-verification/i },
  { name: 'GitHub Enterprise', match: /github-domain-verification/i },
  { name: 'OpenAI', match: /openai-domain-verification/i },
  { name: 'Anthropic', match: /anthropic-domain-verification/i },
  { name: 'Miro', match: /miro-verification/i },
  { name: 'Cisco Webex', match: /cisco-ci-domain-verification/i },
  { name: 'Zoom', match: /zoom-domain-verification/i },
  { name: 'Amazon SES / AWS', match: /amazonses\.com|amazon-domain-verification/i },
  { name: 'Proofpoint', match: /pphosted\.com|proofpoint/i },
  { name: 'Mimecast', match: /mimecast\.com/i }
];

function detectMailProvider(host, targetDomain) {
  const cleanHost = (host || '').toLowerCase().replace(/\.$/, '');
  if (cleanHost.includes('google.com') || cleanHost.includes('googlemail.com') || cleanHost.includes('aspmx')) {
    return { name: 'Google Workspace', class: 'dns-tag-cloud' };
  }
  if (cleanHost.includes('outlook.com') || cleanHost.includes('office365.com')) {
    return { name: 'Microsoft 365', class: 'dns-tag-cloud' };
  }
  if (cleanHost.includes('pphosted.com') || cleanHost.includes('proofpoint')) {
    return { name: 'Proofpoint Enterprise', class: 'dns-tag-gateway' };
  }
  if (cleanHost.includes('mimecast.com')) {
    return { name: 'Mimecast Secure Gateway', class: 'dns-tag-gateway' };
  }
  if (cleanHost.includes('barracudanetworks.com')) {
    return { name: 'Barracuda Networks', class: 'dns-tag-gateway' };
  }
  if (cleanHost.includes('iphmx.com')) {
    return { name: 'Cisco IronPort (CES)', class: 'dns-tag-gateway' };
  }
  if (cleanHost.includes('zoho.com')) {
    return { name: 'Zoho Mail', class: 'dns-tag-cloud' };
  }
  if (cleanHost.includes('protonmail.ch') || cleanHost.includes('proton.me')) {
    return { name: 'ProtonMail', class: 'dns-tag-cloud' };
  }
  if (targetDomain && (cleanHost === targetDomain || cleanHost.endsWith('.' + targetDomain))) {
    return { name: '⚠️ Self-Hosted / Direct Gateway', class: 'dns-tag-selfhost' };
  }
  return { name: 'Direct Gateway', class: 'dns-tag-provider' };
}

function detectNsProvider(host) {
  const cleanHost = (host || '').toLowerCase().replace(/\.$/, '');
  if (cleanHost.includes('cloudflare.com')) return 'Cloudflare DNS';
  if (cleanHost.includes('awsdns')) return 'AWS Route 53';
  if (cleanHost.includes('azure-dns')) return 'Azure DNS';
  if (cleanHost.includes('googledomains.com') || cleanHost.includes('googlecloud.com')) return 'Google Cloud DNS';
  if (cleanHost.includes('akam')) return 'Akamai Edge DNS';
  if (cleanHost.includes('dynect.net')) return 'Dyn / Oracle';
  if (cleanHost.includes('nsone.net')) return 'NS1 (IBM)';
  if (cleanHost.includes('ultradns')) return 'Vercara UltraDNS';
  if (cleanHost.includes('domaincontrol.com')) return 'GoDaddy DNS';
  if (cleanHost.includes('registrar-servers.com')) return 'Namecheap DNS';
  return '';
}

function parseDmarcRecord(dmarcStr) {
  if (!dmarcStr) return null;
  const clean = dmarcStr.replace(/^["']+|["']+$/g, '').trim();
  const match = clean.match(/p\s*=\s*([a-zA-Z]+)/i);
  const policy = match ? match[1].toLowerCase() : 'none';
  const ruaMatch = clean.match(/rua\s*=\s*([^;]+)/i);
  const rua = ruaMatch ? ruaMatch[1].trim() : '';
  return {
    raw: clean,
    policy,
    rua,
    statusClass: policy === 'reject' ? 'dmarc-pass' : (policy === 'quarantine' ? 'dmarc-warn' : 'dmarc-fail'),
    statusLabel: policy === 'reject' ? 'Protected (p=reject)' : (policy === 'quarantine' ? 'Monitoring (p=quarantine)' : '⚠️ Inactive / Spoofable (p=none)')
  };
}

function parseSoaRecord(soaStr) {
  if (!soaStr) return null;
  const clean = soaStr.replace(/^["']+|["']+$/g, '').trim();
  const tokens = clean.split(/\s+/);
  if (tokens.length < 2) return null;
  const mname = tokens[0].replace(/\.$/, '');
  let rname = tokens[1].replace(/\.$/, '');
  if (rname.includes('.')) {
    const firstDot = rname.indexOf('.');
    rname = rname.substring(0, firstDot) + '@' + rname.substring(firstDot + 1);
  }
  const serial = tokens[2] || '';
  return { mname, rname, serial, raw: clean };
}

function parseDnsZoneData(targetDomain, rawAnswers) {
  const cleanStr = (s) => (s || '').replace(/^["']+|["']+$/g, '').trim();

  const aList = (rawAnswers.a || []).map(r => cleanStr(r.data)).filter(Boolean);
  const aaaaList = (rawAnswers.aaaa || []).map(r => cleanStr(r.data)).filter(Boolean);

  const nsList = (rawAnswers.ns || []).map(r => {
    const host = cleanStr(r.data).replace(/\.$/, '');
    return {
      host,
      provider: detectNsProvider(host)
    };
  }).filter(n => n.host);

  const mxList = (rawAnswers.mx || []).map(r => {
    const raw = cleanStr(r.data);
    const tokens = raw.split(/\s+/);
    const priority = tokens.length > 1 ? parseInt(tokens[0], 10) : 0;
    const host = (tokens.length > 1 ? tokens[1] : tokens[0]).replace(/\.$/, '');
    const provider = detectMailProvider(host, targetDomain);
    return {
      priority: isNaN(priority) ? 0 : priority,
      host,
      providerName: provider.name,
      providerClass: provider.class
    };
  }).sort((a, b) => a.priority - b.priority).filter(m => m.host && m.host !== '.');

  const rawTxtList = (rawAnswers.txt || []).map(r => cleanStr(r.data)).filter(Boolean);
  let spfRecord = '';
  const txtRecords = [];
  const saasFound = new Set();

  rawTxtList.forEach(txt => {
    if (txt.toLowerCase().startsWith('v=spf1')) {
      spfRecord = txt;
    } else {
      txtRecords.push(txt);
    }
    SAAS_VENDOR_PATTERNS.forEach(vendor => {
      if (vendor.match.test(txt)) {
        saasFound.add(vendor.name);
      }
    });
  });

  let dmarc = null;
  const dmarcAnswers = rawAnswers.dmarc || [];
  if (dmarcAnswers.length > 0 && dmarcAnswers[0].data) {
    dmarc = parseDmarcRecord(dmarcAnswers[0].data);
    if (dmarc) {
      SAAS_VENDOR_PATTERNS.forEach(vendor => {
        if (vendor.match.test(dmarc.raw)) {
          saasFound.add(vendor.name);
        }
      });
    }
  }

  let soa = null;
  const soaAnswers = rawAnswers.soa || [];
  if (soaAnswers.length > 0 && soaAnswers[0].data) {
    soa = parseSoaRecord(soaAnswers[0].data);
  }

  const totalRecords = aList.length + aaaaList.length + nsList.length + mxList.length + rawTxtList.length + (dmarc ? 1 : 0) + (soa ? 1 : 0);

  return {
    domain: targetDomain,
    a: aList,
    aaaa: aaaaList,
    ns: nsList,
    mx: mxList,
    spf: spfRecord,
    txt: txtRecords,
    dmarc,
    soa,
    saasVendors: Array.from(saasFound).sort(),
    totalRecords
  };
}

async function fetchAndRenderDnsZone(targetDomain) {
  if (!targetDomain) {
    renderDnsZone(null);
    return null;
  }

  try {
    const [aRes, aaaaRes, nsRes, mxRes, txtRes, dmarcRes, soaRes] = await Promise.all([
      queryDns(targetDomain, 'A'),
      queryDns(targetDomain, 'AAAA'),
      queryDns(targetDomain, 'NS'),
      queryDns(targetDomain, 'MX'),
      queryDns(targetDomain, 'TXT'),
      queryDns(`_dmarc.${targetDomain}`, 'TXT'),
      queryDns(targetDomain, 'SOA')
    ]);

    const zone = parseDnsZoneData(targetDomain, {
      a: aRes,
      aaaa: aaaaRes,
      ns: nsRes,
      mx: mxRes,
      txt: txtRes,
      dmarc: dmarcRes,
      soa: soaRes
    });

    currentDnsZone = zone;
    renderDnsZone(zone);
    if (typeof updateGraph === 'function') updateGraph();
    return zone;
  } catch (err) {
    console.warn('Failed to fetch DNS zone:', err);
    return null;
  }
}

function renderDnsZone(zone) {
  if (!els.dnsZoneSection) return;

  if (!zone || !zone.totalRecords) {
    els.dnsZoneSection.style.display = 'none';
    return;
  }

  els.dnsZoneSection.style.display = 'block';
  if (els.dnsRecordsCount) els.dnsRecordsCount.innerText = zone.totalRecords;

  // SaaS banner
  if (els.dnsSaasBanner && els.dnsSaasTags) {
    if (zone.saasVendors.length > 0) {
      els.dnsSaasBanner.style.display = 'flex';
      els.dnsSaasTags.innerHTML = zone.saasVendors.map(v => `<span class="dns-saas-chip">✓ ${escapeHtml(v)}</span>`).join('');
    } else {
      els.dnsSaasBanner.style.display = 'none';
    }
  }

  // Card 1: Nameservers (NS)
  if (els.dnsNsCount) els.dnsNsCount.innerText = zone.ns.length;
  if (els.dnsNsList) {
    if (!zone.ns.length) {
      els.dnsNsList.innerHTML = `<span class="dns-card-empty">No NS records returned.</span>`;
    } else {
      els.dnsNsList.innerHTML = zone.ns.map(n => `
        <div class="dns-record-row">
          <span class="dns-record-val">${escapeHtml(n.host)}</span>
          ${n.provider ? `<span class="dns-tag-provider dns-tag-cloud">${escapeHtml(n.provider)}</span>` : ''}
        </div>
      `).join('');
    }
  }

  // Card 2: Mail Exchange Gateways (MX)
  if (els.dnsMxCount) els.dnsMxCount.innerText = zone.mx.length;
  if (els.dnsMxList) {
    if (!zone.mx.length) {
      els.dnsMxList.innerHTML = `<span class="dns-card-empty">No MX records returned (null MX or direct apex routing).</span>`;
    } else {
      els.dnsMxList.innerHTML = zone.mx.map(m => `
        <div class="dns-record-row">
          <span class="dns-badge mx-badge">${m.priority}</span>
          <span class="dns-record-val" style="margin-left: 0.35rem;">${escapeHtml(m.host)}</span>
          <span class="dns-tag-provider ${m.providerClass || 'dns-tag-cloud'}">${escapeHtml(m.providerName)}</span>
        </div>
      `).join('');
    }
  }

  // Card 3: Apex & Authority (A / AAAA / SOA)
  if (els.dnsApexList) {
    let apexHtml = '';
    if (zone.a.length) {
      zone.a.forEach(ip => {
        apexHtml += `
          <div class="dns-record-row">
            <span class="dns-badge a-badge">IPv4</span>
            <span class="dns-record-val" style="margin-left: 0.35rem;">${escapeHtml(ip)}</span>
            <button type="button" class="btn-sm dns-tag-provider" data-action="check-apex-shodan" data-ip="${escapeHtml(ip)}" title="Check Shodan InternetDB for open ports">Shodan</button>
          </div>
        `;
      });
    }
    if (zone.aaaa.length) {
      zone.aaaa.forEach(ip => {
        apexHtml += `
          <div class="dns-record-row">
            <span class="dns-badge" style="background: rgba(148, 163, 184, 0.2); color: #cbd5e1;">IPv6</span>
            <span class="dns-record-val" style="margin-left: 0.35rem; font-size: 0.72rem;">${escapeHtml(ip)}</span>
          </div>
        `;
      });
    }
    if (zone.soa) {
      apexHtml += `
        <div class="dns-record-row" style="margin-top: 0.35rem; border-top: 1px dashed rgba(255,255,255,0.08); padding-top: 0.35rem;">
          <span class="dns-badge" style="background: rgba(14, 165, 233, 0.2); color: #38bdf8;">SOA</span>
          <span class="dns-record-val" style="margin-left: 0.35rem; font-size: 0.72rem;">
            Master: <strong>${escapeHtml(zone.soa.mname)}</strong><br>
            Admin: <code>${escapeHtml(zone.soa.rname)}</code>
          </span>
        </div>
      `;
    }
    if (!apexHtml) {
      apexHtml = `<span class="dns-card-empty">No apex A/AAAA or SOA records resolved.</span>`;
    }
    els.dnsApexList.innerHTML = apexHtml;
  }

  // Card 4: Text Records & DMARC
  if (els.dnsTxtCount) els.dnsTxtCount.innerText = (zone.spf ? 1 : 0) + zone.txt.length + (zone.dmarc ? 1 : 0);
  if (els.dnsTxtList) {
    let txtHtml = '';
    if (zone.dmarc) {
      txtHtml += `
        <div class="dns-record-row" style="background: rgba(255,255,255,0.04);">
          <span class="dmarc-status-pill ${zone.dmarc.statusClass}">DMARC: ${escapeHtml(zone.dmarc.statusLabel)}</span>
          ${zone.dmarc.rua ? `<span style="font-size: 0.68rem; color: var(--text-muted);" title="${escapeHtml(zone.dmarc.rua)}">RUA Configured</span>` : ''}
        </div>
      `;
    } else {
      txtHtml += `
        <div class="dns-record-row">
          <span class="dmarc-status-pill dmarc-fail">⚠️ DMARC: Missing / Not Configured</span>
        </div>
      `;
    }

    if (zone.spf) {
      txtHtml += `
        <div class="dns-record-row" title="${escapeHtml(zone.spf)}">
          <span class="dns-badge txt-badge">SPF</span>
          <span class="dns-record-val" style="margin-left: 0.35rem; font-size: 0.72rem;">${escapeHtml(zone.spf)}</span>
        </div>
      `;
    }

    if (zone.txt.length) {
      zone.txt.slice(0, 8).forEach(txt => {
        txtHtml += `
          <div class="dns-record-row" title="${escapeHtml(txt)}">
            <span class="dns-record-val" style="font-size: 0.72rem;">${escapeHtml(txt.length > 55 ? txt.slice(0, 55) + '...' : txt)}</span>
          </div>
        `;
      });
      if (zone.txt.length > 8) {
        txtHtml += `<div style="font-size: 0.72rem; color: var(--text-muted); text-align: center; padding: 0.2rem 0;">+ ${zone.txt.length - 8} more TXT records</div>`;
      }
    }

    if (!txtHtml) {
      txtHtml = `<span class="dns-card-empty">No TXT or DMARC records found.</span>`;
    }
    els.dnsTxtList.innerHTML = txtHtml;
  }
}

function copyDnsSummary() {
  if (!currentDnsZone || !currentDnsZone.totalRecords) {
    showToast('No DNS records available to copy.');
    return;
  }
  const z = currentDnsZone;
  const lines = [`### DNS Zone Intelligence: ${z.domain}`];
  if (z.a.length) lines.push(`- **Apex IPv4:** ${z.a.join(', ')}`);
  if (z.aaaa.length) lines.push(`- **Apex IPv6:** ${z.aaaa.join(', ')}`);
  if (z.ns.length) lines.push(`- **Nameservers:** ${z.ns.map(n => n.host + (n.provider ? ` (${n.provider})` : '')).join(', ')}`);
  if (z.mx.length) lines.push(`- **Mail Gateways:** ${z.mx.map(m => `[${m.priority}] ${m.host} (${m.providerName})`).join(', ')}`);
  if (z.dmarc) lines.push(`- **DMARC Policy:** ${z.dmarc.statusLabel} (${z.dmarc.raw})`);
  if (z.spf) lines.push(`- **SPF:** ${z.spf}`);
  if (z.saasVendors.length) lines.push(`- **Detected Cloud/SaaS Ecosystem:** ${z.saasVendors.join(', ')}`);
  if (z.soa) lines.push(`- **SOA Master:** ${z.soa.mname} | Admin: ${z.soa.rname}`);

  navigator.clipboard.writeText(lines.join('\n'));
  showToast('Copied DNS Zone summary to clipboard!');
}

async function sendDnsToAuditLog() {
  if (!currentDnsZone || !currentDnsZone.totalRecords) {
    showToast('No DNS records to send.');
    return;
  }
  const z = currentDnsZone;
  const now = new Date().toISOString();
  let addedCount = 0;

  const addFinding = (url, notes, query) => {
    if (!state.auditLogs.some(a => a.url === url)) {
      state.auditLogs.push({
        id: (Date.now() + addedCount).toString(),
        url,
        status: 'investigating',
        notes,
        query,
        engine: 'dns',
        timestamp: now
      });
      addedCount++;
    }
  };

  if (z.mx.length) {
    const mxSummary = z.mx.map(m => `[${m.priority}] ${m.host} (${m.providerName})`).join(', ');
    addFinding(
      `dns://mx.${z.domain}`,
      `Mail Exchange Gateways for ${z.domain}: ${mxSummary}`,
      `DNS MX: ${z.domain}`
    );
  }

  if (z.ns.length) {
    const nsSummary = z.ns.map(n => `${n.host}${n.provider ? ' (' + n.provider + ')' : ''}`).join(', ');
    addFinding(
      `dns://ns.${z.domain}`,
      `Authoritative Nameservers for ${z.domain}: ${nsSummary}`,
      `DNS NS: ${z.domain}`
    );
  }

  if (z.dmarc || z.spf || z.saasVendors.length) {
    const dmarcNote = z.dmarc ? `DMARC: ${z.dmarc.statusLabel}. ` : 'DMARC: Missing. ';
    const saasNote = z.saasVendors.length ? `Detected SaaS Stack: ${z.saasVendors.join(', ')}. ` : '';
    const spfNote = z.spf ? `SPF: ${z.spf}` : '';
    addFinding(
      `dns://email-security.${z.domain}`,
      `Email Security & Cloud Profile for ${z.domain}: ${dmarcNote}${saasNote}${spfNote}`,
      `DNS TXT/DMARC: ${z.domain}`
    );
  }

  if (z.a.length) {
    addFinding(
      `dns://apex.${z.domain}`,
      `Apex Host IPv4 for ${z.domain}: ${z.a.join(', ')}${z.soa ? ` (Zone Master: ${z.soa.mname})` : ''}`,
      `DNS A: ${z.domain}`
    );
  }

  if (addedCount > 0) {
    await browser.storage.local.set({ auditLogs: state.auditLogs });
    renderAuditLogs();
    updateChecklist();
    showToast(`Logged ${addedCount} DNS Zone findings to Audit Log!`);
  } else {
    showToast('All DNS findings for this domain are already logged.');
  }
}

async function checkSingleIpShodan(ip, btn) {
  if (!ip) return;
  const originalText = btn.textContent;
  btn.disabled = true;
  btn.textContent = '...';

  try {
    let hostData = null;
    if (state.shodanApiKey && state.shodanApiKey.trim()) {
      const res = await fetch(`https://api.shodan.io/shodan/host/${encodeURIComponent(ip)}?key=${encodeURIComponent(state.shodanApiKey.trim())}`);
      if (res.ok) hostData = await res.json().catch(() => null);
    }
    if (!hostData) {
      const res = await fetch(`https://internetdb.shodan.io/${encodeURIComponent(ip)}`);
      if (res.ok) hostData = await res.json().catch(() => null);
    }

    if (!hostData || (!hostData.ports || !hostData.ports.length)) {
      showToast(`Shodan: No open ports indexed for ${ip}`);
      btn.textContent = 'No Ports';
      btn.title = 'No open ports indexed by Shodan InternetDB';
    } else {
      const ports = hostData.ports.join(', ');
      const cves = hostData.cves && hostData.cves.length ? ` | CVEs: ${hostData.cves.length}` : '';
      btn.textContent = `Ports: ${ports}${cves}`;
      btn.className = 'btn-sm dns-tag-provider dns-tag-selfhost';
      btn.title = `Open ports on ${ip}: ${ports}${cves}`;
      showToast(`Shodan (${ip}): Open ports [${ports}]${cves}`);
    }
  } catch (_) {
    btn.textContent = 'Err';
  } finally {
    btn.disabled = false;
  }
}

async function fetchInfra(isCustomKeywordSearch = false) {
  const infraVal = (els.infraKeyword ? els.infraKeyword.value : '').trim();
  const domainVal = (els.domain ? els.domain.value : '').trim();

  let rawInput = infraVal || domainVal;
  if (!rawInput) {
    els.infraStatus.innerText = 'Target domain or organization keyword is required.';
    return;
  }

  // Keep inputs synchronized
  if (els.infraKeyword) els.infraKeyword.value = rawInput;
  if (els.domain && !els.domain.value.trim() && rawInput.includes('.')) {
    els.domain.value = rawInput;
    updateQuery();
  }

  let targetDomain = '';
  let companyKeyword = '';
  let baseKeyword = '';

  if (rawInput.includes('.') && !rawInput.includes(' ')) {
    targetDomain = extractApexDomain(rawInput);
    companyKeyword = targetDomain.split('.')[0];
    baseKeyword = companyKeyword.replace(/(corp|inc|llc|group|tech|global|systems|holdings|services|solutions|enterprises)$/i, '');
  } else {
    companyKeyword = rawInput.toLowerCase();
    baseKeyword = companyKeyword.replace(/(corp|inc|llc|group|tech|global|systems|holdings|services|solutions|enterprises)$/i, '');
    if (domainVal) {
      targetDomain = extractApexDomain(domainVal);
    }
  }

  els.infraStatus.innerText = 'Resolving authoritative DNS records and zone assets...';
  currentRelatedDomains = [];
  currentNetblocks = [];
  currentDnsZone = null;
  renderDnsZone(null);
  renderRelatedDomains([]);
  renderNetblocks([]);
  updateChecklist();

  try {
    // 0. Discover & render DNS Zone Intelligence (NS, MX, TXT/SPF, DMARC, A, SOA)
    if (targetDomain) {
      await fetchAndRenderDnsZone(targetDomain);
      updateChecklist();
    }

    // 1. Discover related domains via DNS DoH (takes ~50ms)
    await discoverRelatedDomains(targetDomain, companyKeyword, baseKeyword, (updatedDomains) => {
      currentRelatedDomains = updatedDomains;
      renderRelatedDomains(currentRelatedDomains);
      updateChecklist();
      els.infraStatus.innerText = `Discovered ${currentRelatedDomains.length} related domains. Querying ARIN registry...`;
    });

    // 2. Discover Global netblocks (ARIN, RIPE, RDAP)
    const discoveredApexes = currentRelatedDomains.map(d => d.domain);
    await discoverGlobalNetblocks(targetDomain, companyKeyword, baseKeyword, discoveredApexes, (updatedNets) => {
      currentNetblocks = updatedNets;
      renderNetblocks(currentNetblocks);
      updateChecklist();
      els.infraStatus.innerText = `Found ${currentRelatedDomains.length} related domains and ${currentNetblocks.length} global netblocks. Hydrating Certificate Transparency...`;
    });

    // 3. Hydrate additional brand subsidiaries via crt.sh in background
    await hydrateCtBrandDomains(targetDomain, companyKeyword, baseKeyword, (updatedDomains) => {
      currentRelatedDomains = updatedDomains;
      renderRelatedDomains(currentRelatedDomains);
      updateChecklist();
    });

    els.infraStatus.innerText = `Reconnaissance complete: Found ${currentRelatedDomains.length} related domains and ${currentNetblocks.length} global netblocks.`;
    updateChecklist();
    if (typeof updateGraph === 'function') updateGraph();
    showToast(`Discovered ${currentRelatedDomains.length} related domains and ${currentNetblocks.length} netblocks!`);
  } catch (err) {
    els.infraStatus.innerText = `Reconnaissance error: ${err.message}`;
  }
}

async function discoverRelatedDomains(targetDomain, companyKeyword, baseKeyword, onProgress) {
  const domainsMap = new Map();
  const domainRegex = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/i;

  const addCandidate = (rawHost, source, detail) => {
    if (!rawHost) return;
    const cleanHost = rawHost.trim().toLowerCase().replace(/^\*\./, '').replace(/\.$/, '');
    if (!domainRegex.test(cleanHost)) return;
    const apex = extractApexDomain(cleanHost);
    if (!apex || !domainRegex.test(apex)) return;
    if (targetDomain && apex === targetDomain) return;
    if (THIRD_PARTY_PROVIDERS.has(apex)) return;

    if (!domainsMap.has(apex)) {
      domainsMap.set(apex, { domain: apex, source, detail });
    }
  };

  // 1. DNS Infrastructure Queries (Google DoH / Cloudflare DoH)
  if (targetDomain) {
    const [nsRecords, soaRecords, mxRecords] = await Promise.all([
      queryDns(targetDomain, 'NS'),
      queryDns(targetDomain, 'SOA'),
      queryDns(targetDomain, 'MX')
    ]);

    nsRecords.forEach(ans => {
      if (ans.data) addCandidate(ans.data, 'DNS Nameserver (NS)', `Authoritative NS: ${ans.data.replace(/\.$/, '')}`);
    });

    soaRecords.forEach(ans => {
      if (ans.data) {
        const tokens = ans.data.split(/\s+/);
        if (tokens[0]) addCandidate(tokens[0], 'DNS Authority (SOA)', `Zone Master: ${tokens[0].replace(/\.$/, '')}`);
        if (tokens[1]) addCandidate(tokens[1], 'DNS Authority (SOA)', `Admin RNAME: ${tokens[1].replace(/\.$/, '')}`);
      }
    });

    mxRecords.forEach(ans => {
      if (ans.data) {
        const parts = ans.data.split(/\s+/);
        const host = parts.length > 1 ? parts[1] : parts[0];
        addCandidate(host, 'Mail Gateway (MX)', `Mail Server: ${host.replace(/\.$/, '')}`);
      }
    });

    // Also query sibling NS for top discovered apexes immediately
    const siblings = Array.from(domainsMap.keys());
    for (const sib of siblings.slice(0, 2)) {
      const sibNs = await queryDns(sib, 'NS');
      sibNs.forEach(ans => {
        if (ans.data) addCandidate(ans.data, 'Sibling NS', `Nameserver on ${sib}: ${ans.data.replace(/\.$/, '')}`);
      });
    }
  }

  const list = Array.from(domainsMap.values()).sort((a, b) => a.domain.localeCompare(b.domain));
  if (onProgress) onProgress(list);
  return list;
}

async function discoverGlobalNetblocks(targetDomain, companyKeyword, baseKeyword, discoveredDomains = [], onProgress) {
  const netsMap = new Map();

  const addNetblock = (net) => {
    if (!net || !net.cidr) return;
    if (!netsMap.has(net.cidr)) {
      netsMap.set(net.cidr, net);
    }
  };

  // 1. Resolve Active Web IP: query ARIN with RDAP international fallback
  if (targetDomain) {
    try {
      const aRecords = await queryDns(targetDomain, 'A');
      const ipAns = aRecords.find(a => a.type === 1 || (a.data && /^\d+\.\d+\.\d+\.\d+$/.test(a.data)));
      if (ipAns && ipAns.data) {
        const activeIp = ipAns.data;
        let gotIpNet = false;

        // Try ARIN Whois-RWS first
        const ipData = await fetchArinJson(`https://whois.arin.net/rest/ip/${encodeURIComponent(activeIp)}.json`);
        if (ipData && ipData.net) {
          const net = ipData.net;
          const start = getArinVal(net, 'startAddress');
          const end = getArinVal(net, 'endAddress');
          const cidr = ipRangeToCidr(start, end);
          const name = getArinVal(net, 'name');
          const handle = getArinVal(net, 'handle');
          const orgName = net.orgRef ? (net.orgRef['@name'] || net.orgRef['$'] || '') : '';
          if (cidr) {
            addNetblock({
              handle,
              name: name || handle,
              startAddress: start,
              endAddress: end,
              cidr,
              orgName,
              type: `Active Web Host / WAF (${activeIp})`
            });
            gotIpNet = true;
          }
        }

        // Global RDAP fallback (automatically redirects to RIPE, APNIC, etc.)
        if (!gotIpNet) {
          try {
            const rdapRes = await fetch(`https://rdap.arin.net/registry/ip/${encodeURIComponent(activeIp)}`);
            if (rdapRes.ok) {
              const rdap = await rdapRes.json().catch(() => null);
              if (rdap) {
                const start = rdap.startAddress || '';
                const end = rdap.endAddress || '';
                const cidr = rdap.cidr0_cidrs?.[0] ? `${rdap.cidr0_cidrs[0].v4prefix}/${rdap.cidr0_cidrs[0].length}` : ipRangeToCidr(start, end);
                const name = rdap.name || rdap.handle || activeIp;
                let orgName = '';
                if (rdap.entities) {
                  const ent = rdap.entities.find(e => e.roles && (e.roles.includes('registrant') || e.roles.includes('administrative')));
                  if (ent && ent.vcardArray && Array.isArray(ent.vcardArray[1])) {
                    const fn = ent.vcardArray[1].find(item => item[0] === 'fn');
                    if (fn && fn[3]) orgName = fn[3];
                  }
                }
                if (cidr) {
                  addNetblock({
                    handle: rdap.handle || '',
                    name,
                    startAddress: start,
                    endAddress: end,
                    cidr,
                    orgName,
                    type: `Active Web Host (${activeIp})`
                  });
                }
              }
            }
          } catch (_) {}
        }
      }
    } catch (_) {}
  }

  // 2. Determine search terms from keywords and discovered apexes
  const searchTerms = new Set();
  if (companyKeyword && companyKeyword.length >= 3) searchTerms.add(companyKeyword);
  if (baseKeyword && baseKeyword.length >= 3) searchTerms.add(baseKeyword);
  discoveredDomains.forEach(d => {
    const k = d.split('.')[0];
    if (k && k.length >= 3) searchTerms.add(k);
  });

  // 3. ARIN Whois-RWS lookup (North America)
  for (const term of Array.from(searchTerms).slice(0, 3)) {
    try {
      const orgData = await fetchArinJson(`https://whois.arin.net/rest/orgs;name=${encodeURIComponent(term)}*.json?showNets=true`);
      if (!orgData || !orgData.orgs) continue;

      const orgRefs = Array.isArray(orgData.orgs.orgRef)
        ? orgData.orgs.orgRef
        : (orgData.orgs.orgRef ? [orgData.orgs.orgRef] : []);

      for (const orgRef of orgRefs.slice(0, 4)) {
        const orgHandle = orgRef['@handle'] || orgRef.handle;
        const orgName = orgRef['@name'] || orgRef.name || '';
        if (!orgHandle) continue;

        const netsData = await fetchArinJson(`https://whois.arin.net/rest/org/${encodeURIComponent(orgHandle)}/nets.json`);
        if (!netsData || !netsData.nets) continue;

        const netRefs = Array.isArray(netsData.nets.netRef)
          ? netsData.nets.netRef
          : (netsData.nets.netRef ? [netsData.nets.netRef] : []);

        netRefs.forEach(ref => {
          const start = getArinVal(ref, 'startAddress');
          const end = getArinVal(ref, 'endAddress');
          const handle = getArinVal(ref, 'handle');
          const name = getArinVal(ref, 'name');
          const cidr = ipRangeToCidr(start, end);
          if (cidr) {
            addNetblock({
              handle,
              name: name || handle,
              startAddress: start,
              endAddress: end,
              cidr,
              orgName,
              type: 'ARIN Allocation (Americas)'
            });
          }
        });
      }
    } catch (_) {}
  }

  // 4. RIPE NCC REST lookup (Europe & Global RIR database)
  for (const term of Array.from(searchTerms).slice(0, 3)) {
    try {
      const ripeRes = await fetch(`https://rest.db.ripe.net/search.json?query-string=${encodeURIComponent(term)}&type-filter=organisation`);
      if (!ripeRes.ok) continue;
      const ripeData = await ripeRes.json().catch(() => null);
      if (!ripeData || !ripeData.objects || !Array.isArray(ripeData.objects.object)) continue;

      const ripeOrgs = ripeData.objects.object.filter(o => o.type === 'organisation').slice(0, 4);
      for (const orgObj of ripeOrgs) {
        const orgId = orgObj['primary-key']?.attribute?.[0]?.value || orgObj.link?.href?.split('/').pop();
        if (!orgId) continue;

        const inetRes = await fetch(`https://rest.db.ripe.net/search.json?query-string=${encodeURIComponent(orgId)}&inverse-attribute=org`);
        if (!inetRes.ok) continue;
        const inetData = await inetRes.json().catch(() => null);
        if (!inetData || !inetData.objects || !Array.isArray(inetData.objects.object)) continue;

        const inets = inetData.objects.object.filter(o => o.type === 'inetnum');
        for (const item of inets) {
          const attrs = item.attributes?.attribute || [];
          const inetnumStr = attrs.find(a => a.name === 'inetnum')?.value;
          const netname = attrs.find(a => a.name === 'netname')?.value;
          const descr = attrs.find(a => a.name === 'descr')?.value;
          if (inetnumStr && inetnumStr.includes('-')) {
            const [start, end] = inetnumStr.split('-').map(s => s.trim());
            const cidr = ipRangeToCidr(start, end);
            if (cidr) {
              addNetblock({
                handle: orgId,
                name: netname || descr || orgId,
                startAddress: start,
                endAddress: end,
                cidr,
                orgName: descr || term.toUpperCase(),
                type: 'RIPE Allocation (Europe)'
              });
            }
          }
        }
      }
    } catch (_) {}
  }

  const list = Array.from(netsMap.values()).sort((a, b) => a.cidr.localeCompare(b.cidr));
  if (onProgress) onProgress(list);
  return list;
}
const discoverArinNetblocks = discoverGlobalNetblocks;

async function hydrateCtBrandDomains(targetDomain, companyKeyword, baseKeyword, onProgress) {
  const domainsMap = new Map();
  currentRelatedDomains.forEach(d => domainsMap.set(d.domain, d));
  const domainRegex = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/i;

  const addCandidate = (rawHost, source, detail) => {
    if (!rawHost) return;
    const cleanHost = rawHost.trim().toLowerCase().replace(/^\*\./, '').replace(/\.$/, '');
    if (!domainRegex.test(cleanHost)) return;
    const apex = extractApexDomain(cleanHost);
    if (!apex || !domainRegex.test(apex)) return;
    if (targetDomain && apex === targetDomain) return;
    if (THIRD_PARTY_PROVIDERS.has(apex)) return;

    if (!domainsMap.has(apex)) {
      domainsMap.set(apex, { domain: apex, source, detail });
    }
  };

  // 1. CT logs for %.targetDomain
  if (targetDomain) {
    let data = [];
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 12000);
    try {
      const res = await fetch(`https://crt.sh/?q=%.${encodeURIComponent(targetDomain)}&output=json`, {
        signal: controller.signal
      });
      clearTimeout(timeoutId);
      if (res.ok) {
        data = await res.json().catch(() => []);
      }
    } catch (_) {
      clearTimeout(timeoutId);
      // Fast fallback to apex exact query if wildcard fails or times out
      try {
        const fallbackRes = await fetch(`https://crt.sh/?q=${encodeURIComponent(targetDomain)}&output=json`);
        if (fallbackRes.ok) {
          data = await fallbackRes.json().catch(() => []);
        }
      } catch (_) {}
    }

    if (Array.isArray(data)) {
      data.forEach(cert => {
        if (cert.common_name) addCandidate(cert.common_name, 'TLS Multi-SAN Cert', `Common Name on cert #${cert.id || ''}`);
        if (cert.name_value) {
          cert.name_value.split('\n').forEach(name => {
            addCandidate(name, 'TLS Multi-SAN Cert', `Multi-SAN cross-link`);
          });
        }
      });
    }
  }

  // 2. CT logs for discovered primary sibling (e.g. siblingcorp.com)
  const siblings = Array.from(domainsMap.keys()).filter(d => d !== targetDomain);
  for (const sib of siblings.slice(0, 1)) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000);
    try {
      const res = await fetch(`https://crt.sh/?q=%.${encodeURIComponent(sib)}&output=json`, {
        signal: controller.signal
      });
      clearTimeout(timeoutId);
      if (res.ok) {
        const data = await res.json().catch(() => []);
        if (Array.isArray(data)) {
          data.forEach(cert => {
            if (cert.common_name) addCandidate(cert.common_name, 'Sibling Brand Cert', `Cross-linked on sibling ${sib}`);
            if (cert.name_value) {
              cert.name_value.split('\n').forEach(name => {
                addCandidate(name, 'Sibling Brand Cert', `Multi-SAN on sibling ${sib}`);
              });
            }
          });
        }
      }
    } catch (_) {
      clearTimeout(timeoutId);
    }
  }

  const list = Array.from(domainsMap.values()).sort((a, b) => a.domain.localeCompare(b.domain));
  if (onProgress) onProgress(list);
  return list;
}

function renderRelatedDomains(domains) {
  if (els.infraDomainsCount) els.infraDomainsCount.textContent = domains.length;
  if (!els.infraDomainsList) return;

  if (!domains.length) {
    els.infraDomainsList.innerHTML = `<p style="color: var(--text-muted); padding: 0.5rem;">No related corporate domains discovered.</p>`;
    return;
  }

  els.infraDomainsList.innerHTML = domains.map(d => `
    <div class="domain-card">
      <div class="domain-card-top">
        <span class="domain-name">${escapeHtml(d.domain)}</span>
        <span class="source-badge">${escapeHtml(d.source)}</span>
      </div>
      <div class="domain-detail" style="font-size: 0.75rem; color: var(--text-muted);">${escapeHtml(d.detail || '')}</div>
      <div class="domain-actions">
        <button type="button" class="btn-accent" data-action="set-target" data-domain="${escapeHtml(d.domain)}" title="Set as active composer target">Set as Target</button>
        <button type="button" data-action="discover-emails" data-domain="${escapeHtml(d.domain)}" title="Switch to Emails tab and discover personnel emails">Discover Emails</button>
        <button type="button" data-action="append-exclusion" data-domain="${escapeHtml(d.domain)}" title="Append -site:domain to composer exclusions">Append Exclusion</button>
        <button type="button" data-action="log-domain" data-domain="${escapeHtml(d.domain)}" title="Log to Audit Log">Log Finding</button>
      </div>
    </div>
  `).join('');
}

const RISKY_PORTS = new Set([
  21, 22, 23, 25, 69, 110, 111, 135, 137, 138, 139, 143, 161, 389, 445,
  1433, 1521, 2049, 2375, 2376, 3306, 3389, 5432, 5900, 5901, 6379, 8081,
  9200, 11211, 27017, 50070
]);

const WEB_PORTS = new Set([80, 443, 8000, 8080, 8443, 8888]);

const PORT_NAMES = {
  21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
  80: 'HTTP', 110: 'POP3', 139: 'NetBIOS', 143: 'IMAP', 161: 'SNMP',
  389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 1433: 'MSSQL', 1521: 'Oracle',
  2049: 'NFS', 2375: 'Docker', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
  5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 9200: 'Elastic',
  27017: 'MongoDB'
};

function getSampledIps(startAddress, endAddress, cidr) {
  const ips = [];
  const base = (startAddress || (cidr ? cidr.split('/')[0] : '')).trim();
  const parts = base.split('.').map(Number);
  if (parts.length === 4 && !parts.some(isNaN)) {
    const prefix = `${parts[0]}.${parts[1]}.${parts[2]}`;
    ips.push(`${prefix}.1`);
    ips.push(`${prefix}.2`);
    ips.push(`${prefix}.10`);
    ips.push(`${prefix}.254`);

    if (endAddress) {
      const endParts = endAddress.split('.').map(Number);
      if (endParts.length === 4 && !isNaN(endParts[2]) && endParts[2] !== parts[2]) {
        const endPrefix = `${endParts[0]}.${endParts[1]}.${endParts[2]}`;
        ips.push(`${endPrefix}.1`);
        ips.push(`${endPrefix}.254`);
      }
    }
  }
  return Array.from(new Set(ips));
}

async function probeNetblockPtrs(cidr, start, end, btn) {
  const safeId = (cidr || '').replace(/[^a-zA-Z0-9]/g, '_');
  const container = document.getElementById(`netblock-probe-results-${safeId}`);
  if (!container) return;

  const originalText = btn.textContent;
  btn.disabled = true;
  btn.textContent = 'Probing...';
  container.style.display = 'block';
  container.innerHTML = `
    <div class="netblock-probe-section">
      <div style="display: flex; align-items: center; gap: 0.5rem; color: #93c5fd; font-size: 0.75rem;">
        <span class="spinner" style="width: 12px; height: 12px; border-width: 2px;"></span>
        <span>Probing reverse DNS PTR records via Google DoH...</span>
      </div>
    </div>
  `;

  try {
    const sampledIps = getSampledIps(start, end, cidr);
    const results = [];
    let zoneMaster = null;
    let hostmaster = null;

    await Promise.all(sampledIps.map(async (ip) => {
      try {
        const rev = ip.split('.').reverse().join('.') + '.in-addr.arpa';
        const res = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(rev)}&type=PTR`);
        if (!res.ok) return;
        const data = await res.json().catch(() => null);
        if (!data) return;

        if (Array.isArray(data.Answer) && data.Answer.length > 0) {
          const ptrAnswers = data.Answer.filter(a => a.type === 12 && a.data);
          ptrAnswers.forEach(ans => {
            const hostname = ans.data.replace(/\.$/, '').toLowerCase();
            results.push({ ip, hostname });
          });
        } else if (!zoneMaster && Array.isArray(data.Authority) && data.Authority.length > 0) {
          const soa = data.Authority.find(a => a.type === 6 && a.data);
          if (soa) {
            const tokens = soa.data.split(/\s+/);
            if (tokens[0]) zoneMaster = tokens[0].replace(/\.$/, '');
            if (tokens[1]) hostmaster = tokens[1].replace(/\.$/, '').replace('.', '@');
          }
        }
      } catch (_) {}
    }));

    let html = `
      <div class="netblock-probe-section">
        <div class="probe-header">
          <span>🔍 Reverse DNS PTR Probing (${sampledIps.length} Sampled Hosts)</span>
          <span style="font-size: 0.7rem; color: var(--text-muted); cursor: pointer;" data-action="close-probe" data-cidr="${escapeHtml(cidr)}">✕ Close</span>
        </div>
    `;

    if (results.length > 0) {
      html += `
        <div class="probe-tags" style="margin-top: 0.35rem;">
          ${results.map(r => `
            <span class="ptr-tag">
              <strong>${escapeHtml(r.ip)}</strong> &rarr; ${escapeHtml(r.hostname)}
              <button type="button" class="tag-action" data-action="set-target" data-domain="${escapeHtml(r.hostname)}" title="Set composer target domain">+ Target</button>
              <button type="button" class="tag-action" data-action="dork-host" data-domain="${escapeHtml(r.hostname)}" title="Dork for this host">+ Dork</button>
              <button type="button" class="tag-action" data-action="copy-text" data-text="${escapeHtml(r.hostname)}" title="Copy hostname">Copy</button>
            </span>
          `).join('')}
        </div>
      `;
    } else {
      html += `
        <div style="color: var(--text-muted); font-size: 0.73rem; margin-top: 0.2rem;">
          Probed ${sampledIps.length} sampled IPs (${sampledIps.join(', ')}) &mdash; No public PTR records configured for these individual hosts.
        </div>
      `;
    }

    if (zoneMaster) {
      html += `
        <div style="margin-top: 0.4rem; font-size: 0.72rem; color: #cbd5e1; border-top: 1px solid rgba(255,255,255,0.06); padding-top: 0.35rem;">
          <span style="color: var(--text-muted);">Reverse Zone SOA:</span> <code>${escapeHtml(zoneMaster)}</code>
          ${hostmaster ? `<span style="color: var(--text-muted); margin-left: 0.4rem;">Admin:</span> <code>${escapeHtml(hostmaster)}</code>` : ''}
          <button type="button" class="tag-action" data-action="set-target" data-domain="${escapeHtml(zoneMaster)}" title="Investigate zone master in Vantage" style="margin-left: 0.4rem; color: #60a5fa; cursor: pointer; background: none; border: none; font-size: 0.7rem; font-weight: 600;">+ Target</button>
        </div>
      `;
    }

    html += `</div>`;
    container.innerHTML = html;
    showToast(`PTR Probing: Found ${results.length} PTR record(s) across ${sampledIps.length} sampled IPs.`);
  } catch (err) {
    container.innerHTML = `<div class="netblock-probe-section" style="color: #fca5a5;">PTR Probing failed: ${escapeHtml(err.message)}</div>`;
  } finally {
    btn.disabled = false;
    btn.textContent = originalText;
  }
}

async function checkNetblockPorts(cidr, start, end, btn) {
  const safeId = (cidr || '').replace(/[^a-zA-Z0-9]/g, '_');
  const container = document.getElementById(`netblock-probe-results-${safeId}`);
  if (!container) return;

  const originalText = btn.textContent;
  btn.disabled = true;
  btn.textContent = 'Checking...';
  container.style.display = 'block';
  container.innerHTML = `
    <div class="netblock-probe-section">
      <div style="display: flex; align-items: center; gap: 0.5rem; color: #4ade80; font-size: 0.75rem;">
        <span class="spinner" style="width: 12px; height: 12px; border-width: 2px;"></span>
        <span>Querying Shodan InternetDB & services...</span>
      </div>
    </div>
  `;

  try {
    const sampledIps = getSampledIps(start, end, cidr).slice(0, 3);
    const hostFindings = [];

    for (const ip of sampledIps) {
      let hostData = null;

      // 1. If BYOK Shodan API Key is provided, try deep Shodan host query
      if (state.shodanApiKey) {
        try {
          const sRes = await fetch(`https://api.shodan.io/shodan/host/${encodeURIComponent(ip)}?key=${encodeURIComponent(state.shodanApiKey)}`);
          if (sRes.ok) {
            const data = await sRes.json();
            if (data && data.ports && data.ports.length > 0) {
              hostData = {
                ip,
                ports: data.ports,
                hostnames: data.hostnames || [],
                cpes: data.cpes || [],
                tags: data.tags || [],
                vulns: data.vulns || [],
                source: 'Shodan API (BYOK)'
              };
            }
          }
        } catch (_) {}
      }

      // 2. Fallback / Default: Shodan InternetDB (unauthenticated, fast)
      if (!hostData) {
        try {
          const dbRes = await fetch(`https://internetdb.shodan.io/${encodeURIComponent(ip)}`);
          if (dbRes.ok) {
            const data = await dbRes.json();
            if (data && Array.isArray(data.ports) && data.ports.length > 0) {
              hostData = {
                ip,
                ports: data.ports,
                hostnames: data.hostnames || [],
                cpes: data.cpes || [],
                tags: data.tags || [],
                vulns: data.vulns || [],
                source: 'Shodan InternetDB'
              };
            }
          }
        } catch (_) {}
      }

      if (hostData) {
        hostFindings.push(hostData);
      }
    }

    let html = `
      <div class="netblock-probe-section">
        <div class="probe-header">
          <span>🛡️ Shodan Service & Exposure Intel (${sampledIps.length} Probed IPs &bull; ${state.shodanApiKey ? 'Shodan BYOK Key' : 'InternetDB Free'})</span>
          <span style="font-size: 0.7rem; color: var(--text-muted); cursor: pointer;" data-action="close-probe" data-cidr="${escapeHtml(cidr)}">✕ Close</span>
        </div>
    `;

    if (hostFindings.length > 0) {
      html += hostFindings.map(item => `
        <div style="margin-top: 0.4rem; padding-bottom: 0.4rem; border-bottom: 1px solid rgba(255,255,255,0.06);">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.25rem;">
            <strong style="color: #67e8f9; font-family: var(--font-mono);">${escapeHtml(item.ip)}</strong>
            <span style="color: var(--text-muted); font-size: 0.7rem;">${item.ports.length} Open Port${item.ports.length === 1 ? '' : 's'} &bull; ${escapeHtml(item.source)}</span>
          </div>

          <!-- Ports -->
          <div class="probe-tags" style="margin-bottom: 0.35rem;">
            ${item.ports.map(port => {
              const isRisky = RISKY_PORTS.has(port);
              const isWeb = WEB_PORTS.has(port);
              const portClass = isRisky ? 'port-badge port-risky' : (isWeb ? 'port-badge port-web' : 'port-badge');
              const label = PORT_NAMES[port] ? `${port} (${PORT_NAMES[port]})` : port;
              return `<span class="${portClass}" title="${isRisky ? 'Sensitive/Management Port!' : (isWeb ? 'Web Service' : 'Open Port')}">${escapeHtml(String(label))}</span>`;
            }).join('')}
          </div>

          <!-- Hostnames if any -->
          ${item.hostnames && item.hostnames.length ? `
            <div style="margin-bottom: 0.3rem;">
              <span style="font-size: 0.7rem; color: var(--text-muted); margin-right: 0.3rem;">Hostnames:</span>
              ${item.hostnames.map(h => `
                <span class="ptr-tag">
                  ${escapeHtml(h)}
                  <button type="button" class="tag-action" data-action="set-target" data-domain="${escapeHtml(h)}" title="Set composer target domain">+ Target</button>
                  <button type="button" class="tag-action" data-action="dork-host" data-domain="${escapeHtml(h)}" title="Dork for this host">+ Dork</button>
                </span>
              `).join('')}
            </div>
          ` : ''}

          <!-- CPEs / Software if any -->
          ${item.cpes && item.cpes.length ? `
            <div style="margin-bottom: 0.3rem; font-size: 0.7rem; color: var(--text-muted);">
              <span>CPEs: </span><code>${escapeHtml(item.cpes.slice(0, 3).join(', '))}</code>
            </div>
          ` : ''}

          <!-- CVEs if any -->
          ${item.vulns && item.vulns.length ? `
            <div style="display: flex; flex-wrap: wrap; gap: 0.3rem; align-items: center; margin-top: 0.3rem;">
              <span style="font-size: 0.7rem; color: #f87171; font-weight: 600;">⚠️ Known Vulnerabilities (${item.vulns.length}):</span>
              ${item.vulns.slice(0, 8).map(cve => `
                <a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve)}" target="_blank" rel="noopener noreferrer" class="cve-badge" title="Inspect ${escapeHtml(cve)} on NIST NVD">${escapeHtml(cve)}</a>
              `).join('')}
              ${item.vulns.length > 8 ? `<span style="font-size: 0.7rem; color: #fca5a5;">+${item.vulns.length - 8} more</span>` : ''}
            </div>
          ` : ''}
        </div>
      `).join('');
    } else {
      html += `
        <div style="color: var(--text-muted); font-size: 0.73rem; margin-top: 0.2rem;">
          Checked IPs (${sampledIps.join(', ')}) &mdash; No open ports or vulnerabilities currently indexed in Shodan. (Hosts may be firewalled or not responding).
        </div>
      `;
    }

    html += `</div>`;
    container.innerHTML = html;

    const totalOpenPorts = hostFindings.reduce((acc, h) => acc + h.ports.length, 0);
    showToast(`Shodan: Found ${totalOpenPorts} open port(s) across ${hostFindings.length} responding host(s).`);
  } catch (err) {
    container.innerHTML = `<div class="netblock-probe-section" style="color: #fca5a5;">Shodan check failed: ${escapeHtml(err.message)}</div>`;
  } finally {
    btn.disabled = false;
    btn.textContent = originalText;
  }
}

function renderNetblocks(nets) {
  if (els.infraNetsCount) els.infraNetsCount.textContent = nets.length;
  if (els.infraNetActions) els.infraNetActions.style.display = nets.length ? 'flex' : 'none';
  if (!els.infraNetsList) return;

  if (!nets.length) {
    els.infraNetsList.innerHTML = `<p style="color: var(--text-muted); padding: 0.5rem;">No corporate IP netblocks found.</p>`;
    return;
  }

  els.infraNetsList.innerHTML = nets.map((n, idx) => {
    const safeId = (n.cidr || String(idx)).replace(/[^a-zA-Z0-9]/g, '_');
    return `
    <div class="netblock-card" id="netcard-${safeId}">
      <div class="netblock-card-top">
        <span class="netblock-name">${escapeHtml(n.name || n.handle)}</span>
        <span class="source-badge">${escapeHtml(n.type || 'Global Netblock')}</span>
      </div>
      <div class="netblock-cidr">${escapeHtml(n.cidr)}</div>
      <div class="netblock-range">${escapeHtml(n.startAddress || '')}${n.endAddress ? ' - ' + escapeHtml(n.endAddress) : ''}</div>
      ${n.orgName ? `<div class="netblock-org">Org: ${escapeHtml(n.orgName)}${n.handle ? ' (' + escapeHtml(n.handle) + ')' : ''}</div>` : ''}
      <div class="netblock-actions">
        <button type="button" class="btn-accent" data-action="dork-ip" data-cidr="${escapeHtml(n.cidr)}" data-start="${escapeHtml(n.startAddress || '')}" title="Load IP prefix into composer to dork for exposures">Dork IP Range</button>
        <button type="button" data-action="probe-ptrs" data-cidr="${escapeHtml(n.cidr)}" data-start="${escapeHtml(n.startAddress || '')}" data-end="${escapeHtml(n.endAddress || '')}" title="Probe reverse DNS PTR records across key sampled IPs">🔍 Probe PTRs</button>
        <button type="button" data-action="check-ports" data-cidr="${escapeHtml(n.cidr)}" data-start="${escapeHtml(n.startAddress || '')}" data-end="${escapeHtml(n.endAddress || '')}" title="Query Shodan for open ports, services, and CVEs">🛡️ Check Ports</button>
        <button type="button" data-action="copy-net" data-cidr="${escapeHtml(n.cidr)}" title="Copy CIDR to clipboard">Copy CIDR</button>
        <button type="button" data-action="log-net" data-cidr="${escapeHtml(n.cidr)}" data-name="${escapeHtml(n.name || '')}" data-org="${escapeHtml(n.orgName || '')}" title="Log to Audit Log">Log Netblock</button>
      </div>
      <div id="netblock-probe-results-${safeId}" class="netblock-probe-container" style="display: none;"></div>
    </div>
  `;
  }).join('');
}

async function handleDomainAction(e) {
  const btn = e.target.closest('button[data-action]');
  if (!btn) return;
  const action = btn.dataset.action;
  const domain = btn.dataset.domain;
  if (!domain) return;

  if (action === 'set-target') {
    els.domain.value = domain;
    updateQuery();
    showToast(`Target domain set to: ${domain}`);
    const composer = document.querySelector('.composer');
    if (composer) {
      composer.classList.add('highlight');
      setTimeout(() => composer.classList.remove('highlight'), 1200);
    }
  } else if (action === 'discover-emails') {
    els.domain.value = domain;
    updateQuery();
    switchTab('tab-emails');
    fetchEmails();
    showToast(`Switched target to ${domain} and initiated email discovery!`);
  } else if (action === 'append-exclusion') {
    const exc = `-site:${domain}`;
    const current = els.exclude.value.trim();
    if (!current.includes(exc)) {
      els.exclude.value = current ? `${current} ${exc}` : exc;
      updateQuery();
      showToast(`Appended ${exc} to composer exclusions.`);
    } else {
      showToast(`${exc} is already excluded.`);
    }
  } else if (action === 'log-domain') {
    const item = currentRelatedDomains.find(d => d.domain === domain) || { domain, source: 'Infrastructure Discovery' };
    const url = `https://${domain}`;
    const exists = state.auditLogs.some(a => a.url === url);
    if (exists) {
      showToast(`${domain} is already logged in the Audit Log.`);
      return;
    }
    state.auditLogs.push({
      id: Date.now().toString(),
      url,
      status: 'investigating',
      notes: `Discovered related corporate domain: ${domain}. Source: ${item.source}.${item.detail ? ' ' + item.detail : ''}`,
      query: `Infrastructure Reconnaissance: ${domain}`,
      engine: 'dns',
      timestamp: new Date().toISOString()
    });
    await browser.storage.local.set({ auditLogs: state.auditLogs });
    renderAuditLogs();
    updateChecklist();
    showToast(`Logged ${domain} to Audit Log!`);
  }
}

async function handleNetAction(e) {
  const btn = e.target.closest('[data-action]');
  if (!btn) return;
  const action = btn.dataset.action;
  const cidr = btn.dataset.cidr;
  const start = btn.dataset.start;
  const end = btn.dataset.end;

  if (action === 'probe-ptrs') {
    await probeNetblockPtrs(cidr, start, end, btn);
    return;
  }

  if (action === 'check-ports') {
    await checkNetblockPorts(cidr, start, end, btn);
    return;
  }

  if (action === 'close-probe') {
    const safeId = (cidr || '').replace(/[^a-zA-Z0-9]/g, '_');
    const container = document.getElementById(`netblock-probe-results-${safeId}`);
    if (container) container.style.display = 'none';
    return;
  }

  if (action === 'dork-host') {
    const host = btn.dataset.domain;
    if (host) {
      els.domain.value = host;
      els.inurl.value = '';
      els.intitle.value = '';
      els.filetype.value = '';
      els.exact.value = '';
      els.exclude.value = '';
      updateQuery();
      showToast(`Loaded site:${host} into composer!`);
      const composer = document.querySelector('.composer');
      if (composer) {
        composer.classList.add('highlight');
        setTimeout(() => composer.classList.remove('highlight'), 1200);
      }
    }
    return;
  }

  if (action === 'set-target') {
    const host = btn.dataset.domain;
    if (host) {
      els.domain.value = host;
      updateQuery();
      showToast(`Target domain set to: ${host}`);
      const composer = document.querySelector('.composer');
      if (composer) {
        composer.classList.add('highlight');
        setTimeout(() => composer.classList.remove('highlight'), 1200);
      }
    }
    return;
  }

  if (action === 'copy-text') {
    const text = btn.dataset.text;
    if (text) {
      navigator.clipboard.writeText(text);
      showToast(`Copied ${text} to clipboard!`);
    }
    return;
  }

  if (action === 'dork-ip') {
    const octets = (start || cidr.split('/')[0]).split('.');
    const ipPrefix = `${octets[0]}.${octets[1]}.${octets[2]}.`;
    els.domain.value = '';
    els.inurl.value = ipPrefix;
    els.intitle.value = 'index of';
    els.filetype.value = '';
    els.exact.value = '';
    els.exclude.value = '';
    updateQuery();
    showToast(`Loaded IP prefix (${ipPrefix}) into composer inurl operator!`);
    const composer = document.querySelector('.composer');
    if (composer) {
      composer.classList.add('highlight');
      setTimeout(() => composer.classList.remove('highlight'), 1200);
    }
  } else if (action === 'copy-net') {
    navigator.clipboard.writeText(cidr);
    showToast(`Copied ${cidr} to clipboard!`);
  } else if (action === 'log-net') {
    const net = currentNetblocks.find(n => n.cidr === cidr) || { cidr, name: btn.dataset.name, orgName: btn.dataset.org };
    const url = `net://${cidr}`;
    const exists = state.auditLogs.some(a => a.url === url);
    if (exists) {
      showToast(`${cidr} is already logged in the Audit Log.`);
      return;
    }
    state.auditLogs.push({
      id: Date.now().toString(),
      url,
      status: 'investigating',
      notes: `Global Netblock (${net.type || 'RIR'}): ${net.name || 'Netblock'} (${net.orgName || 'N/A'}). Range: ${net.startAddress || cidr} - ${net.endAddress || ''}`,
      query: `IP Netblock: ${cidr}`,
      engine: 'arin',
      timestamp: new Date().toISOString()
    });
    await browser.storage.local.set({ auditLogs: state.auditLogs });
    renderAuditLogs();
    updateChecklist();
    showToast(`Logged netblock ${cidr} to Audit Log!`);
  }
}

function copyAllNetblocks() {
  if (!currentNetblocks.length) {
    showToast('No netblocks to copy.');
    return;
  }
  const text = currentNetblocks.map(n => `${n.cidr}\t# ${n.name || ''} (${n.orgName || n.type || 'RIR'})`).join('\n');
  navigator.clipboard.writeText(text);
  showToast(`Copied ${currentNetblocks.length} CIDRs to clipboard!`);
}

async function sendAllNetsToAuditLog() {
  if (!currentNetblocks.length) {
    showToast('No netblocks to log.');
    return;
  }
  let addedCount = 0;
  const now = new Date().toISOString();

  currentNetblocks.forEach((net, idx) => {
    const url = `net://${net.cidr}`;
    const exists = state.auditLogs.some(a => a.url === url);
    if (!exists) {
      state.auditLogs.push({
        id: (Date.now() + idx).toString(),
        url,
        status: 'investigating',
        notes: `Global Netblock (${net.type || 'RIR'}): ${net.name || 'Netblock'} (${net.orgName || 'N/A'}). Range: ${net.startAddress || ''} - ${net.endAddress || ''}`,
        query: `IP Netblock: ${net.cidr}`,
        engine: 'arin',
        timestamp: now
      });
      addedCount++;
    }
  });

  if (addedCount > 0) {
    await browser.storage.local.set({ auditLogs: state.auditLogs });
    renderAuditLogs();
    updateChecklist();
    showToast(`Logged ${addedCount} netblocks to Audit Log!`);
  } else {
    showToast('All discovered netblocks are already logged.');
  }
}

// Audit Log & Findings Triage
async function logFinding() {
  const url = document.getElementById('a-url').value.trim();
  const status = document.getElementById('a-status').value;
  const notes = document.getElementById('a-notes').value.trim();
  const query = (els.auditQuery.value || els.output.value).trim();

  if (!url) {
    alert('Finding URL is required.');
    return;
  }

  const entry = {
    id: Date.now().toString(),
    url,
    status,
    notes,
    query,
    engine: Array.from(els.engines).find(e => e.checked).value,
    timestamp: new Date().toISOString()
  };

  state.auditLogs.push(entry);
  await browser.storage.local.set({ auditLogs: state.auditLogs });
  
  document.getElementById('a-url').value = '';
  document.getElementById('a-notes').value = '';
  renderAuditLogs();
  updateChecklist();
  showToast('Finding logged to audit list.');
}

function renderAuditLogs() {
  const container = document.getElementById('audit-list');
  const totalCount = state.auditLogs.length;

  if (!totalCount) {
    els.auditCount.innerText = '0';
    container.innerHTML = `<p style="color: var(--text-muted);">No findings logged yet. Use the form above or "Send Selected to Audit Log" to record discoveries.</p>`;
    return;
  }

  const filter = els.auditFilterStatus ? els.auditFilterStatus.value : 'all';
  const filtered = filter === 'all' ? state.auditLogs : state.auditLogs.filter(a => a.status === filter);

  els.auditCount.innerText = filter === 'all' ? `${totalCount}` : `${filtered.length} of ${totalCount}`;

  if (!filtered.length) {
    container.innerHTML = `<p style="color: var(--text-muted);">No findings match status "${filter}".</p>`;
    return;
  }

  const statusMap = {
    investigating: { label: 'Under Review', class: 'status-investigating' },
    hit: { label: 'Confirmed', class: 'status-hit' },
    false_positive: { label: 'False Positive', class: 'status-false_positive' },
    resolved: { label: 'Fixed', class: 'status-resolved' }
  };

  container.innerHTML = [...filtered].reverse().map(a => {
    const st = statusMap[a.status] || { label: a.status, class: '' };
    const isSafeHttp = /^https?:\/\//i.test(a.url || '');
    return `
      <div class="audit-entry">
        <div class="audit-entry-top">
          <div class="audit-status-wrap">
            <span class="status-badge ${escapeHtml(st.class)}">${escapeHtml(st.label)}</span>
            <select class="audit-status-select" data-action="change-status" data-id="${escapeHtml(a.id)}" title="Change finding status">
              <option value="investigating" ${a.status === 'investigating' ? 'selected' : ''}>Under Review</option>
              <option value="hit" ${a.status === 'hit' ? 'selected' : ''}>Confirmed</option>
              <option value="false_positive" ${a.status === 'false_positive' ? 'selected' : ''}>False Positive</option>
              <option value="resolved" ${a.status === 'resolved' ? 'selected' : ''}>Fixed</option>
            </select>
          </div>
          <span class="audit-meta">${new Date(a.timestamp).toLocaleString()} &bull; Engine: ${escapeHtml((a.engine || '').toUpperCase())}</span>
        </div>
        <div class="audit-url">
          ${isSafeHttp
            ? `<a href="${escapeHtml(a.url)}" target="_blank" rel="noopener noreferrer" title="Live visit (warning: sends requests from your browser to target)">${escapeHtml(a.url)}</a>`
            : `<span>${escapeHtml(a.url || '')}</span>`}
        </div>
        <div class="audit-query"><code>${escapeHtml(a.query || 'N/A')}</code></div>
        ${a.notes ? `<div class="audit-notes">${escapeHtml(a.notes).replace(/\n/g, '<br>')}</div>` : ''}
        <div class="audit-entry-bottom">
          <span class="audit-id-label">ID: ${escapeHtml(String(a.id || '').slice(-6))}</span>
          <div class="audit-entry-actions">
            <button type="button" class="btn-sm btn-ghost btn-urlscan-action" data-action="urlscan" data-id="${escapeHtml(a.id)}" title="Passively search historical scans on urlscan.io without sending packets to target">🔍 urlscan</button>
            <button type="button" class="btn-sm" style="font-size: 0.75rem; padding: 0.25rem 0.6rem;" data-action="delete" data-id="${escapeHtml(a.id)}">Delete Entry</button>
          </div>
        </div>
      </div>
    `;
  }).join('');
}

async function updateAuditStatus(id, newStatus) {
  const entry = state.auditLogs.find(a => a.id === id);
  if (!entry) return;
  entry.status = newStatus;
  await browser.storage.local.set({ auditLogs: state.auditLogs });
  renderAuditLogs();
  updateChecklist();
  const labelMap = {
    investigating: 'Under Review',
    hit: 'Confirmed',
    false_positive: 'False Positive',
    resolved: 'Fixed'
  };
  showToast(`Finding marked as "${labelMap[newStatus] || newStatus}".`);
}

window.deleteAuditFinding = async (id) => {
  if (!confirm('Delete this finding entry?')) return;
  state.auditLogs = state.auditLogs.filter(a => a.id !== id);
  await browser.storage.local.set({ auditLogs: state.auditLogs });
  renderAuditLogs();
  updateChecklist();
  showToast('Finding deleted.');
};

function buildUrlscanSearchUrl(target) {
  if (!target) return null;
  target = target.trim();
  let query = '';

  if (/^mailto:/i.test(target) || (target.includes('@') && !target.includes('/'))) {
    const email = target.replace(/^mailto:/i, '').trim();
    const domainPart = email.split('@')[1];
    query = domainPart ? `domain:${domainPart.toLowerCase()}` : `"${target}"`;
  } else if (/^https?:\/\//i.test(target)) {
    try {
      const u = new URL(target);
      if ((u.pathname && u.pathname !== '/') || u.search) {
        query = `page.url:"${target.replace(/"/g, '\\"')}"`;
      } else {
        query = `domain:${u.hostname.toLowerCase()}`;
      }
    } catch (e) {
      const host = target.replace(/^https?:\/\//i, '').split('/')[0];
      query = `domain:${host.toLowerCase()}`;
    }
  } else if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\/\d{1,2})?$/.test(target)) {
    const ipOnly = target.split('/')[0];
    query = `ip:${ipOnly}`;
  } else {
    const cleanHost = target.replace(/^https?:\/\//i, '').replace(/[\/:]+.*$/, '').trim().toLowerCase();
    query = `domain:${cleanHost}`;
  }

  return `https://urlscan.io/search/#${encodeURI(query)}`;
}

function openAuditUrlscan(id) {
  const entry = state.auditLogs.find(a => a.id === id);
  if (!entry || !entry.url) return;
  const searchUrl = buildUrlscanSearchUrl(entry.url);
  if (searchUrl) {
    window.open(searchUrl, '_blank');
    showToast('Opening passive urlscan search in new tab');
  }
}

function openFormUrlscan() {
  const urlInput = document.getElementById('a-url');
  const val = urlInput ? urlInput.value.trim() : '';
  if (!val) {
    alert('Please enter a finding URL or domain in the form first.');
    return;
  }
  const searchUrl = buildUrlscanSearchUrl(val);
  if (searchUrl) {
    window.open(searchUrl, '_blank');
    showToast('Opening passive urlscan search in new tab');
  }
}


async function clearFalsePositives() {
  const fpList = state.auditLogs.filter(a => a.status === 'false_positive');
  if (!fpList.length) {
    showToast('No False Positive items found to clear.');
    return;
  }
  if (!confirm(`Are you sure you want to remove all ${fpList.length} False Positive findings?`)) return;
  state.auditLogs = state.auditLogs.filter(a => a.status !== 'false_positive');
  await browser.storage.local.set({ auditLogs: state.auditLogs });
  renderAuditLogs();
  updateChecklist();
  showToast(`Removed ${fpList.length} False Positive findings.`);
}

async function clearFixedItems() {
  const fixedList = state.auditLogs.filter(a => a.status === 'resolved');
  if (!fixedList.length) {
    showToast('No Fixed items found to clear.');
    return;
  }
  if (!confirm(`Are you sure you want to remove all ${fixedList.length} Fixed findings?`)) return;
  state.auditLogs = state.auditLogs.filter(a => a.status !== 'resolved');
  await browser.storage.local.set({ auditLogs: state.auditLogs });
  renderAuditLogs();
  updateChecklist();
  showToast(`Removed ${fixedList.length} Fixed findings.`);
}

async function clearAuditLogs() {
  if (!state.auditLogs.length) return;
  if (!confirm('Are you sure you want to clear all logged audit findings?')) return;
  state.auditLogs = [];
  await browser.storage.local.set({ auditLogs: state.auditLogs });
  renderAuditLogs();
  updateChecklist();
  showToast('All audit logs cleared.');
}

function exportObsidian() {
  if (!state.auditLogs.length) {
    alert('No audit logs available to export.');
    return;
  }

  const target = els.domain.value.trim() || 'exposure-audit';
  const date = new Date().toISOString().split('T')[0];
  const engines = [...new Set(state.auditLogs.map(a => a.engine.toUpperCase()))].join(', ');

  const calloutMap = {
    hit: '[!danger] Confirmed Exposure',
    investigating: '[!warning] Under Review / Potential Lead',
    false_positive: '[!note] False Positive / Benign',
    resolved: '[!tip] Fixed / Remediated'
  };

  const tagMap = {
    hit: '#triage/confirmed',
    investigating: '#triage/under_review',
    false_positive: '#triage/false_positive',
    resolved: '#triage/fixed'
  };

  let md = `---
target: ${target}
date: ${date}
total_records: ${state.auditLogs.length}
source: Vantage
tags:
  - audit/findings
  - search/exposure
  - security/osint
---

# Vantage Attack Surface & Exposure Audit Report: ${target}

> [!info] Audit Scope & Summary
> - **Target Domain:** \`${target}\`
> - **Report Date:** \`${date}\`
> - **Total Findings:** ${state.auditLogs.length}
> - **Engines Used:** ${engines}

---

`;

  state.auditLogs.forEach((a, idx) => {
    let hostname = a.url;
    try {
      hostname = new URL(a.url.startsWith('http') ? a.url : `https://${a.url}`).hostname;
    } catch (_) {}

    const callout = calloutMap[a.status] || '[!note] Finding Details';
    const tag = tagMap[a.status] || `#triage/${a.status}`;

    md += `### Finding ${idx + 1}: ${hostname}
- **Status:** ${tag}
- **Discovered:** \`${a.timestamp}\`
- **Engine:** \`${a.engine}\`
- **Query:** \`${a.query}\`
- **URL:** [${a.url}](${a.url})

> ${callout}
> **Analyst Notes:**  
> ${a.notes ? a.notes.replace(/\n/g, '\n> ') : 'No notes provided.'}

---
`;
  });

  downloadData(md, `${target}_audit_${date}.md`, 'text/markdown');
}

// Backup & Import
async function exportData() {
  const exp = {
    templates: state.templates,
    profiles: state.profiles,
    auditLogs: state.auditLogs,
    exportedAt: new Date().toISOString()
  };
  downloadData(JSON.stringify(exp, null, 2), 'vantage_full_backup.json', 'application/json');
}

function downloadData(content, filename, type) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function importData(e) {
  const file = e.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = async (ev) => {
    try {
      const data = JSON.parse(ev.target.result);
      if (data.templates && Array.isArray(data.templates)) state.templates = data.templates;
      if (data.profiles && Array.isArray(data.profiles)) state.profiles = data.profiles;
      if (data.auditLogs && Array.isArray(data.auditLogs)) state.auditLogs = data.auditLogs;

      await browser.storage.local.set({
        templates: state.templates,
        profiles: state.profiles,
        auditLogs: state.auditLogs
      });

      updatePresetDropdown();
      updateCategoryFilterDropdown();
      renderTemplates();
      renderProfiles();
      renderAuditLogs();
      showToast('Data imported successfully!');
    } catch (err) {
      alert('Failed to parse backup JSON file: ' + err.message);
    }
    e.target.value = '';
  };
  reader.readAsText(file);
}

// Guidance Mode Toggle
function setGuidance(enabled) {
  state.showGuidance = enabled;
  if (enabled) {
    document.body.classList.add('show-guidance');
  } else {
    document.body.classList.remove('show-guidance');
  }
  if (els.toggleGuidance) {
    els.toggleGuidance.checked = enabled;
  }
  browser.storage.local.set({ showGuidance: enabled });
  if (state.activeTemplateId) {
    updateExposureCard(state.activeTemplateId);
  }
}

// Exposure Intelligence Card
function updateExposureCard(templateId) {
  if (!els.exposureCard) return;
  const t = state.templates.find(x => x.id === templateId);
  if (!t || !t.whatItLeaks) {
    els.exposureCard.style.display = 'none';
    return;
  }

  if (els.expRiskBadge) {
    els.expRiskBadge.className = `risk-badge risk-${(t.risk || 'high').toLowerCase()}`;
    els.expRiskBadge.textContent = `${(t.risk || 'HIGH')} RISK`;
  }
  if (els.expTemplateTitle) els.expTemplateTitle.textContent = t.name;
  if (els.expWhatLeaks) els.expWhatLeaks.textContent = t.whatItLeaks || 'Potential data exposure.';
  if (els.expTruePositive) els.expTruePositive.innerHTML = t.truePositive ? escapeHtml(t.truePositive).replace(/`([^`]+)`/g, '<code>$1</code>') : 'Verify content directly.';
  if (els.expRemediation) els.expRemediation.textContent = t.remediation || 'Restrict unauthorized access to sensitive endpoints.';

  els.exposureCard.style.display = 'block';
}

// Guided Audit Checklist Methodology
function updateChecklist() {
  const domainSet = !!(els.domain && els.domain.value.trim());
  const crtDone = currentCrtHosts.length > 0;
  const infraDone = (currentDnsZone && currentDnsZone.totalRecords > 0) || currentRelatedDomains.length > 0 || currentNetblocks.length > 0;
  const emailsDone = currentDiscoveredEmails.length > 0;
  const dorksDone = (state.dorksRun > 0) || state.auditLogs.some(a => a.engine !== 'crt.sh' && a.engine !== 'keyserver' && a.engine !== 'arin' && a.engine !== 'network');
  const exportDone = state.auditLogs.length > 0;

  const steps = [
    { id: 'step-target', complete: domainSet },
    { id: 'step-crt', complete: crtDone },
    { id: 'step-infra', complete: infraDone },
    { id: 'step-emails', complete: emailsDone },
    { id: 'step-dorks', complete: dorksDone },
    { id: 'step-export', complete: exportDone }
  ];

  let completedCount = 0;
  steps.forEach(s => {
    const el = document.getElementById(s.id);
    if (!el) return;
    const statusIcon = el.querySelector('.step-status');
    if (s.complete) {
      completedCount++;
      el.classList.add('completed');
      if (statusIcon) statusIcon.textContent = '✅';
    } else {
      el.classList.remove('completed');
      if (statusIcon) statusIcon.textContent = '⏳';
    }
  });

  if (els.checklistProgressText) {
    els.checklistProgressText.textContent = `${completedCount} / 6 Done`;
    if (completedCount === 6) {
      els.checklistProgressText.style.color = '#4ade80';
      els.checklistProgressText.style.borderColor = '#22c55e';
    } else {
      els.checklistProgressText.style.color = '';
      els.checklistProgressText.style.borderColor = '';
    }
  }
}

function toggleChecklistCollapse() {
  if (!els.checklistSteps) return;
  const isCollapsed = els.checklistSteps.classList.toggle('collapsed');
  state.checklistCollapsed = isCollapsed;
  if (els.btnToggleChecklist) {
    els.btnToggleChecklist.textContent = isCollapsed ? 'Expand' : 'Minimize';
  }
}

// Guided Audit Methodology "What & Why" Knowledge Base
const METHODOLOGY_STEPS = {
  1: {
    num: 1,
    title: 'Scope Target & Domain Boundary',
    what: 'Captures and normalizes the target\'s primary apex domain (e.g. <code>example.com</code>) directly from your active browser tab or manual composer entry.',
    why: 'Every search operator (like <code>site:</code>, <code>inurl:</code>, and exclusions <code>-site:</code>) requires an accurate apex root. Scoping the domain ensures all queries stay strictly within your authorized engagement boundary without accidental out-of-scope testing.',
    tip: 'Use apex domains (e.g. <code>company.com</code>) rather than subdomains (e.g. <code>www.company.com</code>) so subsequent certificate and infrastructure discovery can uncover all sister assets.',
    actionLabel: 'Grab Active Tab',
    actionFn: () => useActiveTab()
  },
  2: {
    num: 2,
    title: 'Map Subdomains via Certificate Transparency',
    what: 'Passively queries public append-only TLS certificate logs (<code>crt.sh</code>) for all wildcard and Subject Alternative Name (SAN) records issued to the domain.',
    why: 'Organizations frequently deploy staging environments, internal tools, dev APIs, and VPN endpoints on subdomains (e.g. <code>jira.</code>, <code>vpn.</code>, <code>dev-api.</code>). Enumerating subdomains allows you to target them individually or subtract known production hosts (<code>-site:www...</code>) to force search engines to reveal hidden shadow assets.',
    tip: 'Select all known public subdomains (e.g. <code>www</code>, <code>blog</code>) and click "Append Selected as Exclusions" to strip standard pages out of your Google dork results.',
    actionLabel: 'Open CRT.SH Tab',
    actionFn: () => {
      switchTab('tab-crt');
      if (els.domain.value.trim() && !currentCrtHosts.length) fetchCrt();
    }
  },
  3: {
    num: 3,
    title: 'DNS Zone, Corporate Infrastructure & Shodan',
    what: 'Queries authoritative DNS records (NS, MX, TXT/SPF, DMARC) via Google/Cloudflare DoH, cross-references multi-SAN certificates and Regional Internet Registries (ARIN, RIPE, RDAP) for corporate netblocks, and checks Shodan for open ports and CVEs.',
    why: '<strong>Apex Domain Myopia</strong> and uninspected DNS records are major blind spots: DNS records reveal mail security gateways (OWA/Exchange), cloud providers, and SaaS tokens, while netblock discovery uncovers dedicated corporate datacenters and exposed management ports without active scanning.',
    tip: 'Review detected Cloud & SaaS vendors from TXT records to guide your dork templates in Step 5, and click "Check Ports" to inspect Shodan InternetDB.',
    actionLabel: 'Open DNS & Infrastructure',
    actionFn: () => {
      switchTab('tab-infra');
      if (els.domain.value.trim() && !currentRelatedDomains.length && !currentNetblocks.length && !currentDnsZone) fetchInfra();
    }
  },
  4: {
    num: 4,
    title: 'Email Discovery & Public Identity Profiling',
    what: 'Passively queries open PGP keyservers (<code>keyserver.ubuntu.com</code> / <code>pgp.surf.nl</code>) for cryptographic signatures associated with the target domain, and uses local-part pattern recognition to deduce the corporate email naming convention.',
    why: 'Real technical employees, sysadmins, and DevOps engineers register public PGP keys for Git commit signing and software distribution. Deducing the corporate email convention enables precision dorking for employee resumes, leaked spreadsheets, and configuration dumps containing staff addresses.',
    tip: 'For high-volume enterprise targets, public keyservers may experience database query limits or timeouts. Vantage automatically fails over to secondary keyservers to complete discovery.',
    actionLabel: 'Open Emails Tab',
    actionFn: () => {
      switchTab('tab-emails');
      if (els.domain.value.trim() && !currentDiscoveredEmails.length) fetchEmails();
    }
  },
  5: {
    num: 5,
    title: 'Targeted Dork Execution & Vulnerability Surface',
    what: 'Applies pre-tuned search operator templates targeting sensitive file leaks (<code>.env</code>, <code>wp-config.php</code>, SQL dumps), exposed cloud buckets (S3, Azure, GCP), and unprotected administrative portals.',
    why: 'Search engine crawlers index misconfigured web roots, backup archives (<code>.sql.bak</code>), and open cloud storage buckets. Combining specialized operators (like <code>filetype:env "DB_PASSWORD"</code> and <code>inurl:admin</code>) lets you identify severe data exposures passively without sending any offensive traffic to the target.',
    tip: 'Always check the "True Positive Indicator" on each template card to quickly distinguish benign error pages from actual credentials or keys.',
    actionLabel: 'Load High-Risk Template',
    actionFn: () => loadTemplate('t-env')
  },
  6: {
    num: 6,
    title: 'Audit Log Triage & Markdown Reporting',
    what: 'Logs verified exposures into the persistent Audit Log, classifies findings (<code>Investigating</code>, <code>Confirmed Leak</code>, <code>False Positive</code>, <code>Remediated</code>), and exports structured triage documentation formatted for Obsidian or security reports.',
    why: 'Reconnaissance without documentation is useless. Formal logging ensures false positives are eliminated, confirmed vulnerabilities are recorded with reproducible dork syntax and timestamps, and remediations are tracked to completion.',
    tip: 'Use the "Export Obsidian" button to generate a clean, tagged markdown note ready to drop into your vulnerability management vault.',
    actionLabel: 'Open Audit Log Tab',
    actionFn: () => switchTab('tab-audit')
  }
};

let currentMethodologyStep = 1;

function openMethodologyModal(stepNum) {
  const step = METHODOLOGY_STEPS[stepNum] || METHODOLOGY_STEPS[1];
  currentMethodologyStep = step.num;

  const modal = document.getElementById('methodology-modal');
  const stepNumEl = document.getElementById('m-modal-step-num');
  const titleEl = document.getElementById('m-modal-title');
  const whatEl = document.getElementById('m-modal-what');
  const whyEl = document.getElementById('m-modal-why');
  const tipEl = document.getElementById('m-modal-tip');
  const actionBtn = document.getElementById('btn-modal-step-action');
  const prevBtn = document.getElementById('btn-prev-step-help');
  const nextBtn = document.getElementById('btn-next-step-help');

  if (!modal) return;

  if (stepNumEl) stepNumEl.textContent = `Step ${step.num} of 6`;
  if (titleEl) titleEl.textContent = step.title;
  if (whatEl) whatEl.innerHTML = step.what;
  if (whyEl) whyEl.innerHTML = step.why;
  if (tipEl) tipEl.innerHTML = step.tip;
  if (actionBtn) {
    actionBtn.textContent = step.actionLabel || 'Execute Step';
    actionBtn.onclick = () => {
      closeMethodologyModal();
      if (typeof step.actionFn === 'function') step.actionFn();
    };
  }

  if (prevBtn) {
    prevBtn.disabled = step.num <= 1;
    prevBtn.onclick = () => {
      if (currentMethodologyStep > 1) openMethodologyModal(currentMethodologyStep - 1);
    };
  }

  if (nextBtn) {
    nextBtn.disabled = step.num >= 6;
    nextBtn.onclick = () => {
      if (currentMethodologyStep < 6) openMethodologyModal(currentMethodologyStep + 1);
    };
  }

  modal.style.display = 'flex';
}

function closeMethodologyModal() {
  const modal = document.getElementById('methodology-modal');
  if (modal) modal.style.display = 'none';
}

function switchTab(tabId) {
  document.querySelectorAll('.tab-btn').forEach(b => {
    if (b.dataset.target === tabId) b.classList.add('active');
    else b.classList.remove('active');
  });
  document.querySelectorAll('.tab-content').forEach(c => {
    if (c.id === tabId) c.classList.add('active');
    else c.classList.remove('active');
  });
  if (tabId === 'tab-audit') {
    if (!els.auditQuery.value) els.auditQuery.value = els.output.value;
  }
  if (tabId === 'tab-infra') {
    if (els.infraKeyword && !els.infraKeyword.value.trim() && els.domain.value.trim()) {
      els.infraKeyword.value = els.domain.value.trim();
    }
  }
  if (tabId === 'tab-graph') {
    setTimeout(() => {
      if (typeof updateGraph === 'function') {
        updateGraph();
      }
    }, 50);
  }
}

// Email Pattern Deducer & Quick Dork
function detectEmailPattern(emails) {
  if (!emails || emails.length === 0) {
    if (els.emailPatternBanner) els.emailPatternBanner.style.display = 'none';
    return;
  }

  const targetDomain = els.domain.value.trim() || 'target.com';
  const patternCounts = {};
  let totalWithNames = 0;

  emails.forEach(item => {
    const local = item.email.split('@')[0].toLowerCase();
    const fullName = item.name ? item.name.toLowerCase().trim() : '';

    if (fullName) {
      const words = fullName.replace(/[^a-z\s]/g, ' ').trim().split(/\s+/).filter(w => w.length > 1);
      if (words.length >= 2) {
        totalWithNames++;
        const first = words[0];
        const last = words[words.length - 1];
        const f = first[0];

        if (local === `${first}.${last}`) {
          patternCounts['{first}.{last}'] = (patternCounts['{first}.{last}'] || 0) + 1;
        } else if (local === `${f}.${last}`) {
          patternCounts['{f}.{last}'] = (patternCounts['{f}.{last}'] || 0) + 1;
        } else if (local === `${f}${last}`) {
          patternCounts['{f}{last}'] = (patternCounts['{f}{last}'] || 0) + 1;
        } else if (local === `${first}_${last}`) {
          patternCounts['{first}_{last}'] = (patternCounts['{first}_{last}'] || 0) + 1;
        } else if (local === `${first}${last}`) {
          patternCounts['{first}{last}'] = (patternCounts['{first}{last}'] || 0) + 1;
        } else if (local === `${last}.${first}`) {
          patternCounts['{last}.{first}'] = (patternCounts['{last}.{first}'] || 0) + 1;
        } else if (local === first) {
          patternCounts['{first}'] = (patternCounts['{first}'] || 0) + 1;
        }
      }
    }

    // Fallback delimiter analysis if no name or unparsed
    if (local.includes('.')) {
      patternCounts['{first}.{last}'] = (patternCounts['{first}.{last}'] || 0) + 0.5;
    } else if (local.includes('_')) {
      patternCounts['{first}_{last}'] = (patternCounts['{first}_{last}'] || 0) + 0.5;
    }
  });

  const entries = Object.entries(patternCounts).sort((a, b) => b[1] - a[1]);
  if (entries.length > 0 && entries[0][1] >= 1.5) {
    const bestPattern = entries[0][0];
    const score = Math.round(entries[0][1]);
    const confidence = Math.min(98, Math.max(50, Math.round((entries[0][1] / (totalWithNames || emails.length)) * 100)));

    if (els.emailPatternBanner && els.patternScheme) {
      els.patternScheme.textContent = `${bestPattern}@${targetDomain}`;
      els.patternConfidence.textContent = `(~${confidence}% confidence based on ${score} matches)`;
      els.emailPatternBanner.style.display = 'flex';
    }
  } else {
    if (els.emailPatternBanner) els.emailPatternBanner.style.display = 'none';
  }
}

function loadEmailPatternDork() {
  const targetDomain = els.domain.value.trim();
  els.filetype.value = 'xlsx, csv, pdf';
  els.inurl.value = 'contact, staff, team, directory, about';
  els.exact.value = targetDomain ? `@${targetDomain}` : 'email, contact';
  els.intitle.value = 'staff, directory, email';
  els.exclude.value = '';
  updateQuery();
  showToast('Loaded email exposure dork into composer!');
  const composer = document.querySelector('.composer');
  if (composer) {
    composer.classList.add('highlight');
    setTimeout(() => composer.classList.remove('highlight'), 1200);
  }
}

document.addEventListener('DOMContentLoaded', init);

// ==========================================
// Visual Link Analysis (Node Graphing)
// ==========================================
let cyGraph = null;

function runLayout(isInitial = false) {
  if (!cyGraph) return;
  cyGraph.layout({
      name: 'cose',
      idealEdgeLength: 60,
      nodeOverlap: 10,
      refresh: 20,
      fit: true,
      padding: 30,
      randomize: isInitial,
      componentSpacing: 50,
      nodeRepulsion: 80000,
      edgeElasticity: 100,
      nestingFactor: 1.2,
      gravity: 100
  }).run();
}

function initGraph() {
  const container = document.getElementById('cy');
  if (!container) return;

  if (cyGraph) {
    cyGraph.destroy();
  }

  cyGraph = cytoscape({
    container: container,
    elements: [],
    style: [
      {
        selector: 'node',
        style: {
          'background-color': '#3b82f6',
          'label': 'data(id)',
          'color': '#f8fafc',
          'text-valign': 'center',
          'text-halign': 'right',
          'text-margin-x': 6,
          'font-size': '10px',
          'text-outline-color': '#0f172a',
          'text-outline-width': 2,
          'width': 14,
          'height': 14,
          'shape': 'ellipse',
          'transition-property': 'opacity, background-color',
          'transition-duration': '0.2s',
          'min-zoomed-font-size': 7
        }
      },
      {
        selector: 'edge',
        style: {
          'width': 1,
          'line-color': '#334155',
          'curve-style': 'haystack',
          'haystack-radius': 0,
          'opacity': 0.4,
          'transition-property': 'opacity, line-color, width',
          'transition-duration': '0.2s'
        }
      },
      {
        selector: '.root',
        style: {
          'background-color': '#fbbf24',
          'color': '#fbbf24',
          'text-outline-width': 2,
          'font-weight': 'bold',
          'font-size': '14px',
          'width': 28,
          'height': 28,
          'shape': 'hexagon'
        }
      },
      {
        selector: '.category',
        style: {
          'color': '#f8fafc',
          'label': 'data(label)',
          'shape': 'round-rectangle',
          'width': 'label',
          'height': 'label',
          'padding': '8px',
          'font-size': '11px',
          'text-valign': 'center',
          'text-halign': 'center',
          'text-margin-x': 0,
          'border-width': 2,
          'cursor': 'pointer'
        }
      },
      { selector: 'node[id="cat-sub"]', style: { 'background-color': '#064e3b', 'border-color': '#10b981' } },
      { selector: 'node[id="cat-a"]', style: { 'background-color': '#7f1d1d', 'border-color': '#ef4444' } },
      { selector: 'node[id="cat-mx"]', style: { 'background-color': '#4c1d95', 'border-color': '#8b5cf6' } },
      { selector: 'node[id="cat-ns"]', style: { 'background-color': '#831843', 'border-color': '#ec4899' } },
      { selector: 'node[id="cat-rel"]', style: { 'background-color': '#164e63', 'border-color': '#0ea5e9' } },
      { selector: 'node[id="cat-net"]', style: { 'background-color': '#450a0a', 'border-color': '#f87171' } },

      { selector: '.subdomain', style: { 'background-color': '#10b981' } },
      { selector: '.ip', style: { 'background-color': '#ef4444', 'width': 20, 'height': 20, 'shape': 'diamond' } },
      { selector: '.mx', style: { 'background-color': '#8b5cf6', 'shape': 'triangle' } },
      { selector: '.ns', style: { 'background-color': '#ec4899', 'shape': 'triangle' } },
      { selector: '.sibling', style: { 'background-color': '#0ea5e9' } },

      {
        selector: '.dimmed',
        style: {
          'opacity': 0.1
        }
      },
      {
        selector: '.highlighted-edge',
        style: {
          'opacity': 0.9,
          'line-color': '#fbbf24',
          'width': 2,
          'z-index': 10
        }
      }
    ],
    layout: { name: 'preset' } // Dummy initial layout
  });

  // Expand / Collapse Category Hubs
  cyGraph.on('tap', 'node.category', function(evt){
    const node = evt.target;
    const isCollapsed = node.data('collapsed');
    const childNodes = node.outgoers('node');
    const childEdges = node.outgoers('edge');

    if (isCollapsed) {
      node.data('collapsed', false);
      node.data('label', `${node.data('baseLabel')} (${node.data('count')}) [-]`);
      childNodes.style('display', 'element');
      childEdges.style('display', 'element');
    } else {
      node.data('collapsed', true);
      node.data('label', `${node.data('baseLabel')} (${node.data('count')}) [+]`);
      childNodes.style('display', 'none');
      childEdges.style('display', 'none');
    }
    runLayout(false);
  });

  // Enable node double click to copy
  cyGraph.on('dblclick', 'node', function(evt){
    const node = evt.target;
    if (!node.hasClass('category') && !node.hasClass('root')) {
      navigator.clipboard.writeText(node.id());
      showToast(`Copied to clipboard: ${node.id()}`);
    }
  });

  // Hover effect to highlight neighborhood
  cyGraph.on('mouseover', 'node', function(evt){
    const node = evt.target;
    const neighborhood = node.neighborhood().add(node);
    
    cyGraph.elements().addClass('dimmed');
    neighborhood.removeClass('dimmed');
    node.connectedEdges().addClass('highlighted-edge');
  });

  cyGraph.on('mouseout', 'node', function(evt){
    cyGraph.elements().removeClass('dimmed');
    cyGraph.edges().removeClass('highlighted-edge');
  });
}

function updateGraph() {
  if (!document.getElementById('cy')) return;
  if (!cyGraph) initGraph();
  if (!cyGraph) return;

  const rootDomain = els.domain.value.trim();
  if (!rootDomain) return;

  const elements = [];
  elements.push({ data: { id: rootDomain }, classes: 'root' });

  // Gather Data
  const subdomains = Array.isArray(currentCrtHosts) ? currentCrtHosts.filter(h => h !== rootDomain) : [];
  const aRecords = currentDnsZone && currentDnsZone.a ? currentDnsZone.a : [];
  const aaaaRecords = currentDnsZone && currentDnsZone.aaaa ? currentDnsZone.aaaa : [];
  const apexHosts = [...aRecords, ...aaaaRecords];
  const mxRecords = currentDnsZone && currentDnsZone.mx ? currentDnsZone.mx.map(m => m.host) : [];
  const nsRecords = currentDnsZone && currentDnsZone.ns ? currentDnsZone.ns.map(n => n.host) : [];
  const siblings = Array.isArray(currentRelatedDomains) ? currentRelatedDomains.filter(rd => rd.domain !== rootDomain).map(rd => rd.domain) : [];
  const netblocks = Array.isArray(currentNetblocks) ? currentNetblocks.map(nb => nb.cidr) : [];

  function addCategory(catId, label, items, nodeClass) {
    if (!items || items.length === 0) return;
    
    // De-duplicate items just in case
    const uniqueItems = [...new Set(items)];
    const maxItems = 50;
    const isCapped = uniqueItems.length > maxItems;
    const displayItems = uniqueItems.slice(0, maxItems);
    
    const countStr = isCapped ? `${maxItems} of ${uniqueItems.length}` : uniqueItems.length;

    elements.push({ 
      data: { 
        id: catId, 
        baseLabel: label, 
        count: countStr, 
        label: `${label} (${countStr}) [+]`,
        collapsed: true 
      }, 
      classes: 'category' 
    });
    elements.push({ data: { id: `edge-root-${catId}`, source: rootDomain, target: catId } });

    displayItems.forEach(item => {
      // Because a host might be an MX and a Subdomain, we prefix IDs to keep them bound to the hub physically
      const childId = `${catId}-${item}`;
      elements.push({ 
        data: { id: childId, label: item }, 
        classes: `child-node ${nodeClass}`
      });
      elements.push({ 
        data: { id: `edge-${childId}`, source: catId, target: childId },
        classes: 'child-edge'
      });
    });
  }

  addCategory('cat-sub', 'Subdomains', subdomains, 'subdomain');
  addCategory('cat-a', 'Apex Hosts', apexHosts, 'ip');
  addCategory('cat-mx', 'Mail Servers', mxRecords, 'mx');
  addCategory('cat-ns', 'Nameservers', nsRecords, 'ns');
  addCategory('cat-rel', 'Corporate Siblings', siblings, 'sibling');
  addCategory('cat-net', 'Netblocks', netblocks, 'ip');

  cyGraph.elements().remove();
  
  try {
    cyGraph.add(elements);
    // Set initial display to none for all children so they are collapsed by default
    cyGraph.nodes('.child-node').style('display', 'none');
    cyGraph.edges('.child-edge').style('display', 'none');
  } catch (e) {
    console.warn('Graph add error', e);
  }
  
  runLayout(true);
}

document.addEventListener('DOMContentLoaded', () => {
    const btnRefresh = document.getElementById('btn-refresh-graph');
    if(btnRefresh) btnRefresh.addEventListener('click', updateGraph);
    
    const btnClear = document.getElementById('btn-clear-graph');
    if(btnClear) btnClear.addEventListener('click', () => {
        if(cyGraph) {
          cyGraph.elements().remove();
          cyGraph.add({ data: { id: els.domain.value.trim() || 'Target' }, classes: 'root' });
        }
    });
});
