// Main UI Controller for SentinelGrid Public Cyber Defense Portal
(function (global) {
  const SG = global.SentinelGrid;
  const STORAGE_STATS = 'sg_stats_v1';
  const STORAGE_HISTORY = 'sg_history_v1';
  const STORAGE_FEED = 'sg_feed_v1';
  const STORAGE_AI = 'sg_ai_cfg_v1';

  let stats = loadJson(STORAGE_STATS, { totalScans: 0, threatsCaught: 0, bugsFound: 0 });
  let history = loadJson(STORAGE_HISTORY, []);
  let feed = loadJson(STORAGE_FEED, SG.DEFAULT_THREAT_FEED);
  let aiConfig = loadJson(STORAGE_AI, { provider: 'local', ollamaModel: 'llama3.2', geminiKey: '' });

  let lastSpamResult = null;
  let lastBugResult = null;
  let quizIndex = 0;
  let quizScore = 0;
  let quizAnswered = 0;

  function loadJson(key, fallback) {
    try {
      const raw = localStorage.getItem(key);
      return raw ? JSON.parse(raw) : structuredClone(fallback);
    } catch {
      return structuredClone(fallback);
    }
  }

  function saveJson(key, value) {
    try {
      localStorage.setItem(key, JSON.stringify(value));
    } catch {
      // ignore storage quota errors
    }
  }

  // Navigation
  function switchTab(tabId) {
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
    const panel = document.getElementById(`tab-${tabId}`);
    if (panel) panel.classList.add('active');
    const nav = document.querySelector(`.nav-btn[data-tab="${tabId}"]`);
    if (nav) nav.classList.add('active');
  }

  function renderTelemetry() {
    document.getElementById('statTotalScans').textContent = stats.totalScans;
    document.getElementById('statThreatsCaught').textContent = stats.threatsCaught;
    document.getElementById('statBugsFound').textContent = stats.bugsFound;
    document.getElementById('statCommunityReports').textContent = feed.length;

    const label = document.getElementById('aiModeLabel');
    if (aiConfig.provider === 'ollama') label.textContent = `Ollama: ${aiConfig.ollamaModel}`;
    else if (aiConfig.provider === 'gemini' && aiConfig.geminiKey) label.textContent = 'Gemini Copilot Ready';
    else label.textContent = 'Local AI Active';
  }

  function pushHistory(entry) {
    history.unshift({ ...entry, time: new Date().toLocaleTimeString() });
    history = history.slice(0, 12);
    saveJson(STORAGE_HISTORY, history);
    renderHistory();
  }

  function renderHistory() {
    const container = document.getElementById('historyList');
    if (!history.length) {
      container.innerHTML = '<p class="empty-state">No scans yet. Try a quick scan above or pick a sample scenario.</p>';
      return;
    }
    container.innerHTML = history
      .map(h => {
        const badgeCls = h.tone === 'danger' ? 'badge-danger' : h.tone === 'warn' ? 'badge-warn' : 'badge-safe';
        return `<div class="history-item">
          <div>
            <strong>${SG.escapeHtml(h.kind)}</strong> &mdash; <span class="muted">${SG.escapeHtml(h.preview)}</span>
          </div>
          <div style="display:flex;align-items:center;gap:10px;flex-shrink:0;">
            <span class="badge ${badgeCls}">${SG.escapeHtml(h.verdict)}</span>
            <span class="muted">${SG.escapeHtml(h.time)}</span>
          </div>
        </div>`;
      })
      .join('');
  }

  // Spam / Scam Analyzer
  function runSpamScan() {
    const text = document.getElementById('spamText').value.trim();
    const sender = document.getElementById('spamSender').value.trim();
    const channel = document.getElementById('spamChannel').value;

    if (!text) {
      alert('Please paste a message to analyze.');
      return;
    }

    const res = SG.analyzeSpamMessage({ text, sender, channel });
    lastSpamResult = { ...res, rawText: text, sender, channel };

    stats.totalScans += 1;
    if (res.riskScore >= 45) stats.threatsCaught += 1;
    saveJson(STORAGE_STATS, stats);
    renderTelemetry();

    pushHistory({
      kind: `Spam Scan (${channel.toUpperCase()})`,
      preview: res.redactedPreview.slice(0, 68) + (res.redactedPreview.length > 68 ? '...' : ''),
      verdict: `${res.riskScore}/100`,
      tone: res.verdictTone
    });

    document.getElementById('spamEmptyState').classList.add('hidden');
    document.getElementById('spamResults').classList.remove('hidden');
    document.getElementById('spamLiveAiBox').classList.add('hidden');

    const banner = document.getElementById('spamVerdictBanner');
    banner.className = `verdict-banner ${res.verdictTone}`;
    document.getElementById('spamCategoryLabel').textContent = `${channel.toUpperCase()} Message Assessment`;
    document.getElementById('spamVerdictTitle').textContent = res.verdict;
    document.getElementById('spamScoreNum').textContent = res.riskScore;
    document.getElementById('spamConfidence').textContent = `${res.confidence}%`;
    document.getElementById('spamScamType').textContent = res.scamType;
    document.getElementById('spamLinkCount').textContent = res.linkCount;
    document.getElementById('spamHighlightedText').innerHTML = res.highlightedHtml;

    const signalLabels = [
      ['Urgency & Fear', res.scores.urgency],
      ['Credential / OTP Theft', res.scores.credentials],
      ['Financial / Job Bait', res.scores.financial],
      ['Link / Domain Risk', res.scores.linkRisk],
      ['Impersonation', res.scores.impersonation],
      ['Obfuscation', res.scores.obfuscation]
    ];

    document.getElementById('spamSignalBars').innerHTML = signalLabels
      .map(([name, val]) => {
        const color = val >= 50 ? 'var(--red)' : val >= 20 ? 'var(--amber)' : 'var(--emerald)';
        return `<div class="signal-row">
          <span>${name}</span>
          <div class="bar-track"><div class="bar-fill" style="width:${val}%;background:${color};"></div></div>
          <strong>${val}%</strong>
        </div>`;
      })
      .join('');

    const findingsList = document.getElementById('spamFindingsList');
    if (!res.findings.length) {
      findingsList.innerHTML = '<li>No known scam triggers, spoofed links, or obfuscation characters detected.</li>';
    } else {
      findingsList.innerHTML = res.findings
        .map(f => `<li><strong>${SG.escapeHtml(f.title)}:</strong> ${SG.escapeHtml(f.detail)}</li>`)
        .join('');
    }

    document.getElementById('spamAdviceList').innerHTML = res.advice
      .map(tip => `<li>${SG.escapeHtml(tip)}</li>`)
      .join('');
  }

  // Bug & Link Scanner
  function runBugScan() {
    const input = document.getElementById('bugInput').value.trim();
    const requestedMode = document.getElementById('bugMode').value;
    if (!input) {
      alert('Please paste a code snippet, script, or URL to scan.');
      return;
    }

    const mode = SG.detectTargetMode(input, requestedMode);
    const res = mode === 'url' ? SG.inspectUrl(input) : SG.scanCodeBugs(input);
    lastBugResult = { ...res, rawInput: input };

    stats.totalScans += 1;
    stats.bugsFound += res.findings.length;
    if (res.riskScore >= 50) stats.threatsCaught += 1;
    saveJson(STORAGE_STATS, stats);
    renderTelemetry();

    pushHistory({
      kind: mode === 'url' ? 'URL Inspector' : 'Code Bug Scan',
      preview: input.split(/\r?\n/)[0].slice(0, 68),
      verdict: `Grade ${res.grade} (${res.findings.length})`,
      tone: res.verdictTone
    });

    document.getElementById('bugEmptyState').classList.add('hidden');
    document.getElementById('bugResults').classList.remove('hidden');
    document.getElementById('bugLiveAiBox').classList.add('hidden');

    const banner = document.getElementById('bugVerdictBanner');
    banner.className = `verdict-banner ${res.verdictTone}`;
    document.getElementById('bugTargetType').textContent = mode === 'url' ? 'URL & Payload Anatomy' : 'Static Code & Script Audit';
    document.getElementById('bugVerdictTitle').textContent = res.verdict;
    document.getElementById('bugGrade').textContent = res.grade;
    document.getElementById('bugCountSummary').textContent = `${res.findings.length} Issue${res.findings.length === 1 ? '' : 's'}`;

    const highCount = res.findings.filter(f => f.severity === 'Critical' || f.severity === 'High').length;
    const medCount = res.findings.length - highCount;
    document.getElementById('bugHighCount').textContent = highCount;
    document.getElementById('bugMedCount').textContent = medCount;
    document.getElementById('bugRiskScore').textContent = `${res.riskScore}/100`;

    const urlBox = document.getElementById('bugUrlBreakdownBox');
    if (mode === 'url' && res.urlParts) {
      urlBox.style.display = 'block';
      document.getElementById('bugUrlAnatomy').innerHTML = Object.entries(res.urlParts)
        .map(([k, v]) => `<div class="url-part"><span>${SG.escapeHtml(k)}</span><strong>${SG.escapeHtml(v)}</strong></div>`)
        .join('');
    } else {
      urlBox.style.display = 'none';
    }

    const container = document.getElementById('bugFindingsContainer');
    if (!res.findings.length) {
      container.innerHTML = '<div class="bug-item Low"><strong>All Clear:</strong> No static vulnerabilities, hardcoded secrets, obfuscated droppers, or URL traps matched our ruleset.</div>';
    } else {
      container.innerHTML = res.findings
        .map(f => {
          const badgeCls = f.severity === 'Critical' || f.severity === 'High' ? 'badge-danger' : f.severity === 'Medium' ? 'badge-warn' : 'badge-cyan';
          return `<div class="bug-item ${SG.escapeHtml(f.severity)}">
            <div class="bug-item-head">
              <strong>[${SG.escapeHtml(f.id)}] ${SG.escapeHtml(f.title)}</strong>
              <div>
                <span class="badge ${badgeCls}">${SG.escapeHtml(f.severity)}</span>
                <span class="muted">Line ${f.line}</span>
              </div>
            </div>
            <div class="bug-code-snippet">${SG.escapeHtml(f.snippet)}</div>
            <p class="muted" style="margin:6px 0;">${SG.escapeHtml(f.explanation)}</p>
            <div class="bug-fix"><strong>Secure Fix:</strong> ${SG.escapeHtml(f.fix)}</div>
          </div>`;
        })
        .join('');
    }
  }

  // Optional Live AI Copilot (Ollama / Gemini)
  async function runLiveAiExplain(targetBoxId, promptText) {
    const box = document.getElementById(targetBoxId);
    box.classList.remove('hidden');

    if (aiConfig.provider === 'local') {
      box.innerHTML = '<strong>AI Copilot Tip:</strong> Built-in Local AI analysis is already displayed above. To enable generative LLM explanations, click <em>"Local AI Active"</em> in the top bar and configure local Ollama or a Gemini API key.';
      return;
    }

    box.innerHTML = '<strong>Querying Live AI Copilot...</strong>';

    try {
      let answer = '';
      if (aiConfig.provider === 'ollama') {
        const resp = await fetch('http://localhost:11434/api/generate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            model: aiConfig.ollamaModel || 'llama3.2',
            prompt: promptText,
            stream: false
          })
        });
        if (!resp.ok) throw new Error(`Ollama HTTP ${resp.status}`);
        const data = await resp.json();
        answer = data.response || 'No response returned.';
      } else if (aiConfig.provider === 'gemini') {
        if (!aiConfig.geminiKey) throw new Error('Missing Gemini API key in AI Engine Settings.');
        const resp = await fetch(
          `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${encodeURIComponent(aiConfig.geminiKey)}`,
          {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              contents: [{ parts: [{ text: promptText }] }]
            })
          }
        );
        if (!resp.ok) throw new Error(`Gemini HTTP ${resp.status}`);
        const data = await resp.json();
        answer = data.candidates?.[0]?.content?.parts?.[0]?.text || 'No response returned.';
      }
      box.innerHTML = `<strong>Live AI Copilot Assessment:</strong><br><div style="margin-top:6px;white-space:pre-wrap;">${SG.escapeHtml(answer)}</div>`;
    } catch (err) {
      box.innerHTML = `<strong>Live AI Copilot Unavailable:</strong> ${SG.escapeHtml(err.message)}. Built-in Local AI findings above remain active.`;
    }
  }

  // Threat Feed
  function renderFeed() {
    const q = document.getElementById('feedSearch').value.trim().toLowerCase();
    const cat = document.getElementById('feedFilterCategory').value;
    const sev = document.getElementById('feedFilterSeverity').value;

    const filtered = feed.filter(item => {
      if (cat !== 'all' && item.category !== cat) return false;
      if (sev !== 'all' && item.severity !== sev) return false;
      if (q) {
        const hay = `${item.title} ${item.indicator} ${item.notes} ${item.category}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });

    const grid = document.getElementById('threatFeedGrid');
    if (!filtered.length) {
      grid.innerHTML = '<div class="card">No matching threat advisories found.</div>';
      return;
    }

    grid.innerHTML = filtered
      .map(item => {
        const sevCls = item.severity === 'Critical' || item.severity === 'High' ? 'badge-danger' : 'badge-warn';
        return `<article class="card feed-card">
          <div>
            <div class="feed-meta">
              <span class="badge badge-cyan">${SG.escapeHtml(item.category)}</span>
              <span class="badge ${sevCls}">${SG.escapeHtml(item.severity)}</span>
            </div>
            <h3 style="margin:10px 0 6px;font-size:1.05rem;">${SG.escapeHtml(item.title)}</h3>
            <div class="feed-sample">${SG.escapeHtml(item.indicator)}</div>
            <p class="muted" style="margin:8px 0 0;">${SG.escapeHtml(item.notes)}</p>
          </div>
          <div class="feed-footer">
            <span>Reported ${SG.escapeHtml(item.timestamp)}</span>
            <button class="chip" data-upvote="${SG.escapeHtml(item.id)}">&#9650; Confirm (${item.votes})</button>
          </div>
        </article>`;
      })
      .join('');
  }

  function addFeedReport({ category, severity, title, indicator, notes }) {
    const redactedIndicator = SG.redactPII(indicator);
    const entry = {
      id: `thr-${Date.now()}`,
      category,
      severity,
      title: title.trim(),
      indicator: redactedIndicator.slice(0, 260),
      notes: notes.trim() || 'Submitted via SentinelGrid public detector.',
      votes: 1,
      timestamp: 'Just now'
    };
    feed.unshift(entry);
    saveJson(STORAGE_FEED, feed);
    renderTelemetry();
    renderFeed();
  }

  // Prevention Quiz & Playbooks
  function renderQuiz() {
    const container = document.getElementById('quizContainer');
    document.getElementById('quizScoreBadge').textContent = `Score: ${quizScore} / ${quizAnswered}`;
    const q = SG.QUIZ_QUESTIONS[quizIndex % SG.QUIZ_QUESTIONS.length];

    container.innerHTML = `
      <div class="quiz-prompt">
        <div class="muted" style="margin-bottom:6px;">Scenario ${(quizIndex % SG.QUIZ_QUESTIONS.length) + 1} of ${SG.QUIZ_QUESTIONS.length}</div>
        <div>${SG.escapeHtml(q.prompt)}</div>
      </div>
      <div class="quiz-options">
        <button class="btn btn-danger btn-sm" id="quizPickScam">Scam / Malicious</button>
        <button class="btn btn-secondary btn-sm" id="quizPickSafe">Legitimate / Safe</button>
      </div>
      <div id="quizFeedbackArea"></div>
    `;

    const handlePick = choice => {
      const correct = choice === q.answer;
      quizAnswered += 1;
      if (correct) quizScore += 1;
      document.getElementById('quizScoreBadge').textContent = `Score: ${quizScore} / ${quizAnswered}`;
      document.getElementById('quizPickScam').disabled = true;
      document.getElementById('quizPickSafe').disabled = true;

      document.getElementById('quizFeedbackArea').innerHTML = `
        <div class="quiz-feedback ${correct ? 'correct' : 'wrong'}">
          <strong>${correct ? 'Correct!' : 'Watch out!'}</strong> ${SG.escapeHtml(q.explanation)}
        </div>
        <button class="btn btn-primary btn-sm" id="quizNextBtn">Next Scenario &rarr;</button>
      `;
      document.getElementById('quizNextBtn').addEventListener('click', () => {
        quizIndex += 1;
        renderQuiz();
      });
    };

    document.getElementById('quizPickScam').addEventListener('click', () => handlePick('scam'));
    document.getElementById('quizPickSafe').addEventListener('click', () => handlePick('safe'));
  }

  function renderPlaybook(key) {
    const items = SG.PLAYBOOKS[key] || SG.PLAYBOOKS.clicked;
    document.getElementById('playbookContent').innerHTML = items
      .map(step => `<label><input type="checkbox" /> <span>${SG.escapeHtml(step)}</span></label>`)
      .join('');
  }

  function downloadJson(filename, data) {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }

  // Modal helpers
  function openModal(id) {
    document.getElementById(id).classList.remove('hidden');
  }
  function closeModal(id) {
    document.getElementById(id).classList.add('hidden');
  }

  // Init bindings
  document.addEventListener('DOMContentLoaded', () => {
    renderTelemetry();
    renderHistory();
    renderFeed();
    renderQuiz();
    renderPlaybook('clicked');

    // Tab navigation & jump buttons
    document.querySelectorAll('[data-tab]').forEach(btn => {
      btn.addEventListener('click', () => switchTab(btn.dataset.tab));
    });
    document.querySelectorAll('[data-jump]').forEach(btn => {
      btn.addEventListener('click', () => switchTab(btn.dataset.jump));
    });
    document.querySelector('.brand').addEventListener('click', e => {
      e.preventDefault();
      switchTab('overview');
    });

    // Quick triage presets & auto-routing
    document.querySelectorAll('[data-quick-preset]').forEach(btn => {
      btn.addEventListener('click', () => {
        const p = btn.dataset.quickPreset;
        const qi = document.getElementById('quickInput');
        if (p === 'sms') qi.value = SG.SPAM_SAMPLES.kyc.text;
        if (p === 'url') qi.value = SG.BUG_SAMPLES.phishurl;
        if (p === 'code') qi.value = SG.BUG_SAMPLES.sqli;
      });
    });

    document.getElementById('quickAnalyzeBtn').addEventListener('click', () => {
      const val = document.getElementById('quickInput').value.trim();
      if (!val) {
        alert('Paste a suspicious message, URL, or code snippet first.');
        return;
      }
      const isSingleUrl = val.split(/\r?\n/).length === 1 && /^(?:https?:\/\/|www\.)\S+$/i.test(val);
      const looksLikeCode = /(function\s|const\s|let\s|import\s|SELECT\s|<script|eval\(|subprocess\.|def\s|=>)/i.test(val);

      if (isSingleUrl || looksLikeCode) {
        document.getElementById('bugInput').value = val;
        document.getElementById('bugMode').value = 'auto';
        switchTab('bugs');
        runBugScan();
      } else {
        document.getElementById('spamText').value = val;
        switchTab('spam');
        runSpamScan();
      }
    });

    document.getElementById('clearHistoryBtn').addEventListener('click', () => {
      history = [];
      saveJson(STORAGE_HISTORY, history);
      renderHistory();
    });

    // Spam detector controls
    document.querySelectorAll('[data-spam-sample]').forEach(btn => {
      btn.addEventListener('click', () => {
        const s = SG.SPAM_SAMPLES[btn.dataset.spamSample];
        if (!s) return;
        document.getElementById('spamChannel').value = s.channel;
        document.getElementById('spamSender').value = s.sender;
        document.getElementById('spamText').value = s.text;
        runSpamScan();
      });
    });
    document.getElementById('analyzeSpamBtn').addEventListener('click', runSpamScan);
    document.getElementById('clearSpamBtn').addEventListener('click', () => {
      document.getElementById('spamText').value = '';
      document.getElementById('spamSender').value = '';
      document.getElementById('spamResults').classList.add('hidden');
      document.getElementById('spamEmptyState').classList.remove('hidden');
    });
    document.getElementById('spamToAiBtn').addEventListener('click', () => {
      const msg = document.getElementById('spamText').value.trim();
      if (!msg) return alert('Paste a message first.');
      runLiveAiExplain(
        'spamLiveAiBox',
        `Analyze this message for cyber fraud, spam, or social engineering and give concise citizen safety advice:\n\n${SG.redactPII(msg)}`
      );
    });
    document.getElementById('reportSpamPublicBtn').addEventListener('click', () => {
      if (!lastSpamResult) return;
      addFeedReport({
        category: lastSpamResult.riskScore >= 60 ? 'Phishing' : 'SMS Smishing',
        severity: lastSpamResult.riskScore >= 70 ? 'Critical' : 'High',
        title: `${lastSpamResult.scamType} (${lastSpamResult.channel.toUpperCase()})`,
        indicator: lastSpamResult.redactedPreview,
        notes: `Risk ${lastSpamResult.riskScore}/100. Triggers: ${lastSpamResult.findings.map(f => f.title).slice(0, 3).join(', ') || 'User reported'}`
      });
      switchTab('feed');
    });
    document.getElementById('exportSpamBtn').addEventListener('click', () => {
      if (!lastSpamResult) return;
      downloadJson('sentinelgrid-spam-report.json', {
        exportedAt: new Date().toISOString(),
        channel: lastSpamResult.channel,
        verdict: lastSpamResult.verdict,
        riskScore: lastSpamResult.riskScore,
        scamType: lastSpamResult.scamType,
        findings: lastSpamResult.findings,
        redactedMessage: lastSpamResult.redactedPreview
      });
    });

    // Bug & Link scanner controls
    document.querySelectorAll('[data-bug-sample]').forEach(btn => {
      btn.addEventListener('click', () => {
        const sample = SG.BUG_SAMPLES[btn.dataset.bugSample];
        if (!sample) return;
        document.getElementById('bugInput').value = sample;
        document.getElementById('bugMode').value = 'auto';
        runBugScan();
      });
    });
    document.getElementById('analyzeBugBtn').addEventListener('click', runBugScan);
    document.getElementById('clearBugBtn').addEventListener('click', () => {
      document.getElementById('bugInput').value = '';
      document.getElementById('bugResults').classList.add('hidden');
      document.getElementById('bugEmptyState').classList.remove('hidden');
    });
    document.getElementById('bugToAiBtn').addEventListener('click', () => {
      const code = document.getElementById('bugInput').value.trim();
      if (!code) return alert('Paste code or a URL first.');
      runLiveAiExplain(
        'bugLiveAiBox',
        `Review this snippet or URL for security vulnerabilities, software bugs, or malware indicators and explain how to fix it:\n\n${SG.redactPII(code)}`
      );
    });
    document.getElementById('reportBugPublicBtn').addEventListener('click', () => {
      if (!lastBugResult) return;
      addFeedReport({
        category: lastBugResult.mode === 'url' ? 'Malicious Link' : 'Code Bug / Malware',
        severity: lastBugResult.riskScore >= 70 ? 'Critical' : 'High',
        title: `${lastBugResult.verdict} (Grade ${lastBugResult.grade})`,
        indicator: lastBugResult.rawInput.split(/\r?\n/).slice(0, 2).join(' '),
        notes: `Findings: ${lastBugResult.findings.map(f => f.id).join(', ') || 'Reported suspicious artifact'}`
      });
      switchTab('feed');
    });
    document.getElementById('exportBugBtn').addEventListener('click', () => {
      if (!lastBugResult) return;
      downloadJson('sentinelgrid-bug-audit.json', {
        exportedAt: new Date().toISOString(),
        mode: lastBugResult.mode,
        grade: lastBugResult.grade,
        riskScore: lastBugResult.riskScore,
        verdict: lastBugResult.verdict,
        findings: lastBugResult.findings
      });
    });

    // Feed filtering & upvotes
    document.getElementById('feedSearch').addEventListener('input', renderFeed);
    document.getElementById('feedFilterCategory').addEventListener('change', renderFeed);
    document.getElementById('feedFilterSeverity').addEventListener('change', renderFeed);
    document.getElementById('threatFeedGrid').addEventListener('click', e => {
      const btn = e.target.closest('[data-upvote]');
      if (!btn) return;
      const item = feed.find(x => x.id === btn.dataset.upvote);
      if (item) {
        item.votes += 1;
        saveJson(STORAGE_FEED, feed);
        renderFeed();
      }
    });

    // Playbook switcher
    document.getElementById('playbookTabs').addEventListener('click', e => {
      const btn = e.target.closest('[data-playbook]');
      if (!btn) return;
      document.querySelectorAll('#playbookTabs .chip').forEach(c => c.classList.remove('active'));
      btn.classList.add('active');
      renderPlaybook(btn.dataset.playbook);
    });

    // Modals
    document.getElementById('openReportModalBtn').addEventListener('click', () => openModal('reportModal'));
    document.getElementById('aiConfigBtn').addEventListener('click', () => {
      document.getElementById('aiProvider').value = aiConfig.provider;
      document.getElementById('ollamaModel').value = aiConfig.ollamaModel || 'llama3.2';
      document.getElementById('geminiApiKey').value = aiConfig.geminiKey || '';
      toggleAiFields(aiConfig.provider);
      openModal('aiModal');
    });

    document.querySelectorAll('[data-close-modal]').forEach(el => {
      el.addEventListener('click', () => closeModal(el.dataset.closeModal));
    });

    document.getElementById('publicReportForm').addEventListener('submit', e => {
      e.preventDefault();
      addFeedReport({
        category: document.getElementById('repCategory').value,
        severity: document.getElementById('repSeverity').value,
        title: document.getElementById('repTitle').value,
        indicator: document.getElementById('repIndicator').value,
        notes: document.getElementById('repNotes').value
      });
      e.target.reset();
      closeModal('reportModal');
    });

    function toggleAiFields(provider) {
      document.getElementById('ollamaFields').style.display = provider === 'ollama' ? 'block' : 'none';
      document.getElementById('geminiFields').style.display = provider === 'gemini' ? 'block' : 'none';
    }
    document.getElementById('aiProvider').addEventListener('change', e => toggleAiFields(e.target.value));
    document.getElementById('aiConfigForm').addEventListener('submit', e => {
      e.preventDefault();
      aiConfig = {
        provider: document.getElementById('aiProvider').value,
        ollamaModel: document.getElementById('ollamaModel').value.trim() || 'llama3.2',
        geminiKey: document.getElementById('geminiApiKey').value.trim()
      };
      // Keep API key only in memory/session if desired, store non-sensitive settings
      saveJson(STORAGE_AI, { ...aiConfig, geminiKey: '' });
      renderTelemetry();
      closeModal('aiModal');
    });
  });
})(window);
