/* ═══════════════════════════════════════════
   NEUROSCAN — App Controller v2
   Orchestrates scan flow, UI transitions, gauge
   ═══════════════════════════════════════════ */

class NeuroScanApp {
  constructor() {
    this.graph = new NeuralGraph('graphContainer');
    this.particles = new ParticleSystem('particles');
    this.analyzer = new VulnerabilityAnalyzer();
    this.isScanning = false;
    this._bindEvents();
    this.particles.start(60);
  }

  _bindEvents() {
    document.getElementById('scanBtn').addEventListener('click', () => this._startScan());
    document.getElementById('demoBtn').addEventListener('click', () => this._startDemo());
    document.getElementById('detailClose').addEventListener('click', () => {
      document.getElementById('detailPanel').classList.add('hidden');
    });
    document.getElementById('contractAddress').addEventListener('keydown', (e) => {
      if (e.key === 'Enter') this._startScan();
    });
    // Close detail panel on Escape
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') document.getElementById('detailPanel').classList.add('hidden');
    });
  }

  async _startDemo() {
    if (this.isScanning) return;
    this._resetUI();
    const { source, abi, name } = DEMO_CONTRACT;
    await this._runAnalysis(source, abi, name, '0xDEMO...VULNERABLE');
  }

  async _startScan() {
    if (this.isScanning) return;
    const address = document.getElementById('contractAddress').value.trim();
    if (!address || !address.startsWith('0x') || address.length !== 42) {
      this._addStatus('❌ Invalid address format. Must be 0x... (42 chars)', 'error');
      return;
    }
    this._resetUI();
    const chain = document.getElementById('chainSelect').value;
    const fetcher = new ContractFetcher(chain);

    try {
      this._addStatus(`Connecting to ${CHAINS[chain].name} explorer...`);
      await this._delay(400);

      this._addStatus('Fetching contract ABI...');
      const abi = await fetcher.fetchABI(address);
      this._addStatus(`✓ ABI loaded — ${abi.filter(a => a.type === 'function').length} functions`);
      await this._delay(300);

      this._addStatus('Downloading verified source code...');
      const { source, name } = await fetcher.fetchSource(address);
      this._addStatus(`✓ Source verified — ${name}`);
      await this._delay(300);

      await this._runAnalysis(source, abi, name, address);
    } catch (err) {
      this._addStatus(`❌ ${err.message}`, 'error');
      this._addStatus('Tip: Contract must be verified on the block explorer.', 'error');
      this.isScanning = false;
    }
  }

  async _runAnalysis(source, abi, contractName, address) {
    this.isScanning = true;

    // Transition layout: landing → scanning
    const mainEl = document.querySelector('main');
    const scanLine = document.getElementById('scanLine');
    const inputPanel = document.getElementById('inputPanel');

    mainEl.classList.remove('landing');
    mainEl.classList.add('scanning');
    inputPanel.classList.add('compact');
    scanLine.classList.remove('hidden');

    this._addStatus('Initializing neural scan engine...');
    await this._delay(500);

    this._addStatus('Parsing function signatures...');
    await this._delay(300);

    // Run analysis
    this._addStatus('Running vulnerability detectors...');
    const { functions, findings } = this.analyzer.analyze(source, abi);
    await this._delay(400);

    this._addStatus(`✓ ${functions.length} functions analyzed`);
    this._addStatus(`✓ ${findings.length} findings detected`);
    await this._delay(300);

    // Show graph
    this._addStatus('Building neural map...');
    const graphContainer = document.getElementById('graphContainer');
    graphContainer.classList.remove('hidden');

    // Wait a frame for the container to get its size
    await this._delay(50);
    this.graph.init();
    await this.graph.build(functions);

    this._addStatus('✓ Neural map constructed');
    await this._delay(200);

    // Calculate risk
    const riskScore = this.analyzer.calculateRiskScore(findings);

    // Show risk panel
    this._addStatus('Calculating risk score...');
    await this._delay(300);
    this._showRiskPanel(riskScore, findings);
    this._addStatus(`✓ Risk Score: ${riskScore}/100`);

    // Show findings
    this._showFindings(findings);
    this._addStatus('━━━ Scan complete ━━━');

    // Stop scan line
    setTimeout(() => scanLine.classList.add('hidden'), 3000);
    this.isScanning = false;
  }

  _showRiskPanel(score, findings) {
    const panel = document.getElementById('riskPanel');
    panel.classList.remove('hidden');

    // Animate gauge
    const arc = document.getElementById('gaugeArc');
    const circumference = 2 * Math.PI * 85;
    const offset = circumference - (score / 100) * circumference;

    let color;
    if (score >= 70) color = '#ff0040';
    else if (score >= 40) color = '#ff6b00';
    else if (score >= 20) color = '#ffd000';
    else color = '#00ff88';

    // Update the score text color to match gauge
    const scoreEl = document.getElementById('riskScore');
    setTimeout(() => {
      arc.style.strokeDashoffset = offset;
      arc.style.stroke = color;
      scoreEl.style.color = color;
    }, 100);

    // Animate score counter
    this._animateCounter('riskScore', 0, score, 2000);

    // Risk level label
    const levelEl = document.getElementById('riskLevel');
    let level, levelClass;
    if (score >= 70) { level = '🔴 CRITICAL RISK'; levelClass = 'critical'; }
    else if (score >= 40) { level = '🟠 HIGH RISK'; levelClass = 'high'; }
    else if (score >= 20) { level = '🟡 MEDIUM RISK'; levelClass = 'medium'; }
    else { level = '🟢 LOW RISK'; levelClass = 'low'; }
    levelEl.textContent = level;
    levelEl.className = 'risk-level ' + levelClass;

    // Stats
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const f of findings) counts[f.severity]++;

    document.getElementById('riskStats').innerHTML = `
      <div class="risk-stat"><span><span class="risk-stat-dot" style="background:#ff0040"></span>Critical</span><span>${counts.critical}</span></div>
      <div class="risk-stat"><span><span class="risk-stat-dot" style="background:#ff6b00"></span>High</span><span>${counts.high}</span></div>
      <div class="risk-stat"><span><span class="risk-stat-dot" style="background:#ffd000"></span>Medium</span><span>${counts.medium}</span></div>
      <div class="risk-stat"><span><span class="risk-stat-dot" style="background:#00d4ff"></span>Low</span><span>${counts.low}</span></div>
    `;
  }

  _showFindings(findings) {
    const panel = document.getElementById('findingsPanel');
    const list = document.getElementById('findingsList');
    const count = document.getElementById('findingsCount');
    panel.classList.remove('hidden');
    count.textContent = findings.length;

    // Sort: critical first
    const order = { critical: 0, high: 1, medium: 2, low: 3 };
    findings.sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9));

    list.innerHTML = findings.map(f => `
      <div class="finding-card ${f.severity}" data-fn="${f.function}" data-title="${f.title}">
        <span class="finding-severity ${f.severity}">${f.severity.toUpperCase()}</span>
        <div class="finding-title">${f.title}</div>
        <div class="finding-func">${f.function}() — Line ${f.line || 'N/A'}</div>
      </div>
    `).join('');

    // Click to show detail
    list.querySelectorAll('.finding-card').forEach(card => {
      card.addEventListener('click', () => {
        const fnName = card.dataset.fn;
        const title = card.dataset.title;
        const finding = findings.find(f => f.function === fnName && f.title === title);
        if (finding) this._showFindingDetail(finding);
      });
    });
  }

  _showFindingDetail(finding) {
    const panel = document.getElementById('detailPanel');
    const sevColors = { critical: '#ff0040', high: '#ff6b00', medium: '#ffd000', low: '#00d4ff' };
    document.getElementById('detailTitle').textContent = finding.title;
    document.getElementById('detailContent').innerHTML = `
      <p><strong>Severity:</strong> <span style="color:${sevColors[finding.severity] || '#fff'}">${finding.severity.toUpperCase()}</span></p>
      <p><strong>Function:</strong> <code>${finding.function}()</code></p>
      <p><strong>Line:</strong> ${finding.line || 'N/A'}</p>
      <p style="margin-top:12px">${finding.description}</p>
      <p style="margin-top:12px;color:#00ff88"><strong>💡 Recommendation:</strong> ${finding.recommendation}</p>
    `;
    panel.classList.remove('hidden');
  }

  _resetUI() {
    this.graph.destroy();
    const mainEl = document.querySelector('main');
    mainEl.classList.remove('scanning');
    mainEl.classList.add('landing');
    document.getElementById('inputPanel').classList.remove('compact');
    document.getElementById('graphContainer').classList.add('hidden');
    document.getElementById('riskPanel').classList.add('hidden');
    document.getElementById('findingsPanel').classList.add('hidden');
    document.getElementById('detailPanel').classList.add('hidden');
    document.getElementById('scanLine').classList.add('hidden');

    // Reset status
    const status = document.getElementById('scanStatus');
    status.innerHTML = '';
    status.classList.remove('hidden');

    // Reset gauge
    const arc = document.getElementById('gaugeArc');
    arc.style.strokeDashoffset = 534;
    arc.style.stroke = '#00ff88';
    const scoreEl = document.getElementById('riskScore');
    scoreEl.textContent = '0';
    scoreEl.style.color = '#00ff88';
  }

  _addStatus(text, type = 'info') {
    const container = document.getElementById('scanStatus');
    container.classList.remove('hidden');
    const line = document.createElement('div');
    line.className = 'status-line';
    if (type === 'error') line.style.color = '#ff0040';
    line.textContent = text;
    container.appendChild(line);
    container.scrollTop = container.scrollHeight;
  }

  _animateCounter(id, start, end, duration) {
    const el = document.getElementById(id);
    const range = end - start;
    const startTime = performance.now();
    const step = (now) => {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3); // ease-out cubic
      el.textContent = Math.round(start + range * eased);
      if (progress < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }

  _delay(ms) { return new Promise(r => setTimeout(r, ms)); }
}

// ── Launch ──
document.addEventListener('DOMContentLoaded', () => {
  window.app = new NeuroScanApp();
});
