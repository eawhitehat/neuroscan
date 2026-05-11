/* ═══════════════════════════════════════════
   NEUROSCAN — Neural Graph Visualization
   D3.js force-directed graph + animations
   ═══════════════════════════════════════════ */

class NeuralGraph {
  constructor(containerId) {
    this.container = document.getElementById(containerId);
    this.svg = d3.select(`#${containerId} svg`);
    this.nodes = [];
    this.links = [];
    this.simulation = null;
    this.width = 0;
    this.height = 0;
    this.g = null;
    this.zoom = null;
  }

  init() {
    const rect = this.container.getBoundingClientRect();
    this.width = rect.width || 800;
    this.height = rect.height || 600;

    this.svg.attr('viewBox', `0 0 ${this.width} ${this.height}`);

    // Zoom behavior
    this.zoom = d3.zoom()
      .scaleExtent([0.3, 3])
      .on('zoom', (e) => this.g.attr('transform', e.transform));
    this.svg.call(this.zoom);

    // Main group
    this.g = this.svg.append('g');

    // Defs for glow filters
    const defs = this.svg.append('defs');
    this._createGlowFilter(defs, 'glow-safe', '0, 255, 136');
    this._createGlowFilter(defs, 'glow-info', '0, 212, 255');
    this._createGlowFilter(defs, 'glow-medium', '255, 208, 0');
    this._createGlowFilter(defs, 'glow-high', '255, 107, 0');
    this._createGlowFilter(defs, 'glow-critical', '255, 0, 64');

    // Gradient for links
    const grad = defs.append('linearGradient').attr('id', 'link-gradient');
    grad.append('stop').attr('offset', '0%').attr('stop-color', '#00ff88').attr('stop-opacity', 0.3);
    grad.append('stop').attr('offset', '100%').attr('stop-color', '#00d4ff').attr('stop-opacity', 0.1);
  }

  _createGlowFilter(defs, id, rgb) {
    const filter = defs.append('filter').attr('id', id).attr('x', '-50%').attr('y', '-50%').attr('width', '200%').attr('height', '200%');
    filter.append('feGaussianBlur').attr('stdDeviation', '4').attr('result', 'blur');
    filter.append('feFlood').attr('flood-color', `rgb(${rgb})`).attr('flood-opacity', '0.6').attr('result', 'color');
    filter.append('feComposite').attr('in', 'color').attr('in2', 'blur').attr('operator', 'in').attr('result', 'glow');
    const merge = filter.append('feMerge');
    merge.append('feMergeNode').attr('in', 'glow');
    merge.append('feMergeNode').attr('in', 'SourceGraphic');
  }

  async build(functions) {
    const riskColors = {
      critical: '#ff0040', high: '#ff6b00', medium: '#ffd000',
      low: '#00d4ff', safe: '#00ff88', info: '#00d4ff'
    };
    const riskRadius = {
      critical: 20, high: 16, medium: 14, low: 12, safe: 10, info: 10
    };
    const riskGlow = {
      critical: 'url(#glow-critical)', high: 'url(#glow-high)',
      medium: 'url(#glow-medium)', low: 'url(#glow-info)',
      safe: 'url(#glow-safe)', info: 'url(#glow-info)'
    };

    // Build nodes
    this.nodes = functions.map((fn, i) => ({
      id: fn.name, index: i,
      risk: fn.risk || 'info',
      color: riskColors[fn.risk] || riskColors.info,
      radius: riskRadius[fn.risk] || 10,
      glow: riskGlow[fn.risk] || riskGlow.info,
      visibility: fn.visibility,
      mutability: fn.mutability,
      params: fn.params,
      line: fn.line,
      x: this.width / 2 + (Math.random() - 0.5) * 200,
      y: this.height / 2 + (Math.random() - 0.5) * 200,
    }));

    // Build links
    this.links = [];
    for (const fn of functions) {
      for (const conn of fn.connections) {
        const source = this.nodes.find(n => n.id === fn.name);
        const target = this.nodes.find(n => n.id === conn);
        if (source && target) {
          this.links.push({ source, target });
        }
      }
    }

    // Force simulation
    this.simulation = d3.forceSimulation(this.nodes)
      .force('link', d3.forceLink(this.links).id(d => d.id).distance(120).strength(0.4))
      .force('charge', d3.forceManyBody().strength(-350))
      .force('center', d3.forceCenter(this.width / 2, this.height / 2))
      .force('collision', d3.forceCollide().radius(d => d.radius + 20))
      .force('x', d3.forceX(this.width / 2).strength(0.05))
      .force('y', d3.forceY(this.height / 2).strength(0.05));

    // Draw links
    const linkGroup = this.g.append('g').attr('class', 'links');
    const linkEls = linkGroup.selectAll('line')
      .data(this.links).enter().append('line')
      .attr('class', 'link-line link-animated')
      .attr('stroke', 'url(#link-gradient)')
      .attr('stroke-width', 1.5);

    // Draw nodes with staggered animation
    const nodeGroup = this.g.append('g').attr('class', 'nodes');
    const nodeEls = nodeGroup.selectAll('g')
      .data(this.nodes).enter().append('g')
      .attr('class', 'node-group')
      .style('opacity', 0);

    // Outer glow ring
    nodeEls.append('circle')
      .attr('class', 'node-glow')
      .attr('r', d => d.radius + 6)
      .attr('fill', 'none')
      .attr('stroke', d => d.color)
      .attr('stroke-width', 1)
      .attr('stroke-opacity', 0.2);

    // Main circle
    nodeEls.append('circle')
      .attr('class', 'node-circle')
      .attr('r', d => d.radius)
      .attr('fill', d => d.color + '25')
      .attr('stroke', d => d.color)
      .attr('stroke-width', 2)
      .attr('filter', d => d.glow);

    // Inner dot
    nodeEls.append('circle')
      .attr('r', 3)
      .attr('fill', d => d.color);

    // Label
    nodeEls.append('text')
      .attr('class', 'node-label')
      .attr('dy', d => d.radius + 16)
      .text(d => d.id.length > 14 ? d.id.slice(0, 12) + '..' : d.id);

    // Staggered appear animation
    for (let i = 0; i < this.nodes.length; i++) {
      await new Promise(r => setTimeout(r, 80));
      d3.select(nodeEls.nodes()[i])
        .transition().duration(400)
        .style('opacity', 1);
    }

    // Drag behavior
    const drag = d3.drag()
      .on('start', (e, d) => { if (!e.active) this.simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
      .on('drag', (e, d) => { d.fx = e.x; d.fy = e.y; })
      .on('end', (e, d) => { if (!e.active) this.simulation.alphaTarget(0); d.fx = null; d.fy = null; });
    nodeEls.call(drag);

    // Tick
    this.simulation.on('tick', () => {
      linkEls.attr('x1', d => d.source.x).attr('y1', d => d.source.y)
             .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
      nodeEls.attr('transform', d => `translate(${d.x},${d.y})`);
    });

    // Pulse animation for critical nodes
    this._startPulseAnimation(nodeEls);

    // Hover & click handlers
    this._setupInteractions(nodeEls);
  }

  _startPulseAnimation(nodeEls) {
    const pulse = () => {
      nodeEls.filter(d => d.risk === 'critical' || d.risk === 'high')
        .select('.node-glow')
        .transition().duration(1200)
        .attr('stroke-opacity', 0.6)
        .attr('r', d => d.radius + 12)
        .transition().duration(1200)
        .attr('stroke-opacity', 0.15)
        .attr('r', d => d.radius + 6)
        .on('end', pulse);
    };
    pulse();
  }

  _setupInteractions(nodeEls) {
    const tooltip = document.getElementById('nodeTooltip');

    nodeEls.on('mouseenter', (e, d) => {
      const sevLabel = { critical: '🔴 CRITICAL', high: '🟠 HIGH', medium: '🟡 MEDIUM', low: '🔵 LOW', safe: '🟢 SAFE', info: '⚪ VIEW/PURE' };
      tooltip.innerHTML = `
        <div class="tt-name">${d.id}(${d.params || ''})</div>
        <div class="tt-vis">${d.visibility} ${d.mutability}</div>
        <div class="tt-risk" style="color:${d.color}">${sevLabel[d.risk] || d.risk}</div>
      `;
      tooltip.classList.remove('hidden');
      const rect = this.container.getBoundingClientRect();
      tooltip.style.left = (e.clientX - rect.left + 15) + 'px';
      tooltip.style.top = (e.clientY - rect.top - 10) + 'px';

      // Highlight connected
      d3.selectAll('.link-line')
        .attr('stroke-opacity', l => (l.source.id === d.id || l.target.id === d.id) ? 0.8 : 0.05)
        .attr('stroke-width', l => (l.source.id === d.id || l.target.id === d.id) ? 3 : 1);
    })
    .on('mouseleave', () => {
      tooltip.classList.add('hidden');
      d3.selectAll('.link-line').attr('stroke-opacity', 0.3).attr('stroke-width', 1.5);
    })
    .on('click', (e, d) => {
      const panel = document.getElementById('detailPanel');
      document.getElementById('detailTitle').textContent = `${d.id}()`;
      document.getElementById('detailContent').innerHTML = `
        <p><strong>Visibility:</strong> <code>${d.visibility}</code> ${d.mutability ? `<code>${d.mutability}</code>` : ''}</p>
        <p><strong>Parameters:</strong> <code>${d.params || 'none'}</code></p>
        <p><strong>Risk Level:</strong> <span style="color:${d.color};font-weight:700">${d.risk.toUpperCase()}</span></p>
        <p><strong>Line:</strong> ${d.line || 'N/A'}</p>
        ${d.risk === 'critical' || d.risk === 'high' ? '<p style="color:#ff6b00;margin-top:8px">⚠️ This function contains security vulnerabilities. Review findings panel for details.</p>' : ''}
      `;
      panel.classList.remove('hidden');
    });
  }

  destroy() {
    if (this.simulation) this.simulation.stop();
    this.g?.selectAll('*').remove();
  }
}

/* ── Particle System ── */
class ParticleSystem {
  constructor(canvasId) {
    this.canvas = document.getElementById(canvasId);
    this.ctx = this.canvas.getContext('2d');
    this.particles = [];
    this.running = false;
    this.resize();
    window.addEventListener('resize', () => this.resize());
  }

  resize() {
    this.canvas.width = window.innerWidth;
    this.canvas.height = window.innerHeight;
  }

  start(count = 80) {
    this.particles = [];
    for (let i = 0; i < count; i++) {
      this.particles.push({
        x: Math.random() * this.canvas.width,
        y: Math.random() * this.canvas.height,
        vx: (Math.random() - 0.5) * 0.3,
        vy: (Math.random() - 0.5) * 0.3,
        r: Math.random() * 2 + 0.5,
        alpha: Math.random() * 0.4 + 0.1,
      });
    }
    this.running = true;
    this._animate();
  }

  _animate() {
    if (!this.running) return;
    this.ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);

    for (const p of this.particles) {
      p.x += p.vx; p.y += p.vy;
      if (p.x < 0) p.x = this.canvas.width;
      if (p.x > this.canvas.width) p.x = 0;
      if (p.y < 0) p.y = this.canvas.height;
      if (p.y > this.canvas.height) p.y = 0;

      this.ctx.beginPath();
      this.ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      this.ctx.fillStyle = `rgba(0, 255, 136, ${p.alpha})`;
      this.ctx.fill();
    }

    // Draw connections between nearby particles
    for (let i = 0; i < this.particles.length; i++) {
      for (let j = i + 1; j < this.particles.length; j++) {
        const a = this.particles[i], b = this.particles[j];
        const dx = a.x - b.x, dy = a.y - b.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 120) {
          this.ctx.beginPath();
          this.ctx.moveTo(a.x, a.y);
          this.ctx.lineTo(b.x, b.y);
          this.ctx.strokeStyle = `rgba(0, 255, 136, ${0.06 * (1 - dist / 120)})`;
          this.ctx.lineWidth = 0.5;
          this.ctx.stroke();
        }
      }
    }
    requestAnimationFrame(() => this._animate());
  }
}
