/* ═══════════════════════════════════════════
   NEUROSCAN — Analysis Engine
   Contract fetching + Vulnerability detection
   ═══════════════════════════════════════════ */

const CHAINS = {
  eth:  { name: 'Ethereum', api: 'https://api.etherscan.io/api', key: 'YourApiKeyToken', explorer: 'https://etherscan.io' },
  bsc:  { name: 'BSC',      api: 'https://api.bscscan.com/api', key: 'YourApiKeyToken', explorer: 'https://bscscan.com' },
  arb:  { name: 'Arbitrum', api: 'https://api.arbiscan.io/api', key: 'YourApiKeyToken', explorer: 'https://arbiscan.io' },
  base: { name: 'Base',     api: 'https://api.basescan.org/api', key: 'YourApiKeyToken', explorer: 'https://basescan.org' },
};

/* ── Contract Fetcher ── */
class ContractFetcher {
  constructor(chain) {
    this.chain = CHAINS[chain] || CHAINS.bsc;
  }

  async fetchABI(address) {
    const url = `${this.chain.api}?module=contract&action=getabi&address=${address}&apikey=${this.chain.key}`;
    const res = await fetch(url);
    const data = await res.json();
    if (data.status !== '1') throw new Error('ABI not found — contract may not be verified');
    return JSON.parse(data.result);
  }

  async fetchSource(address) {
    const url = `${this.chain.api}?module=contract&action=getsourcecode&address=${address}&apikey=${this.chain.key}`;
    const res = await fetch(url);
    const data = await res.json();
    if (data.status !== '1' || !data.result[0].SourceCode) throw new Error('Source not found');
    const r = data.result[0];
    let src = r.SourceCode;
    if (src.startsWith('{{')) {
      try {
        const parsed = JSON.parse(src.slice(1, -1));
        src = Object.values(parsed.sources).map(s => s.content).join('\n');
      } catch { /* use raw */ }
    }
    return { source: src, name: r.ContractName, compiler: r.CompilerVersion, optimization: r.OptimizationUsed === '1' };
  }
}

/* ── Vulnerability Analyzer ── */
class VulnerabilityAnalyzer {
  analyze(source, abi) {
    const functions = this.parseFunctions(source, abi);
    const findings = [];

    for (const fn of functions) {
      // Reentrancy
      if (this.detectReentrancy(fn)) {
        findings.push({ severity: 'critical', title: 'Reentrancy Vulnerability', function: fn.name,
          description: `External call before state update in ${fn.name}(). Violates Check-Effects-Interactions pattern.`,
          line: fn.line, recommendation: 'Apply ReentrancyGuard or update state before external calls.' });
        fn.risk = 'critical';
      }
      // Access Control
      if (this.detectMissingAccess(fn)) {
        findings.push({ severity: 'high', title: 'Missing Access Control', function: fn.name,
          description: `${fn.name}() modifies critical state but has no access restriction (onlyOwner, require).`,
          line: fn.line, recommendation: 'Add appropriate access control modifier.' });
        if (!fn.risk) fn.risk = 'high';
      }
      // Selfdestruct
      if (this.detectSelfdestruct(fn)) {
        findings.push({ severity: 'critical', title: 'Unprotected SELFDESTRUCT', function: fn.name,
          description: `selfdestruct() or suicide() found in ${fn.name}(). Can permanently destroy the contract.`,
          line: fn.line, recommendation: 'Remove selfdestruct or add strict multi-sig authorization.' });
        fn.risk = 'critical';
      }
      // Delegatecall
      if (this.detectDelegatecall(fn)) {
        findings.push({ severity: 'high', title: 'Dangerous DELEGATECALL', function: fn.name,
          description: `delegatecall in ${fn.name}() can execute arbitrary code in contract context.`,
          line: fn.line, recommendation: 'Ensure delegatecall target is trusted and immutable.' });
        if (!fn.risk) fn.risk = 'high';
      }
      // tx.origin
      if (this.detectTxOrigin(fn)) {
        findings.push({ severity: 'medium', title: 'tx.origin Authentication', function: fn.name,
          description: `tx.origin used for authorization in ${fn.name}(). Vulnerable to phishing attacks.`,
          line: fn.line, recommendation: 'Replace tx.origin with msg.sender.' });
        if (!fn.risk) fn.risk = 'medium';
      }
      // Unchecked call
      if (this.detectUncheckedCall(fn)) {
        findings.push({ severity: 'medium', title: 'Unchecked Return Value', function: fn.name,
          description: `Low-level call in ${fn.name}() without checking return value.`,
          line: fn.line, recommendation: 'Check return value or use Address.sendValue().' });
        if (!fn.risk) fn.risk = 'medium';
      }
      // Timestamp dependence
      if (this.detectTimestamp(fn)) {
        findings.push({ severity: 'low', title: 'Block Timestamp Dependence', function: fn.name,
          description: `block.timestamp used in ${fn.name}(). Miners can manipulate ±15 seconds.`,
          line: fn.line, recommendation: 'Avoid using timestamp for critical logic.' });
        if (!fn.risk) fn.risk = 'low';
      }
      // Arbitrary mint
      if (this.detectArbitraryMint(fn)) {
        findings.push({ severity: 'critical', title: 'Arbitrary Token Minting', function: fn.name,
          description: `${fn.name}() allows minting tokens without proper constraints.`,
          line: fn.line, recommendation: 'Add supply caps and access controls to mint functions.' });
        fn.risk = 'critical';
      }
      if (!fn.risk) fn.risk = fn.visibility === 'view' || fn.visibility === 'pure' ? 'safe' : 'info';
    }
    return { functions, findings };
  }

  parseFunctions(source, abi) {
    const fns = [];
    const fnRegex = /function\s+(\w+)\s*\(([^)]*)\)\s*((?:public|external|internal|private)?)\s*((?:view|pure|payable)?)\s*(?:returns\s*\([^)]*\))?\s*\{/g;
    let match, lineNum = 0;
    const lines = source.split('\n');

    while ((match = fnRegex.exec(source)) !== null) {
      const beforeMatch = source.substring(0, match.index);
      lineNum = beforeMatch.split('\n').length;
      const bodyStart = match.index + match[0].length;
      const body = this.extractBody(source, bodyStart);

      fns.push({
        name: match[1],
        params: match[2].trim(),
        visibility: match[3] || 'public',
        mutability: match[4] || '',
        line: lineNum,
        body: body,
        risk: null,
        connections: []
      });
    }

    // Add ABI-only functions (fallback, receive, constructor)
    if (abi) {
      for (const item of abi) {
        if (item.type === 'function' && !fns.find(f => f.name === item.name)) {
          fns.push({
            name: item.name,
            params: (item.inputs || []).map(i => `${i.type} ${i.name}`).join(', '),
            visibility: item.stateMutability === 'view' || item.stateMutability === 'pure' ? item.stateMutability : 'external',
            mutability: item.stateMutability || '',
            line: 0, body: '', risk: null, connections: []
          });
        }
      }
    }

    // Build connections
    for (const fn of fns) {
      for (const other of fns) {
        if (fn.name !== other.name && fn.body.includes(other.name + '(')) {
          fn.connections.push(other.name);
        }
      }
    }
    return fns;
  }

  extractBody(source, start) {
    let depth = 1, i = start;
    while (i < source.length && depth > 0) {
      if (source[i] === '{') depth++;
      if (source[i] === '}') depth--;
      i++;
    }
    return source.substring(start, i - 1);
  }

  detectReentrancy(fn) {
    if (!fn.body) return false;
    const hasExternalCall = /\.call\{|\.call\(|\.send\(|\.transfer\(/i.test(fn.body);
    const hasStateUpdate = /\w+\s*[\[\]]*\s*=\s*(?!.*==)/m.test(fn.body);
    if (!hasExternalCall || !hasStateUpdate) return false;
    const callIdx = fn.body.search(/\.call\{|\.call\(|\.send\(|\.transfer\(/);
    const assignIdx = fn.body.search(/(?:balances|balance|_balances)\s*\[/);
    return assignIdx > -1 && callIdx > -1 && callIdx < assignIdx;
  }

  detectMissingAccess(fn) {
    if (!fn.body || fn.visibility === 'view' || fn.visibility === 'pure' || fn.visibility === 'internal' || fn.visibility === 'private') return false;
    const isSensitive = /selfdestruct|delegatecall|_mint|_burn|setOwner|transferOwnership|pause|withdraw|set[A-Z]/i.test(fn.body + fn.name);
    const hasGuard = /onlyOwner|require\s*\(\s*msg\.sender|require\s*\(\s*_msgSender|modifier|auth|onlyRole|onlyAdmin|access/i.test(fn.body);
    return isSensitive && !hasGuard;
  }

  detectSelfdestruct(fn) {
    return /selfdestruct\s*\(|suicide\s*\(/i.test(fn.body);
  }

  detectDelegatecall(fn) {
    return /\.delegatecall\s*\(/i.test(fn.body);
  }

  detectTxOrigin(fn) {
    return /tx\.origin/i.test(fn.body);
  }

  detectUncheckedCall(fn) {
    if (!fn.body) return false;
    const hasLowLevel = /\.call\{|\.call\(/i.test(fn.body);
    const checksReturn = /\(bool\s+\w+\s*,|require\s*\(/i.test(fn.body);
    return hasLowLevel && !checksReturn;
  }

  detectTimestamp(fn) {
    return /block\.timestamp|block\.number|now\b/i.test(fn.body);
  }

  detectArbitraryMint(fn) {
    if (!fn.body) return false;
    const hasMint = /_mint\s*\(|mint\s*\(/i.test(fn.body + fn.name);
    const hasGuard = /onlyOwner|require|maxSupply|cap|MAX_SUPPLY/i.test(fn.body);
    return hasMint && !hasGuard;
  }

  calculateRiskScore(findings) {
    let score = 0;
    for (const f of findings) {
      if (f.severity === 'critical') score += 30;
      else if (f.severity === 'high') score += 20;
      else if (f.severity === 'medium') score += 10;
      else if (f.severity === 'low') score += 5;
    }
    return Math.min(score, 100);
  }
}

/* ── Demo Data ── */
const DEMO_CONTRACT = {
  name: 'VulnerableVault',
  source: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableVault {
    mapping(address => uint256) public balances;
    mapping(address => bool) public isVIP;
    address public owner;
    uint256 public totalDeposits;
    bool public paused;
    uint256 public rewardRate;
    uint256 public lastUpdate;

    constructor() {
        owner = msg.sender;
        rewardRate = 100;
        lastUpdate = block.timestamp;
    }

    function deposit() external payable {
        require(!paused, "paused");
        require(msg.value > 0, "zero");
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
    }

    function withdrawAll() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] = 0;
        totalDeposits -= amount;
    }

    function withdrawTo(address payable _to) external {
        uint256 amount = balances[msg.sender];
        (bool ok,) = _to.call{value: amount}("");
        balances[msg.sender] = 0;
    }

    function setRewardRate(uint256 _rate) external {
        rewardRate = _rate;
    }

    function setVIP(address _user) external {
        isVIP[_user] = true;
    }

    function claimReward() external {
        uint256 elapsed = block.timestamp - lastUpdate;
        uint256 reward = balances[msg.sender] * rewardRate * elapsed / 1e18;
        (bool s,) = msg.sender.call{value: reward}("");
        lastUpdate = block.timestamp;
    }

    function emergencyWithdraw() external {
        require(tx.origin == owner, "not owner");
        payable(owner).transfer(address(this).balance);
    }

    function pause() public {
        paused = true;
    }

    function unpause() public {
        paused = false;
    }

    function destroy() external {
        selfdestruct(payable(owner));
    }

    function getBalance(address _user) external view returns (uint256) {
        return balances[_user];
    }

    function getTotalDeposits() external view returns (uint256) {
        return totalDeposits;
    }

    function isPaused() external view returns (bool) {
        return paused;
    }

    function getOwner() external view returns (address) {
        return owner;
    }

    function upgradeLogic(address _impl) external {
        (bool s,) = _impl.delegatecall(abi.encodeWithSignature("initialize()"));
    }

    function multicall(bytes[] calldata data) external {
        for(uint i = 0; i < data.length; i++) {
            (bool success,) = address(this).delegatecall(data[i]);
        }
    }

    receive() external payable {
        balances[msg.sender] += msg.value;
    }
}`,
  abi: [
    {type:'function',name:'deposit',inputs:[],stateMutability:'payable'},
    {type:'function',name:'withdrawAll',inputs:[],stateMutability:'nonpayable'},
    {type:'function',name:'withdrawTo',inputs:[{name:'_to',type:'address'}],stateMutability:'nonpayable'},
    {type:'function',name:'setRewardRate',inputs:[{name:'_rate',type:'uint256'}],stateMutability:'nonpayable'},
    {type:'function',name:'setVIP',inputs:[{name:'_user',type:'address'}],stateMutability:'nonpayable'},
    {type:'function',name:'claimReward',inputs:[],stateMutability:'nonpayable'},
    {type:'function',name:'emergencyWithdraw',inputs:[],stateMutability:'nonpayable'},
    {type:'function',name:'pause',inputs:[],stateMutability:'nonpayable'},
    {type:'function',name:'unpause',inputs:[],stateMutability:'nonpayable'},
    {type:'function',name:'destroy',inputs:[],stateMutability:'nonpayable'},
    {type:'function',name:'getBalance',inputs:[{name:'_user',type:'address'}],stateMutability:'view'},
    {type:'function',name:'getTotalDeposits',inputs:[],stateMutability:'view'},
    {type:'function',name:'isPaused',inputs:[],stateMutability:'view'},
    {type:'function',name:'getOwner',inputs:[],stateMutability:'view'},
    {type:'function',name:'upgradeLogic',inputs:[{name:'_impl',type:'address'}],stateMutability:'nonpayable'},
    {type:'function',name:'multicall',inputs:[{name:'data',type:'bytes[]'}],stateMutability:'nonpayable'},
  ]
};
