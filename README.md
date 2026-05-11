# 🧠 NEUROSCAN — Smart Contract Brain Scanner

> Visualize smart contract vulnerabilities as an interactive neural network.

[![Live Demo](https://img.shields.io/badge/Live%20Demo-neuroscan--eta.vercel.app-00ff88?style=for-the-badge&logo=vercel)](https://neuroscan-eta.vercel.app/)
![License](https://img.shields.io/badge/license-MIT-green)
![Chains](https://img.shields.io/badge/chains-ETH%20|%20BSC%20|%20ARB%20|%20BASE%20|%20POLY-blue)

## 🔗 Live Demo

> **[neuroscan-eta.vercel.app](https://neuroscan-eta.vercel.app/)** — Try it now, no install needed.

> ⚠️ Requires a **free** [Etherscan API key](https://etherscan.io/myapikey) (30 sec signup) to scan live contracts.
> One key works for ETH, BSC, Arbitrum, Base, and Polygon. Demo mode works without a key.

## What is NEUROSCAN?

NEUROSCAN transforms smart contract security analysis into a **visual experience**. Instead of reading through lines of audit text, see your contract's security architecture as an **interactive neural graph** where:

- 🔴 **Red neurons** pulse for critical vulnerabilities (reentrancy, selfdestruct)
- 🟠 **Orange neurons** glow for high-risk issues (missing access control, delegatecall)
- 🟡 **Yellow neurons** signal medium risks (unchecked returns, tx.origin)
- 🟢 **Green neurons** confirm safe functions
- ⚪ **Cyan neurons** represent view/pure functions

## Features

- **Neural Visualization** — D3.js force-directed graph maps every function as a neuron
- **Real-time Scanning** — Fetches verified source code from block explorers
- **Multi-chain** — Ethereum, BSC, Arbitrum, Base
- **8 Vulnerability Detectors** — Reentrancy, access control, selfdestruct, delegatecall, tx.origin, unchecked calls, timestamp dependence, arbitrary minting
- **Interactive** — Hover, click, drag, zoom on any node
- **Risk Score** — Animated circular gauge with severity breakdown
- **Zero Dependencies** — Pure HTML/CSS/JS + D3.js CDN
- **Demo Mode** — Try it instantly without an API key

## Quick Start

```bash
# Clone
git clone https://github.com/eawhitehat/neuroscan.git

# Open
open neuroscan/index.html
```

Or visit the [live demo](https://neuroscan.vercel.app).

## How It Works

1. **Paste** a verified contract address
2. **Select** the chain (ETH, BSC, ARB, BASE)
3. **Click** "Initialize Scan"
4. **Watch** the neural map build in real-time
5. **Interact** — click neurons to see vulnerability details

## Vulnerability Detectors

| Detector | Severity | Description |
|---|---|---|
| Reentrancy | Critical | External call before state update |
| Selfdestruct | Critical | Unprotected contract destruction |
| Arbitrary Mint | Critical | Token minting without constraints |
| Missing Access Control | High | Sensitive functions without auth |
| Delegatecall | High | Arbitrary code execution risk |
| tx.origin | Medium | Phishing-vulnerable authentication |
| Unchecked Return | Medium | Low-level call without error handling |
| Timestamp Dependence | Low | Miner-manipulable block.timestamp |

## Tech Stack

- **Frontend**: Vanilla HTML/CSS/JS
- **Visualization**: D3.js v7
- **Particle System**: Canvas 2D
- **Data Source**: Etherscan/BSCScan/Arbiscan/Basescan APIs
- **Design**: Glassmorphism, dark mode, neon glow effects

## Author

Built by [@eawhitehat](https://github.com/eawhitehat) — Web3 Security Researcher & Bug Bounty Hunter.

## License

MIT
