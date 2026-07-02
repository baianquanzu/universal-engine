<p align="center">
  <img src="https://img.shields.io/badge/platform-linux%20%7C%20kali-blue" alt="Platform">
  <img src="https://img.shields.io/badge/node-%3E%3D18-green" alt="Node">
  <img src="https://img.shields.io/badge/license-MIT-brightgreen" alt="License">
  <img src="https://img.shields.io/github/stars/baianquanzu/universal-engine?style=social" alt="Stars">
</p>

# Universal Engine

> Defense-oriented N-day vulnerability detection engine with AI-assisted intelligence.
> Built for Kali Linux. Designed for security researchers.

**Universal Engine** is an intelligent asset reconnaissance and vulnerability scanning platform that combines traditional security scanners (nuclei, nmap, nikto, sqlmap) with AI-powered decision making. It detects known vulnerabilities (N-day), fingerprints web assets, and generates actionable security reports — all from a single CLI.

## Features

<table>
<tr>
<td width="50%">

### 🔍 Asset Intelligence
- **Bulk Import** — Drag & drop `.xlsx`/`.csv` files or use CLI for 1000+ assets
- **Live Probing** — Concurrent HTTP probing with real-time progress bars
- **AI Classification** — DeepSeek-powered business categorization (portal, API, CMS, admin console...)
- **IP:Port Auto-detection** — Smart parsing of IP/port column pairs

### 🎯 Fingerprint Engine
- **30+ Built-in Rules** — WordPress, Spring Boot, Tomcat, Weblogic, Shiro, 中国移动OA/ERP...
- **AI-Assisted** — Falls back to AI when built-in rules are uncertain
- **Multi-source** — FingerprintHub + Wappalyzer + EHole rule libraries

</td>
<td width="50%">

### ⚔️ Vulnerability Scanning
- **Nuclei Integration** — Run 10,000+ community templates
- **Kali Toolbox** — Automatic nmap NSE, nikto, sqlmap orchestration
- **Smart Strategy** — Fingerprint-based tool selection:
  - WordPress → nuclei + nikto + sqlmap
  - Java → nuclei + nmap http-*
  - Database → sqlmap + nmap
- **4 Scan Modes** — Quick / Standard / Deep / Full
- **20 Built-in Filters** — Removes low-value findings (missing headers, info leaks)

### 🤖 AI Agent Cluster
- **Agent Hub** — WebSocket + REST message bus
- **7 Specialized Agents** — File Watcher, POC Converter, Scan Executor, Kali Toolbox, AI Reviewer, Orchestrator
- **Auto Pipeline** — File dropped → classified → fingerprinted → scanned → reviewed → reported
- **Real-time Progress** — Colored progress bars for every operation

</td>
</tr>
</table>

## Quick Start

### Prerequisites

- **Kali Linux** (recommended) or any Debian-based Linux
- **Node.js** >= 18
- **nuclei**, **nmap**, **nikto**, **sqlmap** (auto-detected on Kali)

### Installation

```bash
# Clone the repository
git clone https://github.com/baianquanzu/universal-engine.git
cd universal-engine

# Install dependencies
npm install

# Install system-wide
chmod +x install-linux.sh
sudo ./install-linux.sh

# Verify installation
ue --help
ue --status
```

## Usage

### One-Line Asset Import

```bash
# Import from XLSX with real-time progress bar
ue assets import-file targets.xlsx --project "Q3-Pentest" --owner "RedTeam"

# Output:
# ╭─ 资产导入 targets.xlsx ────────────────────────────╮
# 文件           targets.xlsx
# 大小           136.5 KB
# 提取URL候选    247
#
# ╭─ 资产测活 ──────────────────────────────────────╮
# ████████████████░░░░░░░░░░ 67% [165/247]
# └─ https://oss.example.com 200 "管理后台"
#
# ╰──────────────────────────────────────────────────╯
# 存活          142  ✓
# 不可达        105  ✗
```

### Fingerprint & Scan

```bash
# AI-assisted fingerprinting
ue assets refingerprint --project "Q3-Pentest"

# Run a full scan with AI review
ue settings set ai.enabled=true ai.apiKey=sk-your-deepseek-key
ue scans run --project "Q3-Pentest" --name "Baseline"

# View results
ue findings list --project "Q3-Pentest"
ue reports latest --project "Q3-Pentest" --format md
```

### POC Import

```bash
# Import any POC format — zip, directory, single file
ue templates import-poc ./0day-exploits.zip

# Supported types: .py .c .sh .java .php .go .ps1 .bat .rb .pl .cs .cpp .js .ts .rs
# Auto-extracts: CVE IDs, product name, severity, version range, category
# Output: 23 POCs imported across 15 framework families
```

### Agent Mode (Recommended)

```bash
# Start the full agent cluster
ue agent start

# Drop files into data/incoming/ — everything happens automatically:
# .xlsx → import → fingerprint → scan → AI review → report
# .zip  → POC convert → template merge
# .yaml → template import → merge

# Check cluster status
ue agent status
# {
#   "agents": [
#     {"type": "orchestrator", "status": "online"},
#     {"type": "file-watcher", "status": "watching"},
#     {"type": "scan-executor", "status": "ready"},
#     ...
#   ],
#   "queue": {"pending": 0, "running": 1, "completed": 12}
# }
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   Universal Engine                       │
├─────────────────────────────────────────────────────────┤
│  CLI (ue)  │  Agent Hub (WS+REST)  │  File Watcher      │
├─────────────────────────────────────────────────────────┤
│                     Agent Cluster                        │
│  ┌───────────┐  ┌────────────┐  ┌───────────────────┐  │
│  │Orchestrator│  │POC Converter│  │  Scan Executor    │  │
│  │ (Pipeline) │  │ (50+ langs) │  │ (4 modes/20 filt) │  │
│  └───────────┘  └────────────┘  └───────────────────┘  │
│  ┌───────────┐  ┌────────────┐  ┌───────────────────┐  │
│  │Fingerprinter│ │Kali Toolbox │  │   AI Reviewer     │  │
│  │ (30+ rules) │ │(7 tools)    │  │ (DeepSeek/OpenAI) │  │
│  └───────────┘  └────────────┘  └───────────────────┘  │
├─────────────────────────────────────────────────────────┤
│  Nuclei  │  nmap  │  nikto  │  sqlmap  │  httpx          │
└─────────────────────────────────────────────────────────┘
```

## Configuration

```bash
# View all settings
ue settings show

# Enable AI review
ue settings set ai.enabled=true ai.apiKey=sk-your-key ai.provider=deepseek

# Enable nuclei scanning
ue settings set nuclei.enabled=true

# Configure scan concurrency
ue settings set scanning.assetConcurrency=6 scanning.maxConcurrentTasks=3

# Disable auto AI review (faster scanning)
ue settings set scanning.autoAiReview=false
```

### AI Providers

| Provider | Setting |
|----------|---------|
| DeepSeek | `ai.provider=deepseek ai.baseUrl=https://api.deepseek.com` |
| OpenAI | `ai.provider=openai-compatible ai.baseUrl=https://api.openai.com/v1` |
| Anthropic | `ai.provider=anthropic` |
| Ollama (local) | `ai.provider=ollama ai.baseUrl=http://localhost:11434` |

## Command Reference

### Asset Management
```bash
ue assets import-file <file>       # Import XLSX/CSV with live progress
ue assets add --name <n> --target <url>  # Add single asset
ue assets list [--project <name>]  # List assets
ue assets refingerprint [--project <name>]  # Re-fingerprint with AI
ue assets delete [--project <name>]  # Delete assets
```

### Template Management
```bash
ue templates import <path>         # Import nuclei/YAML templates
ue templates import-poc <path>     # Import POC packages (any format)
ue templates groups                # Show template family distribution
ue templates list [--family cms]   # List templates by family
```

### Scanning
```bash
ue scans run [--project <name>] [--asset-id <ids>] [--name <n>]
ue scans list                      # View scan tasks
ue scans clear-finished            # Clean up completed tasks
```

### Findings & Reports
```bash
ue findings list [--project <name>]
ue findings clear [--project <name>]
ue reports latest [--project <name>] [--format md|json] [--output <file>]
```

### Agent Cluster
```bash
ue agent start                     # Start full agent cluster
ue agent stop                      # Stop cluster
ue agent status                    # View agent status
```

### Settings
```bash
ue settings show
ue settings set ai.enabled=true nuclei.enabled=true
```

## Use Cases

### Web Asset Inventory
Import thousands of web assets from spreadsheets, automatically probe for live hosts, and classify by business function — all with a single command.

### N-Day Vulnerability Assessment
Match your asset fingerprints against known vulnerability templates. When a new CVE drops for WordPress or Spring Boot, re-scan immediately with updated templates.

### POC Library Management
Convert any security research POC into a searchable, classified template. Import directories, zip files, or paste code snippets. The AI extracts CVE IDs, affected versions, and categorizes automatically.

### Automated Pentest Pipeline
Drop a spreadsheet of targets into the incoming folder. The agent cluster handles everything: probing → fingerprinting → scanning → AI review → report generation. Go get coffee.

## FAQ

**Q: Do I need Kali Linux?**
A: Kali is recommended for built-in tool support (nmap, nikto, sqlmap). The engine works on any Linux, but you'll need to install the tools separately.

**Q: Is AI required?**
A: No. AI is optional and enhances fingerprint accuracy and finding review quality. All core features work without it.

**Q: How does POC import work?**
A: The POC Converter agent analyzes directory names, README files, code comments, and file extensions. It extracts CVE IDs, product names, severity levels, and categorizes findings using 50+ detection patterns.

**Q: Can I contribute templates?**
A: Yes! Universal Engine supports standard nuclei templates (`.yaml`) and POC packages (any directory structure with a README). Submit via PR.

## Contributing

```bash
# Development setup
git clone https://github.com/baianquanzu/universal-engine.git
cd universal-engine
npm install
npm run dev          # Start with watch mode

# Run tests
node cli/ue.js --status
node cli/ue.js templates groups
```

See [DEVELOPMENT.md](DEVELOPMENT.md) for architecture details.

## License

MIT License — see [LICENSE](LICENSE) file.

---

<p align="center">
  <sub>Built with ❤️ for the security research community</sub>
</p>
