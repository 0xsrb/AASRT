<div align="center">

# 🛡️ AASRT

### AI Agent Security Reconnaissance Tool

*Imperial Security Reconnaissance System for AI Agent Discovery*

[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Status: Production Ready](https://img.shields.io/badge/Status-Production%20Ready-brightgreen)](PROJECT_STATUS.md)
[![Version](https://img.shields.io/badge/Version-1.0.0-blue)](https://github.com/yourusername/aasrt/releases)
[![Tests](https://img.shields.io/badge/Tests-63%20Passing-success)](tests/)
[![Coverage](https://img.shields.io/badge/Coverage-35%25-yellow)](tests/)

</div>

---

## 🎯 Overview

**AASRT** (AI Agent Security Reconnaissance Tool) automates the discovery of publicly exposed AI agent implementations—including ClawdBot, AutoGPT, LangChain agents, Jupyter notebooks, and more—using the Shodan search engine API.

As organizations rapidly deploy AI agents and LLM-powered systems, many are inadvertently exposed to the public internet without proper security controls. AASRT helps security teams identify these exposures through **passive reconnaissance** before attackers do.

**Key Value Propositions:**
- 🔍 **Automated Discovery** — Find exposed AI infrastructure across the internet
- ⚠️ **Vulnerability Assessment** — Automatic detection of API key leaks, auth issues, and dangerous functionality
- 📊 **Risk Scoring** — CVSS-based scoring with severity categorization (Critical/High/Medium/Low)
- 📋 **Comprehensive Reporting** — JSON, CSV exports with persistent scan history

**Target Audience:** Security researchers, penetration testers, DevSecOps teams, and compliance officers conducting authorized security assessments.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔍 **Multi-Source Search** | Shodan integration (Censys/BinaryEdge planned) |
| 🛡️ **Vulnerability Assessment** | Detects API key exposure, auth issues, debug mode, SSL problems |
| 📊 **Risk Scoring** | CVSS-based 0-10 scoring with severity levels |
| 📋 **13+ Query Templates** | Pre-built searches for AutoGPT, LangChain, Jupyter, and more |
| 🌐 **Web Dashboard** | Interactive Streamlit UI with Star Wars Imperial theme |
| ⌨️ **Full CLI** | Complete command-line interface for automation |
| 💾 **Scan History** | SQLite database for persistent findings (2,253+ findings tracked) |
| 🗺️ **Threat Mapping** | Interactive 3D globe visualization of discovered targets |
| 🐳 **Docker Ready** | Multi-stage Dockerfile with docker-compose for easy deployment |
| ✅ **Production Ready** | 63 passing tests, comprehensive input validation, retry logic |

---

## 📦 Installation

### Prerequisites

- **Python 3.11+** (tested on 3.13)
- **pip** package manager
- **Shodan API Key** — [Get one here](https://account.shodan.io/)

### Method 1: From Source (Recommended)

```bash
# Clone the repository
git clone https://github.com/yourusername/aasrt.git
cd aasrt

# Install dependencies
pip install -r requirements.txt

# (Optional) Install development dependencies
pip install -r requirements-dev.txt
```

### Method 2: Using pip (When Published)

```bash
pip install aasrt
```

### Method 3: Docker

```bash
# Build and run with Docker Compose
docker-compose up -d

# Or build manually
docker build -t aasrt .
docker run -e SHODAN_API_KEY=your_key aasrt
```

### Configuration

1. **Create environment file:**
   ```bash
   cp .env.example .env
   ```

2. **Add your Shodan API key:**
   ```bash
   # .env
   SHODAN_API_KEY=your_shodan_api_key_here
   ```

3. **(Optional) Customize settings in `config.yaml`:**
   ```yaml
   shodan:
     rate_limit: 1      # Queries per second
     max_results: 100   # Results per query
     timeout: 30        # Request timeout
   ```

---

## 🚀 Quick Start

### Example 1: Run a Template Scan (CLI)

```bash
python -m src.main scan --template clawdbot_instances --yes
```

### Example 2: Launch Web Dashboard

```bash
streamlit run app.py
# Open http://localhost:8501 in your browser
```

### Example 3: Custom Shodan Query

```bash
python -m src.main scan --query 'http.title:"AutoGPT"' --yes
```

### Example 4: View Scan History

```bash
python -m src.main history
```

### Example 5: List Available Templates

```bash
python -m src.main templates
```

**Output:**
```
┌─────────────────────────────┬──────────┐
│ Template Name               │ Queries  │
├─────────────────────────────┼──────────┤
│ autogpt_instances           │ 2 queries│
│ clawdbot_instances          │ 3 queries│
│ langchain_agents            │ 2 queries│
│ jupyter_notebooks           │ 3 queries│
│ exposed_env_files           │ 2 queries│
│ ...                         │ ...      │
└─────────────────────────────┴──────────┘
```

---

## 📋 Available Query Templates

| Template | Target | Queries |
|----------|--------|---------|
| `clawdbot_instances` | ClawdBot AI dashboards | 5 |
| `autogpt_instances` | AutoGPT deployments | 5 |
| `langchain_agents` | LangChain agent implementations | 5 |
| `openai_exposed` | Exposed OpenAI integrations | 2 |
| `exposed_env_files` | Leaked .env configuration files | 2 |
| `debug_mode` | Services with debug mode enabled | 3 |
| `jupyter_notebooks` | Exposed Jupyter notebooks | 3 |
| `streamlit_apps` | Streamlit applications | 2 |
| `ai_dashboards` | Generic AI/LLM dashboards | 3 |
| `clawsec_advisories` | ClawSec CVE-matched targets | 10 |

**Create custom templates:** See [Custom Query Templates Guide](CUSTOM_QUERIES_GUIDE.md)

---

## 📖 Documentation

| Document | Description |
|----------|-------------|
| 📖 [Quick Start Guide](QUICK_START.md) | Detailed usage instructions and examples |
| 📋 [Custom Query Templates](CUSTOM_QUERIES_GUIDE.md) | Create your own Shodan query templates |
| 🗺️ [Map Visualization Guide](QUICK_MAP_GUIDE.md) | Interactive threat map features |

**Developer Documentation** (in `dev/docs/`):
| Document | Description |
|----------|-------------|
| 📊 [Project Status](dev/docs/PROJECT_STATUS.md) | Current system health and statistics |
| 📝 [Technical Specification](dev/docs/Outline.md) | Full product requirements document |
| 🔧 [Bug Fixes Log](dev/docs/FIXES_APPLIED.md) | Technical details of resolved issues |
| 🗺️ [Map Enhancements](dev/docs/MAP_ENHANCEMENTS.md) | Map visualization implementation details |

---

## ⚠️ Legal Disclaimer

> **🚨 IMPORTANT: This tool is for AUTHORIZED SECURITY RESEARCH and DEFENSIVE PURPOSES ONLY.**
>
> **Unauthorized access to computer systems is ILLEGAL under:**
> - 🇺🇸 CFAA (Computer Fraud and Abuse Act) — United States
> - 🇬🇧 Computer Misuse Act — United Kingdom
> - 🇪🇺 EU Directive on Attacks Against Information Systems
> - Similar laws exist in virtually every jurisdiction worldwide
>
> **By using this tool, you acknowledge and agree that:**
> 1. ✅ You have **explicit authorization** to scan target systems
> 2. ✅ You will **comply with all applicable laws** and terms of service
> 3. ✅ You will **responsibly disclose** any vulnerabilities discovered
> 4. ✅ You will **NOT exploit** discovered vulnerabilities
> 5. ✅ You understand this tool performs **passive reconnaissance only**
>
> **The authors assume NO LIABILITY for misuse of this tool.**

---

## 📁 Project Structure

```
aasrt/
├── src/                      # Core application code
│   ├── main.py               # CLI entry point
│   ├── core/                 # Query manager, risk scorer, vulnerability assessor
│   ├── engines/              # Search engine integrations (Shodan)
│   ├── enrichment/           # Threat intelligence (ClawSec feed)
│   ├── reporting/            # JSON/CSV report generators
│   ├── storage/              # SQLite database layer
│   └── utils/                # Config, logging, validators, exceptions
├── queries/                  # Query template YAML files
├── reports/                  # Generated scan reports
├── logs/                     # Application logs
├── data/                     # SQLite database
├── dev/                      # Development files (not for production)
│   ├── tests/                # Unit and integration tests (63 tests)
│   ├── docs/                 # Developer documentation
│   ├── pytest.ini            # Pytest configuration
│   └── requirements-dev.txt  # Development dependencies
├── app.py                    # Streamlit web dashboard
├── config.yaml               # Application configuration
├── requirements.txt          # Production dependencies
├── Dockerfile                # Multi-stage Docker build
└── docker-compose.yml        # Docker Compose with PostgreSQL
```

---

## 🧪 Testing

```bash
# Run all unit tests (from project root)
python -m pytest dev/tests/unit/ -v

# Run with coverage
python -m pytest dev/tests/unit/ --cov=src --cov-report=term-missing

# Run specific test module
python -m pytest dev/tests/unit/test_validators.py -v

# Use pytest.ini config
python -m pytest -c dev/pytest.ini dev/tests/unit/ -v
```

**Current Status:** 63 tests passing, 35% coverage

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

For bugs or feature requests, please [open an issue](https://github.com/yourusername/aasrt/issues).

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- [Shodan](https://www.shodan.io/) — Search engine for internet-connected devices
- [Streamlit](https://streamlit.io/) — Web dashboard framework
- [SQLAlchemy](https://www.sqlalchemy.org/) — Database ORM
- [Click](https://click.palletsprojects.com/) — CLI framework
- [Rich](https://rich.readthedocs.io/) — Terminal formatting
- The security research community

---

<div align="center">

**⭐ Star this repo if you find it useful!**

*May the Force be with your reconnaissance.* 🌟

</div>
