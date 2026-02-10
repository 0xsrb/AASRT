# AASRT Quick Start Guide

## Prerequisites
✅ Python 3.13 installed
✅ All dependencies installed (`pip install -r requirements.txt`)
✅ Shodan API key configured in `.env` file

## Basic Commands

### 1. Check System Status
```bash
python -m src.main status
```
This shows:
- Shodan API status and credits
- Available query templates (13 templates)
- Your current plan type

### 2. List Available Templates
```bash
python -m src.main templates
```
Available templates:
- `clawdbot_instances` - Find ClawdBot dashboards
- `autogpt_instances` - Find AutoGPT deployments
- `langchain_agents` - Find LangChain agents
- `openai_exposed` - Find exposed OpenAI integrations
- `exposed_env_files` - Find exposed .env files
- `debug_mode` - Find services with debug mode enabled
- `jupyter_notebooks` - Find exposed Jupyter notebooks
- `streamlit_apps` - Find Streamlit applications
- And 5 more...

### 3. Run a Scan

**Using a template (recommended):**
```bash
python -m src.main scan --template clawdbot_instances --yes
```

**Using a custom query:**
```bash
python -m src.main scan --query 'http.title:"AutoGPT"' --yes
```

**Without --yes flag (shows legal disclaimer):**
```bash
python -m src.main scan --template clawdbot_instances
```

### 4. View Scan History
```bash
python -m src.main history
```
Shows:
- Last 10 scans
- Scan IDs, timestamps, results count
- Database statistics

### 5. Generate Report from Previous Scan
```bash
python -m src.main report --scan-id <scan_id>
```

## Understanding Scan Results

### Console Output
```
+-------------------------------- Scan Summary --------------------------------+
| Scan ID: 211a5df0...                                                         |
| Duration: 3.3s                                                               |
| Total Results: 32                                                            |
| Average Risk Score: 3.7/10                                                   |
+------------------------------------------------------------------------------+

 Risk Distribution  
+------------------+
| Severity | Count |
|----------+-------|
| Critical |     4 |
| High     |     0 |
| Medium   |     0 |
| Low      |    28 |
+------------------+
```

### Report Files
Reports are saved in `./reports/` directory:
- **JSON format:** `scan_<id>_<timestamp>.json`
- **CSV format:** `scan_<id>_<timestamp>.csv` (if enabled)

### Database
All scans are automatically saved to: `./data/scanner.db`

## Common Use Cases

### 1. Find Exposed AI Dashboards
```bash
python -m src.main scan --template ai_dashboards --yes
```

### 2. Find Debug Mode Enabled Services
```bash
python -m src.main scan --template debug_mode --yes
```

### 3. Find Exposed Environment Files
```bash
python -m src.main scan --template exposed_env_files --yes
```

### 4. Custom Search for Specific Service
```bash
python -m src.main scan --query 'product:"nginx" port:8080' --yes
```

## Understanding Risk Scores

- **10.0 (Critical):** No authentication on sensitive dashboards
- **7.0-9.9 (High):** Exposed API keys, shell access, database strings
- **5.0-6.9 (Medium):** SSL issues, exposed config files
- **3.0-4.9 (Low):** Self-signed certificates, missing security.txt
- **1.0-2.9 (Info):** Informational findings

## Vulnerability Types Detected

1. **Authentication Issues**
   - No authentication on dashboards
   - Missing security controls

2. **API Key Exposure**
   - OpenAI keys (sk-...)
   - Anthropic keys (sk-ant-...)
   - AWS credentials (AKIA...)
   - GitHub tokens (ghp_...)
   - Google API keys (AIza...)
   - Stripe keys (sk_live_...)

3. **Dangerous Functionality**
   - Shell execution endpoints
   - Debug mode enabled
   - File upload functionality
   - Admin panels exposed
   - Database connection strings

4. **Information Disclosure**
   - Exposed .env files
   - Configuration files
   - Git repositories
   - Source code files

5. **SSL/TLS Issues**
   - Expired certificates
   - Self-signed certificates
   - No SSL on HTTPS ports

## Configuration

Edit `config.yaml` to customize:

```yaml
shodan:
  rate_limit: 1  # queries per second
  max_results: 100

vulnerability_checks:
  enabled: true
  passive_only: true

reporting:
  formats:
    - json
    - csv
  output_dir: "./reports"

filtering:
  min_confidence_score: 70
  exclude_honeypots: true

logging:
  level: "INFO"
  file: "./logs/scanner.log"
```

## Tips & Best Practices

1. **Start with specific templates** rather than broad queries
2. **Use --yes flag** to skip legal disclaimer for automated scans
3. **Check your Shodan credits** before running large scans
4. **Review reports in JSON format** for detailed findings
5. **Use scan history** to track your reconnaissance over time

## Troubleshooting

### "Invalid API key" error
- Check your `.env` file has the correct `SHODAN_API_KEY`
- Verify the key is valid at https://account.shodan.io/

### "Rate limit exceeded"
- Reduce `rate_limit` in `config.yaml`
- Wait a few minutes before retrying

### No results found
- Try different templates or queries
- Check if the service/product exists on Shodan
- Use `python -m src.main status` to verify API connectivity

## Legal Notice

⚠️ **Important:** This tool is for authorized security research only.
- Only scan systems you have permission to test
- Comply with all applicable laws and terms of service
- Responsibly disclose any findings
- Do not exploit discovered vulnerabilities

## Support

- Documentation: See `README.md` and `Outline.md`
- Bug Fixes: See `FIXES_APPLIED.md`
- Query Templates: Check `queries/` directory
- Logs: Check `logs/scanner.log` for detailed information

## Current Status

✅ All systems operational
✅ 13 query templates available
✅ 81 Shodan query credits remaining
✅ Database with 17 scans and 2253 findings
✅ All bug fixes applied and tested
