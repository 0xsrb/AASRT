# Privacy Policy

**AASRT (AI Agent Security Reconnaissance Tool)**  
**Effective Date:** February 2025  
**Version:** 1.0.0

---

## Overview

AASRT is an open-source security reconnaissance tool designed for security researchers, bug bounty hunters, and DevSecOps teams. This privacy policy explains how AASRT handles data during operation.

**Key Principle:** AASRT is a local tool. All scan data is stored on your machine. We do not operate servers that collect your data.

---

## 1. Data Collection

### What AASRT Collects During Scans

| Data Type | Description | Source |
|-----------|-------------|--------|
| **IP Addresses** | Public IP addresses of discovered hosts | Shodan API |
| **Port Information** | Open ports and service banners | Shodan API |
| **Vulnerability Findings** | Identified security issues and risk scores | AASRT analysis |
| **Host Metadata** | Hostnames, organizations, geographic location | Shodan API |
| **Scan Metadata** | Timestamps, query used, scan duration | AASRT |

### What AASRT Does NOT Collect

- ❌ Personal information beyond publicly indexed data
- ❌ Your Shodan API key (never logged or transmitted)
- ❌ Authentication credentials found in scans (redacted in logs)
- ❌ Analytics or telemetry about your usage
- ❌ Any data sent to AASRT developers or third parties

---

## 2. Data Storage

### Local Database

All scan data is stored locally in a SQLite database:

```
data/scanner.db
```

**You have complete control over this data.** It never leaves your machine unless you explicitly export and share it.

### Data Retention

| Data Type | Default Retention | Configurable |
|-----------|-------------------|--------------|
| Scan Results | 90 days | Yes |
| Audit Logs | 1 year | Yes |
| Error Logs | 30 days | Yes |

### Data Deletion

You can delete your data at any time:

- **Delete individual scans:** Use the CLI or dashboard to remove specific scans
- **Bulk cleanup:** Run `cleanup_old_data(days=N)` to remove scans older than N days
- **Complete deletion:** Delete the `data/scanner.db` file

---

## 3. Third-Party Services

### Shodan API

AASRT uses the [Shodan API](https://www.shodan.io/) to discover publicly indexed hosts. When you run a scan:

- Your query is sent to Shodan's servers
- Shodan returns publicly indexed information
- Shodan's [Privacy Policy](https://www.shodan.io/privacy) and [Terms of Service](https://www.shodan.io/terms) apply

**Important:** Shodan only indexes publicly accessible information. AASRT does not perform active scanning—it queries Shodan's existing database of internet-wide scans.

### ClawSec Advisory Feed

AASRT optionally fetches security advisories from ClawSec for threat enrichment. This is a public feed and does not transmit your scan data.

---

## 4. API Key Security

Your Shodan API key is handled with care:

| Security Measure | Implementation |
|------------------|----------------|
| **Storage** | Environment variable (`SHODAN_API_KEY`) - never in code |
| **Logging** | Never logged - automatically redacted |
| **Transmission** | HTTPS only to Shodan API |
| **Visibility** | Masked in dashboard and CLI output |

### Automatic Redaction

AASRT automatically redacts sensitive patterns in logs and output:

- Anthropic API keys (`sk-ant-***`)
- OpenAI API keys (`sk-***`)
- AWS credentials (`AKIA***`)
- GitHub tokens (`ghp_***`)
- Shodan API keys (`***REDACTED_KEY***`)
- Passwords and secrets

---

## 5. Personal Data & Compliance

### No PII Collection

AASRT does not collect personal information beyond what is already publicly indexed by Shodan. The tool discovers:

- Publicly exposed servers and services
- Misconfigured AI agent deployments
- Information already visible to anyone on the internet

### Anonymization Options

When generating reports, you can anonymize findings:

- Mask IP address octets (e.g., `192.168.1.xxx`)
- Remove organization names
- Redact hostnames

Configure via `anonymize_by_default: true` in `config.yaml`.

### Regulatory Alignment

AASRT is designed with the following regulations in mind:

| Regulation | Consideration |
|------------|---------------|
| **GDPR (EU)** | Right to delete data; no PII collection; local storage only |
| **CFAA (US)** | Passive reconnaissance only; no unauthorized access |
| **Computer Misuse Act (UK)** | No active exploitation; queries public databases only |

**Note:** Compliance ultimately depends on how you use the tool. Always ensure you have authorization for security assessments.

---

## 6. Your Rights

As the user, you have full control:

| Right | How to Exercise |
|-------|-----------------|
| **Access** | View all scan data in the dashboard or database |
| **Export** | Export findings to JSON/CSV at any time |
| **Delete** | Remove individual scans or all data |
| **Retention** | Configure how long data is kept |
| **Portability** | SQLite database can be moved or backed up |

---

## 7. Logging Practices

### What IS Logged (`logs/scanner.log`)

- Scan start/end timestamps
- Query names and types (not the full query)
- Number of results found
- Errors and warnings
- Database operations (create, update, delete)

### What is NOT Logged

- ❌ API keys or credentials
- ❌ Full Shodan API responses
- ❌ Detailed vulnerability exploitation paths
- ❌ User identity or system information

### Log Configuration

```yaml
# config.yaml
logging:
  level: INFO          # DEBUG, INFO, WARNING, ERROR
  file: ./logs/scanner.log
  max_size_mb: 100     # Rotate at 100MB
  backup_count: 5      # Keep 5 backup files
```

---

## 8. Report Sharing Considerations

When you export and share scan reports (JSON/CSV), consider:

### Before Sharing

✅ **Do:**
- Review findings for sensitive information
- Use anonymization options for public reports
- Redact organization names if not authorized
- Follow responsible disclosure practices

❌ **Don't:**
- Share reports containing unexploited vulnerabilities publicly
- Include API keys or credentials found in scans
- Distribute findings without authorization

### Responsible Disclosure

If you discover vulnerabilities in third-party systems:

1. Attempt to contact the affected organization
2. Allow 90 days for remediation before public disclosure
3. Anonymize sensitive details in public reports
4. Consider coordinating with CERTs for critical findings

---

## 9. Legal Disclaimer

AASRT is a **passive reconnaissance tool** that queries publicly available data. However:

- **You are responsible** for ensuring your use complies with applicable laws
- **Authorization is required** for security assessments of systems you don't own
- **This tool is provided "as-is"** without warranty of any kind
- **The developers are not liable** for misuse or illegal activity

See the full [LICENSE](LICENSE) and legal disclaimers in the [README](README.md).

---

## 10. Policy Updates

This privacy policy may be updated as the tool evolves. Changes will be:

- Documented in the repository's commit history
- Noted in release notes for significant changes
- Effective immediately upon commit

---

## Contact

For privacy-related questions or concerns:

- **GitHub Issues:** [github.com/0xsrb/AASRT/issues](https://github.com/0xsrb/AASRT/issues)
- **Repository:** [github.com/0xsrb/AASRT](https://github.com/0xsrb/AASRT)

---

*This privacy policy is designed for an open-source security tool and may not cover all legal requirements in your jurisdiction. Consult legal counsel if needed.*

