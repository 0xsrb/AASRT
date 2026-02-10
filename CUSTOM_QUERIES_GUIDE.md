# 📋 AASRT Custom Query Templates Guide

Create your own Shodan query templates to extend AASRT's reconnaissance capabilities.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [File Structure](#file-structure)
3. [Required & Optional Fields](#required--optional-fields)
4. [Shodan Query Syntax](#shodan-query-syntax)
5. [UI Integration](#ui-integration)
6. [Best Practices](#best-practices)
7. [Step-by-Step Example](#step-by-step-example)
8. [Troubleshooting](#troubleshooting)

---

## Quick Start

1. Copy the example template:
   ```bash
   cp queries/custom.yaml.example queries/my_template.yaml
   ```

2. Edit the file with your queries:
   ```yaml
   name: My Custom Template
   description: Search for my target systems
   author: Your Name
   version: 1.0

   queries:
     - 'http.title:"My Target"'
     - 'http.html:"keyword" port:8080'

   tags:
     - custom
     - my-category
   ```

3. Refresh the AASRT dashboard—your template appears automatically!

---

## File Structure

### Location

All custom templates go in the `queries/` directory at the project root:

```
AASRT/
├── queries/
│   ├── autogpt.yaml           # Built-in template
│   ├── clawdbot.yaml          # Built-in template
│   ├── langchain.yaml         # Built-in template
│   ├── clawsec_advisories.yaml
│   ├── custom.yaml.example    # Template reference (ignored)
│   └── my_custom.yaml         # ← Your custom templates here!
├── app.py
├── src/
└── ...
```

### File Naming

| Aspect | Rule | Example |
|--------|------|---------|
| **Extension** | Must be `.yaml` or `.yml` | `ollama_instances.yaml` |
| **Template Name** | Derived from filename (without extension) | `ollama_instances` |
| **Characters** | Use lowercase, underscores, no spaces | `huggingface_models.yaml` ✅ |
| **Avoid** | Hyphens, uppercase, special chars | `Hugging-Face.yaml` ❌ |

### YAML Format

Templates use standard YAML syntax:

```yaml
# Comment line (starts with #)
name: Template Name          # Scalar value
description: Some text       # String (quotes optional for simple text)

queries:                     # List of items
  - 'first query'           # List item (note the dash)
  - 'second query'
  - 'third query'

tags:                        # Another list
  - tag1
  - tag2
```

> **⚠️ Important:** Use consistent indentation (2 spaces recommended). YAML is whitespace-sensitive!

---

## Required & Optional Fields

### Field Reference Table

| Field | Required | Type | Description |
|-------|----------|------|-------------|
| `name` | ✅ Yes | String | Display name shown in UI |
| `description` | ✅ Yes | String | What the template searches for |
| `queries` | ✅ Yes | List | Shodan query strings to execute |
| `author` | ⚪ Optional | String | Creator's name |
| `version` | ⚪ Optional | String | Template version (e.g., "1.0") |
| `tags` | ⚪ Optional | List | Categorization tags |

### Complete Example

```yaml
# Ollama Model Server Detection Template
# Created: 2026-02-10

name: Ollama Model Servers
description: Detect exposed Ollama LLM model servers with web interfaces
author: Security Research Team
version: 1.2

queries:
  - 'http.title:"Ollama"'
  - 'http.html:"ollama" port:11434'
  - 'http.html:"llama" http.html:"model"'
  - 'product:"Ollama"'
  - 'http.title:"Ollama Web UI"'

tags:
  - ai-agent
  - llm
  - ollama
  - self-hosted
  - critical
```

### Queries Field Formats

AASRT supports two query formats:

**Format 1: Simple List (Recommended)**
```yaml
queries:
  - 'http.title:"Target"'
  - 'http.html:"keyword"'
```

**Format 2: Nested Dict (Advanced)**
```yaml
queries:
  shodan:
    - 'http.title:"Target"'
    - 'http.html:"keyword"'
```

---

## Shodan Query Syntax

### Common Search Operators

| Operator | Purpose | Example |
|----------|---------|---------|
| `http.title:` | Search page titles | `http.title:"Dashboard"` |
| `http.html:` | Search HTML body content | `http.html:"api_key"` |
| `product:` | Search product banners | `product:"nginx"` |
| `port:` | Filter by port number | `port:8080` |
| `hostname:` | Filter by hostname | `hostname:example.com` |
| `org:` | Filter by organization | `org:"Amazon"` |
| `country:` | Filter by country code | `country:US` |
| `ssl:` | Search SSL certificate fields | `ssl:"Let's Encrypt"` |
| `http.status:` | Filter by HTTP status code | `http.status:200` |

### Boolean Operators

| Operator | Usage | Example |
|----------|-------|---------|
| **AND** | Implicit (space-separated) | `http.title:"GPT" port:8000` |
| **OR** | Explicit OR keyword | `http.title:"AutoGPT" OR http.title:"Auto-GPT"` |
| **NOT** | Exclude with minus | `http.title:"Dashboard" -port:443` |

### Combining Filters (Examples)

```yaml
queries:
  # Find LangChain agents on common ports
  - 'http.html:"langchain" http.html:"agent" port:8000,8080,3000'

  # Find exposed API keys in HTML
  - 'http.html:"sk-" http.html:"openai"'

  # Find debug mode enabled (multiple patterns)
  - 'http.html:"DEBUG=True" OR http.html:"debug: true"'

  # Exclude CDN-hosted results
  - 'http.title:"Jupyter" -org:"Cloudflare" -org:"Amazon CloudFront"'

  # Country-specific search
  - 'http.title:"AI Dashboard" country:US,GB,DE'

  # Certificate-based discovery
  - 'ssl.cert.subject.CN:"*.openai.com"'
```

### Query Quoting Rules

| Scenario | Syntax | Example |
|----------|--------|---------|
| Exact phrase | Double quotes inside single | `'http.title:"Auto-GPT Dashboard"'` |
| Simple word | No inner quotes needed | `'product:nginx'` |
| Special characters | Always quote the value | `'http.html:"api_key="'` |

> **💡 Pro Tip:** Test your queries on [Shodan.io](https://www.shodan.io/) before adding them to templates!

---

## UI Integration

### Where Templates Appear

Custom templates automatically appear in the Streamlit dashboard:

```
┌─────────────────────────────────────────────────────┐
│  MISSION TYPE:  ○ 🎯 TEMPLATE  ○ ✍️ CUSTOM          │
├─────────────────────────────────────────────────────┤
│  SELECT TARGET                                      │
│  ┌───────────────────────────────────────────────┐  │
│  │ 📋 My Custom Template                      ▼  │  │
│  ├───────────────────────────────────────────────┤  │
│  │ 🤖 Autogpt Instances                          │  │
│  │ 🐾 Clawdbot Instances                         │  │
│  │ 🔗 Langchain Agents                           │  │
│  │ 📋 My Custom Template        ← Your template! │  │
│  │ 🛡️ Clawsec Advisories                         │  │
│  └───────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

### Template Display Formatting

Templates are displayed with:

1. **Icon** - Based on template name (defaults to 📋 for custom templates)
2. **Name** - Filename converted to title case (`my_template` → "My Template")

**Built-in Icon Mappings:**

| Template Name | Icon |
|--------------|------|
| `autogpt_instances` | 🤖 |
| `langchain_agents` | 🔗 |
| `jupyter_notebooks` | 📓 |
| `clawdbot_instances` | 🐾 |
| `exposed_env_files` | 📁 |
| `clawsec_advisories` | 🛡️ |
| Custom templates | 📋 |

### Refreshing Templates

**Web Dashboard (Streamlit):**
- Templates are cached for 5 minutes (`ttl=300`)
- To force refresh: **Press `R`** or **click the ⟳ button** in the browser
- Or restart the Streamlit server

**CLI:**
- Templates are loaded fresh on each command
- Run `python -m src.main templates` to see updated list

---

## Best Practices

### ✅ Do's

| Practice | Why | Example |
|----------|-----|---------|
| **Start specific, then broaden** | Avoid wasting API credits | Start with `http.title:"Exact Name"` before `http.html:"keyword"` |
| **Test on Shodan.io first** | Validate results before scanning | Check result count and relevance |
| **Use multiple query variations** | Cover different configurations | Include both "Auto-GPT" and "AutoGPT" |
| **Add meaningful tags** | Organize and filter templates | `tags: [ai-agent, critical, llm]` |
| **Document your queries** | Future maintainability | Add comments explaining each query |
| **Version your templates** | Track changes | `version: 1.2` |

### ❌ Don'ts

| Anti-Pattern | Problem | Better Alternative |
|--------------|---------|-------------------|
| `http.html:"a"` | Too broad, millions of results | Use specific keywords |
| No quotes on phrases | Query parsing errors | Always quote multi-word phrases |
| `port:*` | Invalid syntax | Omit port filter entirely |
| Mixing tabs and spaces | YAML parsing fails | Use spaces only (2-space indent) |
| 50+ queries per template | Slow scans, API waste | Split into multiple templates |

### Query Optimization Tips

```yaml
# ❌ Bad: Too broad, returns millions
queries:
  - 'http.html:"api"'

# ✅ Good: Specific and targeted
queries:
  - 'http.html:"openai" http.html:"api_key"'
  - 'http.html:"sk-" http.html:"Bearer"'
```

```yaml
# ❌ Bad: Missing quotes around phrase
queries:
  - http.title:Auto-GPT Dashboard

# ✅ Good: Properly quoted
queries:
  - 'http.title:"Auto-GPT Dashboard"'
```

---

## Step-by-Step Example

Let's create a template to find exposed **Hugging Face Spaces** and **Gradio apps**.

### Step 1: Research on Shodan.io

Visit [Shodan.io](https://www.shodan.io/) and test queries:

```
http.title:"Hugging Face"           → 1,234 results
http.html:"gradio" port:7860        → 567 results
http.title:"Gradio"                 → 890 results
```

### Step 2: Create the Template File

Create `queries/huggingface_spaces.yaml`:

```yaml
# Hugging Face Spaces and Gradio Detection Template
# Finds exposed ML demo applications

name: Hugging Face Spaces
description: Detect exposed Hugging Face Spaces and Gradio ML applications
author: Security Team
version: 1.0

queries:
  # Direct Hugging Face Spaces
  - 'http.title:"Hugging Face"'
  - 'http.html:"huggingface" http.html:"spaces"'

  # Gradio apps (common ML demo framework)
  - 'http.title:"Gradio"'
  - 'http.html:"gradio" port:7860'
  - 'http.html:"gradio-app"'

  # Streamlit ML apps
  - 'http.html:"streamlit" http.html:"model"'

  # Generic ML dashboard patterns
  - 'http.title:"ML Dashboard" OR http.title:"Model Demo"'

tags:
  - ai-agent
  - huggingface
  - gradio
  - machine-learning
  - demo
```

### Step 3: Validate YAML Syntax

Use an online YAML validator or Python:

```bash
python -c "import yaml; yaml.safe_load(open('queries/huggingface_spaces.yaml'))"
```

No output = valid YAML!

### Step 4: Verify Template Loading

```bash
python -m src.main templates
```

Output should include:
```
┌─────────────────────────────────┬──────────┐
│ Template Name                   │ Queries  │
├─────────────────────────────────┼──────────┤
│ autogpt_instances               │ 2 queries│
│ clawdbot_instances              │ 3 queries│
│ huggingface_spaces              │ 8 queries│  ← Your new template!
│ langchain_agents                │ 2 queries│
└─────────────────────────────────┴──────────┘
```

### Step 5: Run a Scan

**CLI:**
```bash
python -m src.main scan --template huggingface_spaces --yes
```

**Web Dashboard:**
1. Open `http://localhost:8501`
2. Select "📋 Huggingface Spaces" from dropdown
3. Accept mission parameters
4. Click "🚀 INITIATE SCAN"

---

## Troubleshooting

### Common Issues

#### Template Not Appearing in UI

| Symptom | Cause | Solution |
|---------|-------|----------|
| Template not in dropdown | File not in `queries/` dir | Move file to correct location |
| Template not in dropdown | Wrong file extension | Rename to `.yaml` or `.yml` |
| Template not in dropdown | Cache not refreshed | Press `R` in browser or restart Streamlit |
| Template not in dropdown | YAML syntax error | Validate YAML (see below) |

#### YAML Syntax Errors

**Error:** `yaml.scanner.ScannerError: mapping values are not allowed here`

```yaml
# ❌ Wrong: Missing space after colon
name:Template Name

# ✅ Correct
name: Template Name
```

**Error:** `yaml.parser.ParserError: expected ',' or ']'`

```yaml
# ❌ Wrong: Mixing quote styles
queries:
  - "http.title:'Dashboard'"

# ✅ Correct: Consistent quoting
queries:
  - 'http.title:"Dashboard"'
```

**Error:** `yaml.scanner.ScannerError: found character '\t'`

```yaml
# ❌ Wrong: Using tabs
queries:
	- 'query'

# ✅ Correct: Using spaces (2-space indent)
queries:
  - 'query'
```

#### Queries Return No Results

| Symptom | Cause | Solution |
|---------|-------|----------|
| 0 results for all queries | Shodan API key invalid | Check `SHODAN_API_KEY` in `.env` |
| 0 results for specific query | Query too specific | Broaden search terms |
| 0 results for specific query | Typo in query | Test on Shodan.io first |
| Fewer results than expected | Rate limiting | Wait and retry |

#### Validate YAML Syntax

**Online validators:**
- [YAML Lint](https://www.yamllint.com/)
- [YAML Validator](https://jsonformatter.org/yaml-validator)

**Python validation:**
```python
import yaml
from pathlib import Path

template_path = Path("queries/my_template.yaml")
try:
    data = yaml.safe_load(template_path.read_text())
    print("✅ Valid YAML!")
    print(f"   Name: {data.get('name')}")
    print(f"   Queries: {len(data.get('queries', []))}")
except yaml.YAMLError as e:
    print(f"❌ YAML Error: {e}")
```

---

## Advanced Topics

### Template Inheritance (Future)

Currently not supported, but you can combine queries manually:

```yaml
# combined_ai_agents.yaml
queries:
  # From autogpt template
  - 'http.title:"Auto-GPT"'
  - 'http.title:"AutoGPT"'

  # From langchain template
  - 'http.html:"langchain" http.html:"agent"'

  # Custom additions
  - 'http.title:"CrewAI"'
```

### Programmatic Template Creation

```python
from src.core.query_manager import QueryManager

qm = QueryManager()

# Add a new template programmatically
qm.templates['my_new_template'] = [
    'http.title:"My Target"',
    'http.html:"keyword"'
]

# Save to file
qm.save_template('my_new_template')
```

---

## Summary Checklist

Before using your custom template:

- [ ] File is in `queries/` directory
- [ ] File extension is `.yaml` or `.yml`
- [ ] `name`, `description`, and `queries` fields are present
- [ ] YAML syntax is valid (validated with linter)
- [ ] Queries are properly quoted
- [ ] Tested queries on Shodan.io first
- [ ] Template appears in `python -m src.main templates` output
- [ ] Tags are meaningful for organization

---

**Happy Hunting! 🎯**

*For questions or contributions, see the main project documentation.*

