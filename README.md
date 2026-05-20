# SecScan JS — Static Security Vulnerability Scanner for JavaScript Source Code

A web-based static analysis tool that detects security vulnerabilities in JavaScript source code without executing it. Built with Python (Flask) and uses AST-based taint analysis to identify real security issues.

## Features

- **AST-Based Analysis** — Parses JavaScript into Abstract Syntax Trees using Acorn for deep structural analysis
- **Taint Tracking** — Tracks user-controlled data flow from sources (e.g., `req.query`, `location.search`) to dangerous sinks
- **Inter-procedural Analysis** — Follows tainted data across function calls
- **CWE Mapping** — Every vulnerability is mapped to its CWE ID with description and remediation
- **Multiple Input Methods** — Upload files, scan URLs (fetches linked JS), or scan entire folders
- **Report Export** — Download reports in JSON, HTML, or PDF format
- **User Authentication** — Login/register system with scan history tracking

## Vulnerability Types Detected

| Type | CWE ID | Description |
|------|--------|-------------|
| SQL Injection | CWE-89 | User input concatenated into SQL queries |
| Cross-Site Scripting (XSS) | CWE-79 | User input in innerHTML/document.write |
| Command Injection | CWE-78 | User input passed to exec/spawn |
| Hardcoded Secrets | CWE-798 | API keys, passwords, tokens in source |
| Insecure eval() | CWE-95 | Dynamic input passed to eval() |
| Angular Security Bypass | CWE-79 | DomSanitizer bypass with user input |

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Web Interface (Flask)                  │
├─────────────────────────────────────────────────────────┤
│  Input Handler  →  Code Extractor  →  Parser (Acorn)    │
│                                           ↓              │
│  Report Generator  ←  CWE Mapper  ←  Core Engine        │
│                                     (Taint Analysis)     │
│                                     (Rule Matching)      │
│                                     (Inter-procedural)   │
└─────────────────────────────────────────────────────────┘
```

## Setup

```bash
# Clone the repository
git clone https://github.com/mizinga45/staticJSscanner.git
cd staticJSscanner

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Install Node.js dependency (for AST parsing)
cd scanner && npm install && cd ..

# Run the application
python app.py
```

The application will be available at `http://localhost:5000`

## Project Structure

```
├── app.py                  # Flask application entry point
├── models.py               # Database models (User, ScanHistory)
├── requirements.txt        # Python dependencies
├── auth/                   # Authentication module
│   ├── routes.py           # Login, register, logout, profile
│   └── forms.py           # WTForms for auth
├── web/                    # Web interface module
│   ├── routes.py           # Scanner dashboard, scan, download
│   └── forms.py           # Scan input form
├── scanner/                # Core scanning engine
│   ├── core_engine.py      # Main analysis engine with taint tracking
│   ├── parser.py           # JavaScript AST parser (uses Acorn)
│   ├── parser_script.js    # Node.js Acorn parser script
│   ├── input_handler.py    # File/URL/folder input handling
│   ├── code_extractor.py   # Extract JS from HTML/PHP files
│   ├── web_fetcher.py      # Fetch remote URLs and linked JS
│   ├── vulnerability.py    # Vulnerability data class
│   ├── cwe_mapper.py       # CWE ID mapping
│   ├── report_generator.py # Report generation
│   ├── interprocedural.py  # Cross-function taint analysis
│   ├── context_analyzer.py # Context-aware analysis
│   └── rules/              # Detection rules
│       ├── base_rule.py
│       ├── sql_injection.py
│       ├── xss.py
│       ├── command_injection.py
│       ├── hardcoded_secrets.py
│       ├── eval_injection.py
│       ├── angular_bypass.py
│       └── express_handler.py
├── data/                   # Static data files
│   ├── cwe_database.json
│   └── vulnerability_patterns.json
├── templates/              # Jinja2 HTML templates
├── static/                 # CSS, JS, images
└── uploads/                # Uploaded files for scanning
```

## Technologies

- **Backend:** Python 3, Flask
- **Frontend:** HTML5, CSS3, Jinja2
- **Database:** SQLite (via SQLAlchemy)
- **JS Parsing:** Acorn (Node.js)
- **Analysis:** Custom rule-based taint analysis engine

## Group 16 — University of Dodoma

| Name | Registration |
|------|-------------|
| Brian Kilawe | T22-03-12950 |
| Kenneth Maina | T22-03-15010 |
| Radhia Kijida | T22-03-12951 |
| Princess Michael | T22-03-08079 |
| Walter Aborogast | T22-03-09382 |
