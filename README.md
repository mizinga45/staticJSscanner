# SecScan JS — Static Security Vulnerability Scanner for JavaScript Source Code

A web-based static analysis tool that detects security vulnerabilities in JavaScript source code without executing it. Built with Python (Flask) backend and a modern dark-themed frontend, it uses AST-based taint analysis to identify real security issues and map them to CWE identifiers.

## Features

- **11 Vulnerability Types** — Comprehensive coverage of JavaScript security weaknesses
- **AST-Based Taint Analysis** — Tracks user-controlled data flow from sources to dangerous sinks
- **Inter-procedural Analysis** — Follows tainted data across function calls
- **CWE Mapping** — Every vulnerability mapped to its CWE ID with severity and remediation
- **Multiple Input Methods** — Upload files, scan URLs (fetches linked JS), or scan entire folders
- **JS Extraction** — Automatically extracts JavaScript from HTML and PHP files
- **Report Export** — Download reports in JSON, HTML, or PDF format
- **Scan History** — All scans saved with full results, viewable anytime
- **User Authentication** — Login/register system with profile and scan history
- **False Positive Reduction** — Skips libraries, detects sanitizers, context-aware analysis
- **Obfuscation Detection** — Warns when code is minified/obfuscated

## Vulnerability Types Detected

| # | Vulnerability | CWE ID | Severity | Detection Method |
|---|---|---|---|---|
| 1 | SQL Injection | CWE-89 | Critical | Taint → string concat + template literals into SQL |
| 2 | Command Injection | CWE-78 | Critical | Taint → exec/spawn/system calls |
| 3 | Path Traversal | CWE-22 | Critical | Taint → fs.readFile/writeFile operations |
| 4 | Cross-Site Scripting (XSS) | CWE-79 | High | Taint → innerHTML/document.write |
| 5 | Insecure eval() | CWE-95 | High | Taint → eval() with dynamic input |
| 6 | Prototype Pollution | CWE-1321 | High | Taint → obj[userKey] = value |
| 7 | Angular Security Bypass | CWE-79 | High | Taint → bypassSecurityTrust* methods |
| 8 | Hardcoded Secrets | CWE-798 | Medium | Regex + entropy (API keys, tokens, passwords) |
| 9 | Open Redirect | CWE-601 | Medium | Taint → redirect/location.href |
| 10 | ReDoS | CWE-1333 | Medium | Regex pattern analysis (nested quantifiers) |
| 11 | Insecure Randomness | CWE-330 | Medium | Math.random() in security contexts |

## Technologies Used

### Frontend
| Technology | Purpose |
|---|---|
| HTML5 | Page structure and semantic markup |
| CSS3 (Custom) | Dark cybersecurity theme, animations, responsive design |
| JavaScript (Vanilla) | Typing animations, drag-and-drop upload, UI interactions |
| Jinja2 | Server-side template engine (Flask integration) |
| Google Fonts (Inter, JetBrains Mono) | Typography |

### Backend
| Technology | Purpose |
|---|---|
| Python 3.10+ | Core programming language |
| Flask 3.x | Web framework (routes, blueprints, sessions) |
| Flask-Login | User authentication and session management |
| Flask-Bcrypt | Password hashing (bcrypt) |
| Flask-SQLAlchemy | ORM for database operations |
| Flask-WTF / WTForms | Form handling and validation |
| SQLite | Database (users, scan history, results) |
| WeasyPrint | PDF report generation |

### Scanner Engine
| Technology | Purpose |
|---|---|
| Acorn (Node.js) | JavaScript AST parser (ECMAScript 2022) |
| Custom Python Rule Engine | Taint analysis and vulnerability detection |
| BeautifulSoup4 | HTML/PHP parsing for JS extraction |
| Requests | HTTP fetching for URL scanning |
| JSBeautifier | Deobfuscation of minified code |
| JSON | CWE database and report export |

### Development & Testing
| Technology | Purpose |
|---|---|
| Git & GitHub | Version control and collaboration |
| pytest | Unit and integration testing |
| Node.js / npm | Acorn parser dependency |

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   Web Interface (Flask)                       │
│   Landing → Login/Register → Dashboard → Scan → Results      │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Input Handler ──→ Code Extractor ──→ Parser (Acorn AST)    │
│  (file/URL/folder)  (HTML/PHP strip)    (Node.js subprocess) │
│                                              │               │
│                                              ▼               │
│  Report Generator ←── CWE Mapper ←── Core Analysis Engine   │
│  (JSON/HTML/PDF)      (CWE IDs)       ├─ SQL Injection      │
│                                        ├─ XSS               │
│                                        ├─ Command Injection  │
│                                        ├─ Path Traversal     │
│                                        ├─ Prototype Pollution│
│                                        ├─ eval() Injection   │
│                                        ├─ Hardcoded Secrets  │
│                                        ├─ Open Redirect      │
│                                        ├─ ReDoS             │
│                                        ├─ Insecure Random    │
│                                        └─ Angular Bypass     │
└─────────────────────────────────────────────────────────────┘
```

## Setup & Installation

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

## Usage

1. **Register** an account at `/auth/register`
2. **Login** at `/auth/login`
3. **Scan** by uploading a .js/.html/.php file, entering a URL, or providing a folder path
4. **View Results** — vulnerabilities grouped by file with severity, CWE, line number, and fix guidance
5. **Download Report** — export as JSON, HTML, or PDF
6. **History** — view all past scans and their results at `/history`

## Project Structure

```
├── app.py                      # Flask application entry point
├── models.py                   # Database models (User, ScanResult)
├── requirements.txt            # Python dependencies
├── auth/                       # Authentication module
│   ├── routes.py               # Login, register, logout, profile
│   └── forms.py               # WTForms for auth
├── web/                        # Web interface module
│   ├── routes.py               # Dashboard, scan, history, download
│   └── forms.py               # Scan input form
├── scanner/                    # Core scanning engine
│   ├── core_engine.py          # Main analysis engine with taint tracking
│   ├── parser.py               # JavaScript AST parser (Acorn)
│   ├── parser_script.js        # Node.js Acorn parser script
│   ├── input_handler.py        # File/URL/folder input handling
│   ├── code_extractor.py       # Extract JS from HTML/PHP files
│   ├── web_fetcher.py          # Fetch remote URLs and linked JS
│   ├── vulnerability.py        # Vulnerability data class
│   ├── cwe_mapper.py           # CWE ID mapping and descriptions
│   ├── report_generator.py     # Report generation (summary + export)
│   ├── interprocedural.py      # Cross-function taint analysis
│   ├── context_analyzer.py     # Context-aware false positive reduction
│   └── rules/                  # Detection rules (one per vulnerability)
│       ├── base_rule.py        # Abstract base class
│       ├── sql_injection.py    # CWE-89
│       ├── xss.py              # CWE-79
│       ├── command_injection.py # CWE-78
│       ├── path_traversal.py   # CWE-22
│       ├── prototype_pollution.py # CWE-1321
│       ├── eval_injection.py   # CWE-95
│       ├── hardcoded_secrets.py # CWE-798
│       ├── open_redirect.py    # CWE-601
│       ├── regex_dos.py        # CWE-1333
│       ├── insecure_random.py  # CWE-330
│       ├── angular_bypass.py   # CWE-79
│       └── express_handler.py  # Express route taint pre-processor
├── data/                       # Static data files
│   ├── cwe_database.json       # CWE descriptions and remediation
│   └── vulnerability_patterns.json
├── templates/                  # Jinja2 HTML templates
│   ├── base.html               # Base layout (navbar, footer)
│   ├── landing.html            # Public landing page
│   ├── login.html              # Login page
│   ├── register.html           # Registration page
│   ├── index.html              # Scanner dashboard
│   ├── scan_result.html        # Vulnerability results display
│   ├── history.html            # Scan history page
│   ├── profile.html            # User profile
│   ├── error.html              # Error page
│   └── download_report.html    # Styled report for export
├── static/                     # Static assets
│   ├── css/style.css           # Full custom CSS (dark theme)
│   └── images/hero-bg.svg      # Hero graphic
├── tests/                      # Test suite
│   ├── test_scanner.py         # Evaluation test script
│   └── test_samples/           # Sample vulnerable + safe JS files
├── diagrams/                   # UML design diagrams
└── uploads/                    # Uploaded files for scanning
```

## Test Results

```
Detection Rate (Recall):  12/12 = 100%
False Positive Rate:      0%
Average Scan Time:        61ms per file
Error Handling:           Graceful (no crashes on malformed input)
```

## Group 16 — University of Dodoma

**Course:** BSc. Cyber Security and Digital Forensics Engineering (Year 4)  
**Academic Year:** 2025/2026  
**Supervisor:** Mr. Bakii

| Name | Registration |
|------|-------------|
| Brian Kilawe | T22-03-12950 |
| Kenneth Maina | T22-03-15010 |
| Radhia Kijida | T22-03-12951 |
| Princess Michael | T22-03-08079 |
| Walter Aborogast | T22-03-09382 |

## License

MIT License — See [LICENSE](LICENSE) for details.
