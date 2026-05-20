# SecScan JS

**A Static Security Vulnerability Scanner for JavaScript Source Code**

SecScan JS is a web-based static analysis tool that detects security vulnerabilities in JavaScript source code without executing it. It uses AST-based taint analysis to track user-controlled data from input sources to dangerous sinks, mapping each finding to its CWE identifier with severity classification and actionable remediation guidance.

---

## Table of Contents

- [Features](#features)
- [Vulnerability Types Detected](#vulnerability-types-detected)
- [Technologies Used](#technologies-used)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Running the Application](#running-the-application)
- [Usage Guide](#usage-guide)
- [Example Scan](#example-scan)
- [Project Structure](#project-structure)
- [Testing](#testing)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)
- [Team](#team)
- [License](#license)

---

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
- **Background Scanning** — Scans run asynchronously; navigate freely and get notified when done
- **Real-time Notifications** — Sound + browser notification when scan completes
- **False Positive Reduction** — Skips libraries, detects sanitizers, context-aware analysis
- **Obfuscation Detection** — Warns when code is minified/obfuscated
- **Syntax Highlighting** — Dangerous code patterns highlighted in red in results
- **Severity Classification** — Critical, High, Medium ratings for prioritization

---

## Vulnerability Types Detected

| # | Vulnerability | CWE ID | Severity | What It Detects |
|---|---|---|---|---|
| 1 | SQL Injection | CWE-89 | Critical | String concatenation or template literals in SQL queries |
| 2 | Command Injection | CWE-78 | Critical | User input passed to exec(), spawn(), system() |
| 3 | Path Traversal | CWE-22 | Critical | User input in fs.readFile(), writeFile() operations |
| 4 | Cross-Site Scripting (XSS) | CWE-79 | High | User input in innerHTML, document.write() |
| 5 | Insecure eval() | CWE-95 | High | Dynamic/user input passed to eval() |
| 6 | Prototype Pollution | CWE-1321 | High | User-controlled key in object property assignment |
| 7 | Angular Security Bypass | CWE-79 | High | bypassSecurityTrust* with user input |
| 8 | Hardcoded Secrets | CWE-798 | Medium | API keys, passwords, tokens in source code |
| 9 | Open Redirect | CWE-601 | Medium | User input in redirect/location.href |
| 10 | ReDoS | CWE-1333 | Medium | Regex with nested quantifiers (catastrophic backtracking) |
| 11 | Insecure Randomness | CWE-330 | Medium | Math.random() used in security contexts |

---

## Technologies Used

### Frontend

| Technology | Purpose |
|---|---|
| HTML5 | Page structure and semantic markup |
| CSS3 (Custom) | Dark cybersecurity theme, animations, responsive design |
| JavaScript (Vanilla) | Typing animations, drag-and-drop, progress bar, notifications |
| Jinja2 | Server-side template engine |
| Google Fonts | Inter (UI) + JetBrains Mono (code) |

### Backend

| Technology | Purpose |
|---|---|
| Python 3.10+ | Core programming language |
| Flask 3.x | Web framework |
| Flask-Login | User authentication and sessions |
| Flask-Bcrypt | Password hashing |
| Flask-SQLAlchemy | Database ORM |
| Flask-WTF / WTForms | Form handling and validation |
| SQLite | Database (users, scan results) |
| WeasyPrint | PDF report generation |

### Scanner Engine

| Technology | Purpose |
|---|---|
| Acorn (Node.js) | JavaScript AST parser (ECMAScript 2022) |
| Custom Rule Engine | Taint analysis and vulnerability detection |
| BeautifulSoup4 | HTML/PHP parsing for JS extraction |
| Requests | HTTP fetching for URL scanning |
| JSBeautifier | Deobfuscation of minified code |

### Development & Testing

| Technology | Purpose |
|---|---|
| Git & GitHub | Version control |
| pytest | Testing framework |
| Node.js / npm | Acorn parser runtime |

---

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

**How it works:**

1. User provides input (file upload, URL, or folder path)
2. **Input Handler** reads the file or fetches the URL content
3. **Code Extractor** isolates JavaScript from HTML/PHP (strips `<script>` tags)
4. **Parser** converts JavaScript into an Abstract Syntax Tree (AST) using Acorn
5. **Core Engine** runs 11 detection rules with taint analysis on the AST
6. **CWE Mapper** enriches each finding with CWE ID, description, and remediation
7. **Report Generator** produces the final output (web view + downloadable PDF/HTML/JSON)

---

## Prerequisites

| Software | Minimum Version | Check Command |
|---|---|---|
| Python | 3.10+ | `python3 --version` |
| Node.js | 16+ | `node --version` |
| npm | 8+ | `npm --version` |
| Git | any | `git --version` |

### Installing Prerequisites

**Ubuntu / Debian:**
```bash
sudo apt update
sudo apt install python3 python3-venv python3-pip nodejs npm git
```

**macOS (Homebrew):**
```bash
brew install python node git
```

**Windows:**
- Python: https://python.org (check "Add to PATH" during install)
- Node.js: https://nodejs.org (LTS version)
- Git: https://git-scm.com

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/mizinga45/staticJSscanner.git
cd staticJSscanner

# 2. Create Python virtual environment
python3 -m venv venv

# 3. Activate the virtual environment
source venv/bin/activate        # Linux / macOS
# venv\Scripts\activate         # Windows

# 4. Install Python dependencies
pip install -r requirements.txt

# 5. Install Node.js dependency (Acorn parser)
cd scanner
npm install
cd ..
```

---

## Running the Application

```bash
# Make sure virtual environment is activated
source venv/bin/activate

# Start the server
python app.py
```

The application starts at: **http://localhost:5000**

---

## Usage Guide

### 1. Create an Account
- Go to http://localhost:5000
- Click "Create Account"
- Fill in your name, username, email, and password

### 2. Login
- Use your email/username and password to sign in

### 3. Scan JavaScript Code
You have three options:

**Option A: Upload a File**
- Click "Upload" and select a `.js`, `.html`, `.php`, or `.txt` file
- Drag and drop is also supported

**Option B: Enter a URL**
- Paste any URL (e.g., `https://example.com`)
- The scanner will fetch the page and all linked `.js` files automatically

**Option C: Scan a Folder**
- Enter a local folder path (e.g., `/home/user/project/src`)
- All `.js`, `.html`, `.php`, `.txt` files will be scanned recursively

### 4. View Results
- Vulnerabilities are grouped by file with severity badges
- Each finding shows: CWE ID, line number, code snippet (with red highlighting), description, and how to fix
- Extracted JavaScript URLs are listed with status (⚠️ has issues / ✓ clean)

### 5. Download Report
- Click JSON, HTML, or PDF to download a formatted report
- PDF is A4-formatted and suitable for printing or sharing

### 6. Scan History
- All scans are saved automatically
- View any past scan from the History page
- Delete scans you no longer need

---

## Example Scan

Create a file called `vulnerable.js`:

```javascript
// SQL Injection - user input concatenated into query
var userId = req.params.id;
var query = "SELECT * FROM users WHERE id = " + userId;
db.query(query);

// XSS - user input assigned to innerHTML
var input = location.search;
document.getElementById("output").innerHTML = input;

// Command Injection - user input passed to exec
var cmd = req.query.cmd;
exec(cmd);

// Hardcoded Secret
const API_KEY = "AKIA1234567890ABCDEF";

// Insecure eval
var data = location.hash;
eval(data);
```

Upload this file and the scanner will detect:
- 🔴 **Critical:** SQL Injection (CWE-89) at line 3
- 🔴 **Critical:** Command Injection (CWE-78) at line 12
- 🟠 **High:** XSS (CWE-79) at line 8
- 🟠 **High:** Insecure eval (CWE-95) at line 17
- 🟡 **Medium:** Hardcoded Secret (CWE-798) at line 14

---

## Project Structure

```
staticJSscanner/
├── app.py                      # Flask app entry point + Jinja filters
├── models.py                   # Database models (User, ScanResult)
├── requirements.txt            # Python dependencies (pinned versions)
├── .gitignore                  # Git ignore rules
├── LICENSE                     # MIT License
├── README.md                   # This file
│
├── auth/                       # Authentication module
│   ├── __init__.py
│   ├── routes.py               # Login, register, logout, profile routes
│   └── forms.py                # WTForms (RegistrationForm, LoginForm)
│
├── web/                        # Web interface module
│   ├── __init__.py
│   ├── routes.py               # Dashboard, async scan, history, download
│   └── forms.py                # ScanForm (file upload, URL, folder)
│
├── scanner/                    # Core scanning engine
│   ├── __init__.py
│   ├── core_engine.py          # Main engine: orchestrates rules + taint
│   ├── parser.py               # AST parser (calls Acorn via Node.js)
│   ├── parser_script.js        # Node.js script that runs Acorn
│   ├── package.json            # Node.js dependency (acorn)
│   ├── input_handler.py        # Accepts file/URL/folder input
│   ├── code_extractor.py       # Extracts JS from HTML/PHP
│   ├── web_fetcher.py          # Fetches URLs and linked .js files
│   ├── vulnerability.py        # Vulnerability data class
│   ├── cwe_mapper.py           # Maps vuln types to CWE IDs
│   ├── report_generator.py     # Generates summary + dict output
│   ├── interprocedural.py      # Cross-function taint propagation
│   ├── context_analyzer.py     # Context-aware false positive reduction
│   └── rules/                  # One file per vulnerability type
│       ├── __init__.py
│       ├── base_rule.py        # Abstract base class
│       ├── sql_injection.py    # CWE-89: SQL Injection
│       ├── xss.py              # CWE-79: Cross-Site Scripting
│       ├── command_injection.py # CWE-78: Command Injection
│       ├── path_traversal.py   # CWE-22: Path Traversal
│       ├── prototype_pollution.py # CWE-1321: Prototype Pollution
│       ├── eval_injection.py   # CWE-95: Insecure eval()
│       ├── hardcoded_secrets.py # CWE-798: Hardcoded Secrets
│       ├── open_redirect.py    # CWE-601: Open Redirect
│       ├── regex_dos.py        # CWE-1333: ReDoS
│       ├── insecure_random.py  # CWE-330: Insecure Randomness
│       ├── angular_bypass.py   # CWE-79: Angular Bypass
│       └── express_handler.py  # Express route taint pre-processor
│
├── data/                       # Static data
│   └── cwe_database.json       # CWE descriptions and remediation text
│
├── templates/                  # Jinja2 HTML templates
│   ├── base.html               # Base layout (navbar, footer, notifications)
│   ├── landing.html            # Public landing page
│   ├── login.html              # Login page
│   ├── register.html           # Registration page
│   ├── index.html              # Scanner dashboard (after login)
│   ├── scan_result.html        # Vulnerability results display
│   ├── history.html            # Scan history page
│   ├── profile.html            # User profile + stats
│   ├── error.html              # Error page
│   └── download_report.html    # PDF/HTML report template
│
├── static/                     # Static assets
│   ├── css/style.css           # Full custom CSS (dark theme, 700+ lines)
│   └── images/hero-bg.svg      # Shield graphic for landing page
│
├── tests/                      # Test suite
│   ├── test_scanner.py         # Automated evaluation tests
│   └── test_samples/           # Sample JS files for testing
│       ├── sql_injection_basic.js
│       ├── xss_innerHTML.js
│       ├── command_injection_exec.js
│       ├── hardcoded_secret.js
│       ├── eval_user_input.js
│       └── safe_parameterized_query.js
│
└── uploads/                    # Uploaded files (gitignored)
    └── .gitkeep
```

---

## Testing

Run the automated test suite:

```bash
source venv/bin/activate
python tests/test_scanner.py
```

Expected output:
```
Detection Rate (Recall):  5/5 = 100%
False Positive Free:      Yes
Performance (<2s/file):   Yes
Error Handling:           Robust

✅ ALL TESTS PASSED
```

---

## Configuration

| Setting | Location | Default |
|---|---|---|
| Secret Key | `app.py` or `SECRET_KEY` env var | Fixed string (change in production) |
| Database | `scanner.db` in project root | SQLite |
| Upload Folder | `uploads/` | Auto-created |
| Debug Mode | `app.py` last line | `debug=True` |

For production deployment, set the `SECRET_KEY` environment variable:
```bash
export SECRET_KEY="your-random-secret-key-here"
python app.py
```

---

## Troubleshooting

| Problem | Solution |
|---|---|
| `ModuleNotFoundError` | Activate venv: `source venv/bin/activate` |
| `node: command not found` | Install Node.js: `sudo apt install nodejs npm` |
| Parser errors on scan | Run `cd scanner && npm install` |
| WeasyPrint PDF fails | Install: `sudo apt install libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0` |
| Port 5000 already in use | Kill existing process or change port in `app.py` |
| "Invalid credentials" after restart | Delete `scanner.db` and re-register (one-time fix) |
| Scan takes too long on URL | Large sites with many JS files take longer; try specific .js URLs |

---

## Team

**University of Dodoma — College of Informatics and Virtual Education**  
**Course:** BSc. Cyber Security and Digital Forensics Engineering (Year 4)  
**Academic Year:** 2025/2026  
**Supervisor:** Mr. Bakii

| Name | Registration Number |
|------|---------------------|
| Brian Kilawe | T22-03-12950 |
| Kenneth Maina | T22-03-15010 |
| Radhia Kijida | T22-03-12951 |
| Princess Michael | T22-03-08079 |
| Walter Aborogast | T22-03-09382 |

---

## License

MIT License — See [LICENSE](LICENSE) for details.
