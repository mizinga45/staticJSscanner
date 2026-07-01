# scanner/subtechniques.py
"""
Sub-techniques for each vulnerability type.
Displayed in scan results showing which were tested and which were found.
"""

ALL_SUBTECHNIQUES = {
    'SQL Injection': [
        'String Concatenation',
        'Template Literal Injection',
        'Boolean-based Blind',
        'Error-based',
        'Time-based Blind',
        'Union-based',
    ],
    'Cross-Site Scripting (XSS)': [
        'Reflected XSS via innerHTML',
        'Reflected XSS via document.write',
        'DOM-based XSS via outerHTML',
        'React dangerouslySetInnerHTML',
    ],
    'Command Injection': [
        'exec() with User Input',
        'execSync() with User Input',
        'spawn() with User Input',
        'execFile() with User Input',
    ],
    'Path Traversal': [
        'readFile() Traversal',
        'readFileSync() Traversal',
        'writeFile() Traversal',
        'createReadStream() Traversal',
    ],
    'Prototype Pollution': [
        'obj[userKey] Property Injection',
        '__proto__ Manipulation',
        'Constructor Override',
    ],
    'Insecure Use of eval()': [
        'Direct eval() of User Input',
        'setTimeout() Code Injection',
        'setInterval() Code Injection',
    ],
    'Hardcoded Secret': [
        'API Key Exposed',
        'AWS Access Key (AKIA...)',
        'GitHub Personal Access Token (ghp_...)',
        'Stripe Secret Key (sk_live...)',
        'Slack Token (xox...)',
        'Hardcoded Password',
        'Auth/Session Token',
    ],
    'Open Redirect': [
        'res.redirect() with User Input',
        'location.href Assignment',
        'window.location.replace()',
        'location.assign()',
    ],
    'Regular Expression DoS (ReDoS)': [
        'Nested Quantifier (a+)+',
        'Overlapping Alternation',
        'Exponential Backtracking Pattern',
    ],
    'Insecure Randomness': [
        'Math.random() for Token',
        'Math.random() for Session ID',
        'Math.random() for Secret Key',
        'Math.random() in Security Function',
    ],
    'Angular Security Bypass': [
        'bypassSecurityTrustHtml()',
        'bypassSecurityTrustScript()',
        'bypassSecurityTrustStyle()',
        'bypassSecurityTrustUrl()',
        'bypassSecurityTrustResourceUrl()',
    ],
    'Insecure Deserialization': [
        'unserialize() with User Input',
        'deserialize() with User Input',
        'Node-serialize() Exploitation',
    ],
    'Server-Side Request Forgery (SSRF)': [
        'fetch() with User-Controlled URL',
        'axios() with User-Controlled URL',
        'http.get() with User-Controlled URL',
        'request() with User-Controlled URL',
    ],
    'Obfuscation Warning': [
        'Minified/Obfuscated Code Detected',
    ],
}
