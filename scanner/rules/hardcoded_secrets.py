 # scanner/rules/hardcoded_secrets.py
import re
from scanner.rules.base_rule import VulnerabilityRule
from scanner.vulnerability import Vulnerability

class HardcodedSecretRule(VulnerabilityRule):
    def __init__(self):
        super().__init__(
            vuln_type="Hardcoded Secret",
            cwe_id="CWE-798",
            description="API key, password, or token hardcoded in source."
        )
        self.patterns = [
            (r'(?:api[_-]?key|apikey|API_KEY)\s*[:=]\s*["\']([A-Za-z0-9_\-]{10,})["\']', 'API Key'),
            (r'(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']{4,})["\']', 'Password'),
            (r'(?:secret|token)\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{10,})["\']', 'Secret/Token'),
            (r'(sk_[a-zA-Z0-9]{24,})', 'Stripe Secret Key'),
            (r'(ghp_[a-zA-Z0-9]{36})', 'GitHub Personal Access Token'),
            (r'(AKIA[A-Z0-9]{16})', 'AWS Access Key'),
        ]
        self.placeholder_words = {'example', 'demo', 'test', 'sample', 'placeholder', 'dummy', 'your-', 'xxx'}

    def detect(self, ast, file_path, code_lines):
        vulns = []
        for lineno, line in enumerate(code_lines, start=1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*') or stripped.startswith('#') or stripped.startswith('<!--'):
                continue
            code_part = line
            if '//' in code_part:
                code_part = code_part[:code_part.index('//')]
            code_part = re.sub(r'/\*.*?\*/', '', code_part)

            lower_line = code_part.lower()
            if any(word in lower_line for word in self.placeholder_words):
                continue

            for pattern, secret_type in self.patterns:
                match = re.search(pattern, code_part, re.IGNORECASE)
                if match:
                    secret_value = match.group(1)
                    if secret_value.lower() in self.placeholder_words:
                        continue
                    score = self._compute_score(secret_value)
                    if score >= 50:
                        var_name = match.group(1) if len(match.groups()) >= 1 else 'unknown'
                        desc = f"Hardcoded {secret_type} found. The variable '{var_name}' appears to contain a sensitive value."
                        remed = f"Remove this hardcoded {secret_type} and load it from an environment variable."
                        vulns.append(Vulnerability(
                            vuln_type=self.vuln_type,
                            cwe_id=self.cwe_id,
                            file_path=file_path,
                            line_number=lineno,
                            code_snippet=line.strip(),
                            description=desc,
                            remediation=remed,
                            confidence_score=score
                        ))
                    break
        return vulns

    def _compute_score(self, value):
        length = len(value)
        if length >= 20 and self._is_high_entropy(value):
            return 90
        elif length >= 10:
            return 60
        else:
            return 30   # will be filtered out

    def _is_high_entropy(self, s):
        digits = sum(c.isdigit() for c in s)
        upper = sum(c.isupper() for c in s)
        lower = sum(c.islower() for c in s)
        return digits >= 2 and upper >= 2 and lower >= 2