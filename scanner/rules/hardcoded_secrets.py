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
            (r'(?:api[_-]?key|apikey|API_KEY)\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})["\']', 'API Key'),
            (r'(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']{6,})["\']', 'Password'),
            (r'(?:secret[_-]?key|SECRET_KEY)\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{12,})["\']', 'Secret Key'),
            (r'(?:auth[_-]?token|access[_-]?token)\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{12,})["\']', 'Auth Token'),
            (r'(sk_live_[a-zA-Z0-9]{24,})', 'Stripe Live Key'),
            (r'(sk_test_[a-zA-Z0-9]{24,})', 'Stripe Test Key'),
            (r'(ghp_[a-zA-Z0-9]{36})', 'GitHub Personal Access Token'),
            (r'(AKIA[A-Z0-9]{16})', 'AWS Access Key'),
            (r'(xox[bpas]-[a-zA-Z0-9\-]{10,})', 'Slack Token'),
        ]
        # Words that indicate placeholder/example values
        self.placeholder_words = {
            'example', 'demo', 'test', 'sample', 'placeholder', 'dummy',
            'your-', 'xxx', 'changeme', 'todo', 'fixme', 'replace',
            'insert', 'enter', 'put_your', 'my_', 'fake', 'mock'
        }
        # Context that indicates it's not a real secret
        self.safe_contexts = [
            'process.env', 'os.environ', 'config.get', 'getenv',
            'Environment', 'dotenv', '.env'
        ]

    def detect(self, ast, file_path, code_lines, **kwargs):
        vulns = []
        for lineno, line in enumerate(code_lines, start=1):
            stripped = line.strip()
            # Skip comments
            if stripped.startswith(('//','/*','*','#','<!--','"""',"'''")):
                continue

            # Remove inline comments
            code_part = line
            if '//' in code_part:
                code_part = code_part[:code_part.index('//')]

            lower = code_part.lower()

            # Skip placeholder values
            if any(word in lower for word in self.placeholder_words):
                continue

            # Skip if it's loading from environment
            if any(ctx in code_part for ctx in self.safe_contexts):
                continue

            for pattern, secret_type in self.patterns:
                match = re.search(pattern, code_part, re.IGNORECASE)
                if match:
                    secret_value = match.group(1)
                    # Additional false positive checks
                    if len(secret_value) < 8:
                        continue
                    if secret_value.lower() in self.placeholder_words:
                        continue
                    # Check entropy
                    score = self._compute_score(secret_value, secret_type)
                    if score >= 50:
                        vulns.append(Vulnerability(
                            vuln_type=self.vuln_type,
                            cwe_id=self.cwe_id,
                            file_path=file_path,
                            line_number=lineno,
                            code_snippet=stripped[:150],
                            description=f"Hardcoded {secret_type} detected in source code. This is a critical security risk if deployed.",
                            remediation=f"Remove this {secret_type} from source code. Use environment variables (process.env.{secret_type.upper().replace(' ','_')}) or a secrets manager instead.",
                            confidence_score=score,
                            severity='Critical' if secret_type in ('AWS Access Key', 'Stripe Live Key', 'GitHub Personal Access Token') else 'Medium'
                        ))
                    break  # One match per line
        return vulns

    def _compute_score(self, value, secret_type):
        # Known patterns get high confidence
        if secret_type in ('AWS Access Key', 'Stripe Live Key', 'GitHub Personal Access Token', 'Slack Token'):
            return 95
        # High entropy + long = likely real
        if len(value) >= 20 and self._has_mixed_chars(value):
            return 85
        if len(value) >= 12:
            return 65
        return 40

    def _has_mixed_chars(self, s):
        return (sum(c.isdigit() for c in s) >= 2 and
                sum(c.isupper() for c in s) >= 2 and
                sum(c.islower() for c in s) >= 2)
