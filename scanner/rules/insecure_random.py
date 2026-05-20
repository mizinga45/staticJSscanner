# scanner/rules/insecure_random.py
import re
from scanner.rules.base_rule import VulnerabilityRule
from scanner.vulnerability import Vulnerability


class InsecureRandomRule(VulnerabilityRule):
    """Detects Math.random() used in security-sensitive contexts."""

    def __init__(self):
        super().__init__(
            vuln_type="Insecure Randomness",
            cwe_id="CWE-330",
            description="Math.random() used for security-sensitive purposes."
        )
        # Context keywords that suggest security use
        self.security_contexts = [
            'token', 'secret', 'key', 'password', 'hash', 'salt',
            'session', 'csrf', 'nonce', 'otp', 'auth', 'id',
            'uuid', 'random_id', 'generateId', 'createToken'
        ]

    def detect(self, ast, file_path, code_lines, **kwargs):
        vulns = []
        for lineno, line in enumerate(code_lines, start=1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('*'):
                continue

            if 'Math.random' in line:
                # Check if it's in a security context
                lower_line = line.lower()
                # Check surrounding lines too
                context_start = max(0, lineno - 3)
                context_end = min(len(code_lines), lineno + 1)
                context = ' '.join(code_lines[context_start:context_end]).lower()

                for keyword in self.security_contexts:
                    if keyword in context:
                        vulns.append(Vulnerability(
                            vuln_type=self.vuln_type,
                            cwe_id=self.cwe_id,
                            file_path=file_path,
                            line_number=lineno,
                            code_snippet=stripped[:150],
                            description=f"Math.random() is not cryptographically secure and is used near security-related code ('{keyword}').",
                            remediation="Use crypto.randomBytes() (Node.js) or crypto.getRandomValues() (browser) for security-sensitive random values.",
                            confidence_score=75,
                            severity='Medium'
                        ))
                        break
        return vulns
