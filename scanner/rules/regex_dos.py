# scanner/rules/regex_dos.py
import re
from scanner.rules.base_rule import VulnerabilityRule
from scanner.vulnerability import Vulnerability


class RegexDosRule(VulnerabilityRule):
    """Detects potentially catastrophic regular expressions (ReDoS)."""

    def __init__(self):
        super().__init__(
            vuln_type="Regular Expression DoS (ReDoS)",
            cwe_id="CWE-1333",
            description="Potentially catastrophic regex that can cause denial of service."
        )
        # Patterns that indicate evil regex: nested quantifiers, overlapping alternation
        self.evil_patterns = [
            r'\([^)]*[+*][^)]*\)[+*]',       # (a+)+ or (a*)*
            r'\([^)]*\|[^)]*\)[+*]',          # (a|a)+ overlapping alternation with quantifier
            r'\.\*[^?].*\.\*',                 # .* ... .* (backtracking)
            r'\([^)]+[+*]\)\{',               # (a+){n}
        ]

    def detect(self, ast, file_path, code_lines, **kwargs):
        vulns = []
        for lineno, line in enumerate(code_lines, start=1):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('*'):
                continue

            # Check for RegExp constructor: new RegExp("pattern")
            regex_match = re.search(r'new\s+RegExp\s*\(\s*["\'](.+?)["\']', line)
            if regex_match:
                pattern = regex_match.group(1)
                if self._is_evil_regex(pattern):
                    vulns.append(self._make_vuln(file_path, lineno, line, pattern))
                continue

            # Check for regex literals: /pattern/
            literal_match = re.search(r'(?<!=\s)/(.+?)/[gimsuy]*', line)
            if literal_match:
                pattern = literal_match.group(1)
                if self._is_evil_regex(pattern):
                    vulns.append(self._make_vuln(file_path, lineno, line, pattern))

        return vulns

    def _is_evil_regex(self, pattern):
        for evil in self.evil_patterns:
            if re.search(evil, pattern):
                return True
        return False

    def _make_vuln(self, file_path, lineno, line, pattern):
        # Center snippet on the regex pattern
        idx = line.find(pattern)
        if idx == -1:
            idx = line.find('RegExp')
        start = max(0, idx - 20) if idx > 0 else 0
        snippet = line[start:start+120].strip()
        return Vulnerability(
            vuln_type=self.vuln_type,
            cwe_id=self.cwe_id,
            file_path=file_path,
            line_number=lineno,
            code_snippet=snippet[:150],
            description=f"Regex pattern contains nested quantifiers or overlapping alternation that can cause catastrophic backtracking (ReDoS).",
            remediation="Rewrite the regex to avoid nested quantifiers. Use atomic groups or possessive quantifiers. Consider using a regex timeout or the 're2' library.",
            confidence_score=75,
            severity='Medium'
        )
