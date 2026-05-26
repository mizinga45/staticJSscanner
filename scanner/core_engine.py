# scanner/core_engine.py
from scanner.rules import (
    SQLInjectionRule, XSSRule, CommandInjectionRule,
    HardcodedSecretRule, EvalInjectionRule, AngularBypassRule,
    ExpressHandlerTainter, PrototypePollutionRule, PathTraversalRule,
    OpenRedirectRule, RegexDosRule, InsecureRandomRule
)
from scanner.cwe_mapper import CWEMapper
from scanner.vulnerability import Vulnerability
from scanner.code_extractor import CodeExtractor

# Severity mapping based on CWE
SEVERITY_MAP = {
    'CWE-78': 'Critical',   # Command Injection
    'CWE-89': 'Critical',   # SQL Injection
    'CWE-22': 'Critical',   # Path Traversal
    'CWE-95': 'High',       # eval injection
    'CWE-79': 'High',       # XSS
    'CWE-1321': 'High',     # Prototype Pollution
    'CWE-798': 'Medium',    # Hardcoded secrets
    'CWE-601': 'Medium',    # Open Redirect
    'CWE-1333': 'Medium',   # ReDoS
    'CWE-330': 'Medium',    # Insecure Randomness
}

# Known library patterns that cause false positives
LIBRARY_INDICATORS = [
    'jquery', 'bootstrap', 'angular', 'react', 'vue',
    'lodash', 'underscore', 'moment', 'axios', 'popper',
    'sweetalert', 'd3', 'chart', 'socket.io', 'three',
    'backbone', 'ember', 'knockout', 'mootools', 'prototype',
    'dojo', 'ext-all', 'yui', 'raphael', 'fabric',
]


class CoreAnalysisEngine:
    def __init__(self):
        self.express_tainter = ExpressHandlerTainter()
        self.rules = [
            SQLInjectionRule(),
            XSSRule(),
            CommandInjectionRule(),
            HardcodedSecretRule(),
            EvalInjectionRule(),
            AngularBypassRule(),
            PrototypePollutionRule(),
            PathTraversalRule(),
            OpenRedirectRule(),
            RegexDosRule(),
            InsecureRandomRule(),
        ]
        self.cwe_mapper = CWEMapper()

    def scan(self, parts, original_source_label):
        all_vulns = []
        seen = set()
        extracted_urls = []
        # Testing report: track which rules were tested and what they found
        testing_report = {r.vuln_type: {'tested': True, 'detected': False, 'count': 0}
                         for r in self.rules}
        code_info = {'is_minified': False, 'is_obfuscated': False, 'was_beautified': False}

        for source_id, code, html_line_ref in parts:
            if source_id.startswith('http'):
                extracted_urls.append(source_id)

            if self._is_library(source_id, code):
                continue

            if source_id in ('inline_script', 'source'):
                check_path = original_source_label
            else:
                check_path = source_id

            # Handle minified code
            if CodeExtractor.is_minified(code):
                code_info['is_minified'] = True
                code = CodeExtractor.beautify(code)
                code_info['was_beautified'] = True

            # Handle obfuscated code
            if CodeExtractor.is_obfuscated(code):
                code_info['is_obfuscated'] = True
                warn_path = self._build_display_path(source_id, original_source_label, html_line_ref)
                obf_vuln = Vulnerability(
                    vuln_type="Obfuscation Warning",
                    cwe_id="N/A",
                    file_path=warn_path,
                    line_number=1,
                    code_snippet="(code uses obfuscation techniques like eval(atob(...)) or hex encoding)",
                    description="The code is obfuscated using techniques that hide its true logic.",
                    remediation="Obtain the original unobfuscated source code for accurate analysis.",
                    confidence_score=0,
                    severity="Info"
                )
                key = (obf_vuln.file_path, 'OBFUSCATION')
                if key not in seen:
                    seen.add(key)
                    all_vulns.append(obf_vuln)
                continue

            lines = code.splitlines()
            try:
                from scanner.parser import Parser
                ast = Parser().parse_to_ast(code)
            except SyntaxError:
                continue

            initial_tainted = self.express_tainter.get_initial_tainted_vars(ast)

            for rule in self.rules:
                try:
                    found = rule.detect(ast, check_path, lines, initial_tainted=initial_tainted)
                except TypeError:
                    found = rule.detect(ast, check_path, lines)

                if found:
                    testing_report[rule.vuln_type]['detected'] = True
                    testing_report[rule.vuln_type]['count'] += len(found)

                for v in found:
                    details = self.cwe_mapper.get_cwe_details(
                        v.type.lower().replace(' ', '_').replace('(', '').replace(')', '')
                    )
                    if v.cwe_id == 'CWE-Unknown':
                        v.cwe_id = details.get('cwe_id', 'CWE-Unknown')
                    if not v.description or v.description == rule.description:
                        v.description = details.get('description', v.description)
                    v.severity = SEVERITY_MAP.get(v.cwe_id, 'Medium')
                    v.file_path = self._build_display_path(source_id, original_source_label, html_line_ref)

                    key = (v.file_path, v.line_number, v.cwe_id)
                    if key not in seen:
                        seen.add(key)
                        all_vulns.append(v)

        filtered = [v for v in all_vulns if v.type == 'Obfuscation Warning' or v.confidence_score >= 50]
        return filtered, extracted_urls, testing_report, code_info

    def _build_display_path(self, source_id, original_source_label, html_line_ref):
        if source_id == 'inline_script':
            return f"{original_source_label} (inline script at line {html_line_ref})"
        elif source_id == 'source':
            return original_source_label
        elif source_id.startswith('http'):
            return source_id
        else:
            return source_id

    def _is_library(self, source_id, code):
        """Detect if this is a known third-party library to skip scanning."""
        source_lower = source_id.lower()
        for lib in LIBRARY_INDICATORS:
            if lib in source_lower:
                return True
        # Check first few lines for library headers
        first_lines = code[:500].lower()
        for lib in LIBRARY_INDICATORS:
            if lib in first_lines:
                return True
        # Very long single-line files are likely minified libraries
        lines = code.splitlines()
        if len(lines) <= 3 and len(code) > 5000:
            return True
        return False
