 # scanner/core_engine.py
from scanner.rules import (
    SQLInjectionRule, XSSRule, CommandInjectionRule,
    HardcodedSecretRule, EvalInjectionRule, AngularBypassRule,
    ExpressHandlerTainter
)
from scanner.cwe_mapper import CWEMapper
from scanner.vulnerability import Vulnerability
from scanner.code_extractor import CodeExtractor
from scanner.interprocedural import InterproceduralAnalyzer

class CoreAnalysisEngine:
    def __init__(self):
        self.express_tainter = ExpressHandlerTainter()
        self.rules = [
            SQLInjectionRule(),
            XSSRule(),
            CommandInjectionRule(),
            HardcodedSecretRule(),
            EvalInjectionRule(),
            AngularBypassRule()
        ]
        self.cwe_mapper = CWEMapper()
        self.interprocedural = InterproceduralAnalyzer(self.rules)

    def scan(self, parts, original_source_label):
        all_vulns = []
        seen = set()

        for source_id, code, html_line_ref in parts:
            # Determine path for warning messages
            if source_id in ('inline_script', 'source'):
                check_path = original_source_label
            else:
                check_path = source_id

            # ----- Obfuscation warning -----
            if CodeExtractor.is_obfuscated(code):
                if source_id == 'inline_script':
                    warn_path = f"{original_source_label} (inline script, starting at HTML line {html_line_ref})"
                elif source_id == 'source':
                    warn_path = original_source_label
                else:
                    if source_id.startswith('http'):
                        warn_path = f"{source_id} (external script, included at HTML line {html_line_ref})"
                    else:
                        warn_path = source_id

                obf_vuln = Vulnerability(
                    vuln_type="Obfuscation Warning",
                    cwe_id="N/A",
                    file_path=warn_path,
                    line_number=1,
                    code_snippet="(entire file appears obfuscated)",
                    description="The code appears minified/obfuscated. Obfuscation can hide vulnerabilities; the scanner may miss some issues (potential false negatives).",
                    remediation="Consider using an unobfuscated version for accurate analysis.",
                    confidence_score=0
                )
                key = (obf_vuln.file_path, 'OBFUSCATION', 'obfuscated')
                if key not in seen:
                    seen.add(key)
                    all_vulns.append(obf_vuln)
            # -------------------------------

            lines = code.splitlines()
            try:
                from scanner.parser import Parser
                ast = Parser().parse_to_ast(code)
            except SyntaxError:
                continue

            # ---- 0. Pre‑taint with Express/Next route handlers ----
            initial_tainted = self.express_tainter.get_initial_tainted_vars(ast)

            # ---- 1. Intra‑procedural taint collection (after pre‑taint) ----
            tainted_vars_after_intra = self._collect_tainted_vars(ast, initial_tainted)

            # ---- 2. Intra‑procedural vulnerability detection ----
            # Pass the initial tainted set to the rules via an extended version of detect.
            # We'll modify rule.detect to accept an initial_tainted parameter.
            intra_vulns = []
            for rule in self.rules:
                # Use detect with initial_tainted parameter (if rule supports it)
                try:
                    found = rule.detect(ast, check_path, lines, initial_tainted=initial_tainted)
                except TypeError:
                    # Fallback: rule doesn't accept initial_tainted, use standard detect
                    found = rule.detect(ast, check_path, lines)
                intra_vulns.extend(found)

            # ---- 3. Inter‑procedural pass ----
            inter_vulns = self.interprocedural.analyze(ast, lines, check_path, tainted_vars_after_intra)

            # ---- 4. Combine, enrich and deduplicate ----
            for v in intra_vulns + inter_vulns:
                details = self.cwe_mapper.get_cwe_details(
                    v.type.lower().replace(' ', '_').replace('(', '').replace(')', '')
                )
                if v.cwe_id == 'CWE-Unknown':
                    v.cwe_id = details.get('cwe_id', 'CWE-Unknown')
                if not v.description:
                    v.description = details.get('description', '')
                if not v.remediation:
                    v.remediation = details.get('remediation', '')

                if source_id == 'inline_script':
                    v.file_path = f"{original_source_label} (inline script, starting at HTML line {html_line_ref})"
                elif source_id == 'source':
                    v.file_path = original_source_label
                else:
                    if source_id.startswith('http'):
                        v.file_path = f"{source_id} (external script, included at HTML line {html_line_ref})"
                    else:
                        v.file_path = source_id

                key = (v.file_path, v.line_number, v.cwe_id)
                if key not in seen:
                    seen.add(key)
                    all_vulns.append(v)

        # Filter low confidence
        filtered_vulns = [v for v in all_vulns if v.type == 'Obfuscation Warning' or v.confidence_score >= 50]
        return filtered_vulns

    # ---------- Taint collection helpers (updated to accept initial tainted set) ----------
    def _collect_tainted_vars(self, ast, initial_tainted=None):
        if initial_tainted is None:
            initial_tainted = set()
        final_tainted = set(initial_tainted)
        self._taint_walk(ast, set(initial_tainted), 0, final_tainted)
        return final_tainted

    def _taint_walk(self, node, current_tainted, depth, final_tainted):
        if not isinstance(node, dict):
            return current_tainted, depth
        node_type = node.get('type')
        new_tainted = set(current_tainted)
        new_depth = depth

        if node_type == 'AssignmentExpression':
            left = node.get('left')
            right = node.get('right')
            if left and left.get('type') == 'Identifier':
                var_name = left.get('name')
                if self._is_from_user_input(right):
                    new_tainted.add(var_name)
                    new_depth = 1
                elif self._references_tainted(right, current_tainted):
                    new_tainted.add(var_name)
                    new_depth = depth + 1
                else:
                    new_tainted.discard(var_name)
        elif node_type == 'VariableDeclaration':
            for decl in node.get('declarations', []):
                init = decl.get('init')
                if init and self._is_from_user_input(init):
                    var_id = decl.get('id')
                    if var_id and var_id.get('type') == 'Identifier':
                        new_tainted.add(var_id.get('name'))
                        new_depth = 1
                elif init and self._references_tainted(init, current_tainted):
                    var_id = decl.get('id')
                    if var_id and var_id.get('type') == 'Identifier':
                        new_tainted.add(var_id.get('name'))
                        new_depth = depth + 1

        for key, value in node.items():
            if isinstance(value, dict):
                self._taint_walk(value, new_tainted, new_depth, final_tainted)
            elif isinstance(value, list):
                for item in value:
                    self._taint_walk(item, new_tainted, new_depth, final_tainted)

        final_tainted.update(new_tainted)
        return new_tainted, new_depth

    # ---------- Helpers ----------
    def _is_from_user_input(self, node):
        USER_INPUT_SOURCES = {
            'location.search', 'location.hash', 'location.href',
            'document.cookie', 'document.referrer',
            'window.name',
            'req.query', 'req.params', 'req.body', 'req.cookies',
            'request.url', 'request.args', 'request.json',
        }
        if isinstance(node, dict):
            if node.get('type') == 'MemberExpression':
                obj = node.get('object')
                prop = node.get('property')
                if obj and prop:
                    full = f"{self._get_name(obj)}.{self._get_name(prop)}"
                    if full in USER_INPUT_SOURCES:
                        return True
            if node.get('type') == 'CallExpression':
                callee = node.get('callee')
                if callee:
                    full = self._get_full_name(callee)
                    if full in USER_INPUT_SOURCES:
                        return True
        return False

    def _references_tainted(self, node, tainted_vars):
        if isinstance(node, dict):
            if node.get('type') == 'Identifier' and node.get('name') in tainted_vars:
                return True
            for value in node.values():
                if self._references_tainted(value, tainted_vars):
                    return True
        elif isinstance(node, list):
            for item in node:
                if self._references_tainted(item, tainted_vars):
                    return True
        return False

    def _get_name(self, node):
        if isinstance(node, dict) and node.get('type') == 'Identifier':
            return node.get('name', '')
        return ''

    def _get_full_name(self, node):
        if isinstance(node, dict):
            if node.get('type') == 'MemberExpression':
                obj = node.get('object')
                prop = node.get('property')
                obj_name = self._get_full_name(obj) if obj else ''
                prop_name = prop.get('name') if isinstance(prop, dict) else ''
                return f"{obj_name}.{prop_name}" if obj_name else prop_name
            elif node.get('type') == 'Identifier':
                return node.get('name', '')
        return ''