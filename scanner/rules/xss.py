# scanner/rules/xss.py
from scanner.rules.base_rule import VulnerabilityRule
from scanner.vulnerability import Vulnerability

USER_INPUT_SOURCES = {
    'location.search', 'location.hash', 'location.href',
    'document.cookie', 'document.referrer',
    'window.name',
    'req.query', 'req.params', 'req.body', 'req.cookies',
    'request.url', 'request.args', 'request.json',
}

XSS_SANITIZERS = {
    'sanitize', 'escapeHtml', 'escapeHTML', 'sanitizeHtml',
    'sanitizeHTML', 'htmlspecialchars', 'escape', 'encodeURI',
    'encodeURIComponent', 'DOMPurify.sanitize',
    'filterXSS', 'he.encode', 'entities.encode'
}


class XSSRule(VulnerabilityRule):
    def __init__(self):
        super().__init__(
            vuln_type="Cross-Site Scripting (XSS)",
            cwe_id="CWE-79",
            description="User input used in innerHTML or document.write() without sanitization."
        )

    def detect(self, ast, file_path, code_lines, initial_tainted=None):
        vulns = []
        tainted = set(initial_tainted) if initial_tainted else set()
        self._walk(ast, file_path, code_lines, vulns, tainted)
        return vulns

    def _walk(self, node, file_path, code_lines, vulns, tainted):
        if not isinstance(node, dict):
            return tainted

        node_type = node.get('type')

        # Taint propagation
        if node_type == 'VariableDeclaration':
            for decl in node.get('declarations', []):
                init = decl.get('init')
                var_id = decl.get('id')
                if var_id and var_id.get('type') == 'Identifier' and init:
                    var_name = var_id.get('name')
                    if self._is_from_user_input(init):
                        tainted.add(var_name)
                    elif self._references_tainted(init, tainted):
                        tainted.add(var_name)

        elif node_type == 'AssignmentExpression':
            left = node.get('left')
            right = node.get('right')
            if left and left.get('type') == 'Identifier' and right:
                var_name = left.get('name')
                if self._is_from_user_input(right):
                    tainted.add(var_name)
                elif self._references_tainted(right, tainted):
                    tainted.add(var_name)
                else:
                    tainted.discard(var_name)

            # innerHTML assignment detection
            if left and left.get('type') == 'MemberExpression':
                prop = left.get('property')
                if isinstance(prop, dict) and prop.get('name') == 'innerHTML':
                    if right and self._references_tainted(right, tainted):
                        sanitized = self._is_sanitized(right)
                        score = 50 if sanitized else 90
                        loc = node.get('loc', {}).get('start', {})
                        line = loc.get('line', 0)
                        snippet = code_lines[line - 1].strip() if 0 < line <= len(code_lines) else ''
                        vulns.append(Vulnerability(
                            vuln_type=self.vuln_type,
                            cwe_id=self.cwe_id,
                            file_path=file_path,
                            line_number=line,
                            code_snippet=snippet,
                            description="User-controlled input assigned to innerHTML.",
                            remediation="Use textContent instead of innerHTML, or sanitize with DOMPurify.",
                            confidence_score=score
                        ))

        # document.write() detection
        if node_type == 'CallExpression':
            callee = node.get('callee')
            if callee and callee.get('type') == 'MemberExpression':
                obj = callee.get('object')
                prop = callee.get('property')
                if obj and prop:
                    if obj.get('name') == 'document' and prop.get('name') == 'write':
                        args = node.get('arguments', [])
                        if args and self._references_tainted(args[0], tainted):
                            sanitized = self._is_sanitized(args[0])
                            score = 50 if sanitized else 90
                            loc = node.get('loc', {}).get('start', {})
                            line = loc.get('line', 0)
                            snippet = code_lines[line - 1].strip() if 0 < line <= len(code_lines) else ''
                            vulns.append(Vulnerability(
                                vuln_type=self.vuln_type,
                                cwe_id=self.cwe_id,
                                file_path=file_path,
                                line_number=line,
                                code_snippet=snippet,
                                description="document.write() called with user-controlled content.",
                                remediation="Avoid document.write(). Use safe DOM methods like textContent.",
                                confidence_score=score
                            ))

        # Recurse - accumulate taint across siblings
        for key, value in node.items():
            if key in ('loc', 'range', 'start', 'end'):
                continue
            if isinstance(value, dict):
                tainted = self._walk(value, file_path, code_lines, vulns, tainted)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        tainted = self._walk(item, file_path, code_lines, vulns, tainted)

        return tainted

    def _is_from_user_input(self, node):
        if not isinstance(node, dict):
            return False
        full = self._get_full_name(node)
        if full in USER_INPUT_SOURCES:
            return True
        if node.get('type') == 'MemberExpression':
            if self._is_from_user_input(node.get('object')):
                return True
        if node.get('type') == 'CallExpression':
            if self._is_from_user_input(node.get('callee')):
                return True
        return False

    def _references_tainted(self, node, tainted):
        if not tainted:
            return False
        if isinstance(node, dict):
            if node.get('type') == 'Identifier' and node.get('name') in tainted:
                return True
            for v in node.values():
                if self._references_tainted(v, tainted):
                    return True
        elif isinstance(node, list):
            for item in node:
                if self._references_tainted(item, tainted):
                    return True
        return False

    def _is_sanitized(self, expr):
        if isinstance(expr, dict) and expr.get('type') == 'CallExpression':
            callee = expr.get('callee')
            if callee:
                name = self._get_full_name(callee)
                if name in XSS_SANITIZERS:
                    return True
        return False

    def _get_full_name(self, node):
        if not isinstance(node, dict):
            return ''
        if node.get('type') == 'Identifier':
            return node.get('name', '')
        if node.get('type') == 'MemberExpression':
            obj = self._get_full_name(node.get('object'))
            prop = node.get('property', {}).get('name', '')
            return f"{obj}.{prop}" if obj else prop
        return ''
