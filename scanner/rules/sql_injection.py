# scanner/rules/sql_injection.py
import re
from scanner.rules.base_rule import VulnerabilityRule
from scanner.vulnerability import Vulnerability

USER_INPUT_SOURCES = {
    'location.search', 'location.hash', 'location.href',
    'document.cookie', 'document.referrer',
    'window.name',
    'req.query', 'req.params', 'req.body', 'req.cookies',
    'request.url', 'request.args', 'request.json',
}

SQL_SANITIZERS = {
    'escape', 'mysql.escape', 'pg.escape', 'sqlite.escape',
    'quote', 'param', 'escapeSQL', 'sanitizeSQL',
    'db.escape', 'connection.escape', 'pool.escape',
    'sqlstring.escape', 'sqlstring.format'
}


class SQLInjectionRule(VulnerabilityRule):
    def __init__(self):
        super().__init__(
            vuln_type="SQL Injection",
            cwe_id="CWE-89",
            description="User input concatenated into SQL query."
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

        # SQL concatenation detection (+ operator)
        if node_type == 'BinaryExpression' and node.get('operator') == '+':
            left = node.get('left')
            right = node.get('right')
            if self._contains_sql(left) or self._contains_sql(right):
                if self._references_tainted(left, tainted) or self._references_tainted(right, tainted):
                    loc = node.get('loc', {}).get('start', {})
                    line = loc.get('line', 0)
                    snippet = code_lines[line - 1].strip() if 0 < line <= len(code_lines) else ''
                    tainted_side = left if self._references_tainted(left, tainted) else right
                    sanitized = self._is_sanitized(tainted_side)
                    score = 50 if sanitized else 90
                    vulns.append(Vulnerability(
                        vuln_type=self.vuln_type,
                        cwe_id=self.cwe_id,
                        file_path=file_path,
                        line_number=line,
                        code_snippet=snippet,
                        description="User input concatenated into SQL query string.",
                        remediation="Use parameterized queries or prepared statements instead of string concatenation.",
                        confidence_score=score
                    ))

        # SQL template literal injection: `SELECT ... ${tainted}`
        if node_type == 'TemplateLiteral':
            quasis = node.get('quasis', [])
            expressions = node.get('expressions', [])
            # Check if template contains SQL keywords
            full_text = ' '.join(q.get('value', {}).get('raw', '') for q in quasis)
            if re.search(r'\b(SELECT|INSERT|UPDATE|DELETE|DROP)\b', full_text, re.IGNORECASE):
                for expr in expressions:
                    if self._references_tainted(expr, tainted):
                        loc = node.get('loc', {}).get('start', {})
                        line = loc.get('line', 0)
                        snippet = code_lines[line - 1].strip() if 0 < line <= len(code_lines) else ''
                        vulns.append(Vulnerability(
                            vuln_type=self.vuln_type,
                            cwe_id=self.cwe_id,
                            file_path=file_path,
                            line_number=line,
                            code_snippet=snippet,
                            description="User input interpolated into SQL query via template literal.",
                            remediation="Use parameterized queries. Replace template literals with prepared statement placeholders (?).",
                            confidence_score=90
                        ))
                        break

        # Recurse into children - accumulate taint across list items
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

    def _contains_sql(self, node):
        if isinstance(node, dict):
            if node.get('type') == 'Literal':
                val = node.get('value', '')
                if isinstance(val, str):
                    if re.search(r'\b(SELECT|INSERT|UPDATE|DELETE|DROP)\b', val, re.IGNORECASE):
                        return True
            if node.get('type') == 'TemplateLiteral':
                for quasi in node.get('quasis', []):
                    val = quasi.get('value', {}).get('raw', '')
                    if re.search(r'\b(SELECT|INSERT|UPDATE|DELETE|DROP)\b', val, re.IGNORECASE):
                        return True
            for v in node.values():
                if isinstance(v, dict) and self._contains_sql(v):
                    return True
        return False

    def _is_sanitized(self, expr):
        if isinstance(expr, dict) and expr.get('type') == 'CallExpression':
            callee = expr.get('callee')
            if callee:
                name = self._get_full_name(callee)
                if name in SQL_SANITIZERS:
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
