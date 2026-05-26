# scanner/rules/insecure_deserialization.py
from scanner.rules.base_rule import VulnerabilityRule
from scanner.vulnerability import Vulnerability

USER_INPUT_SOURCES = {
    'location.search', 'location.hash', 'location.href',
    'document.cookie', 'document.referrer', 'window.name',
    'req.query', 'req.params', 'req.body', 'req.cookies',
    'request.url', 'request.args', 'request.json',
}


class InsecureDeserializationRule(VulnerabilityRule):
    """Detects unsafe deserialization of user input (CWE-502)."""

    def __init__(self):
        super().__init__(
            vuln_type="Insecure Deserialization",
            cwe_id="CWE-502",
            description="User input deserialized without validation, enabling code execution."
        )
        self.dangerous_funcs = {'unserialize', 'deserialize', 'node-serialize', 'serialize'}

    def detect(self, ast, file_path, code_lines, initial_tainted=None):
        vulns = []
        tainted = set(initial_tainted) if initial_tainted else set()
        self._walk(ast, file_path, code_lines, vulns, tainted)
        return vulns

    def _walk(self, node, file_path, code_lines, vulns, tainted):
        if not isinstance(node, dict):
            return tainted
        node_type = node.get('type')

        if node_type == 'VariableDeclaration':
            for decl in node.get('declarations', []):
                init = decl.get('init')
                var_id = decl.get('id')
                if var_id and var_id.get('type') == 'Identifier' and init:
                    if self._is_from_user_input(init):
                        tainted.add(var_id.get('name'))
                    elif self._refs(init, tainted):
                        tainted.add(var_id.get('name'))

        elif node_type == 'AssignmentExpression':
            left = node.get('left')
            right = node.get('right')
            if left and left.get('type') == 'Identifier' and right:
                if self._is_from_user_input(right):
                    tainted.add(left.get('name'))
                elif self._refs(right, tainted):
                    tainted.add(left.get('name'))

        # Detect: unserialize(tainted) or serialize.unserialize(tainted)
        if node_type == 'CallExpression':
            callee = node.get('callee')
            name = self._callee_name(callee)
            if name in self.dangerous_funcs:
                args = node.get('arguments', [])
                if args and self._refs(args[0], tainted):
                    loc = node.get('loc', {}).get('start', {})
                    line = loc.get('line', 0)
                    snippet = code_lines[line - 1].strip() if 0 < line <= len(code_lines) else ''
                    vulns.append(Vulnerability(
                        vuln_type=self.vuln_type, cwe_id=self.cwe_id,
                        file_path=file_path, line_number=line, code_snippet=snippet,
                        description="User input passed to deserialization function. Attacker can inject objects that execute code.",
                        remediation="Never deserialize untrusted data. Use JSON.parse() with schema validation instead.",
                        confidence_score=90, severity='Critical'
                    ))

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

    def _callee_name(self, callee):
        if not isinstance(callee, dict):
            return ''
        if callee.get('type') == 'Identifier':
            return callee.get('name', '')
        if callee.get('type') == 'MemberExpression':
            return callee.get('property', {}).get('name', '')
        return ''

    def _is_from_user_input(self, node):
        if not isinstance(node, dict):
            return False
        full = self._full(node)
        if full in USER_INPUT_SOURCES:
            return True
        if node.get('type') == 'MemberExpression' and self._is_from_user_input(node.get('object')):
            return True
        if node.get('type') == 'CallExpression' and self._is_from_user_input(node.get('callee')):
            return True
        return False

    def _refs(self, node, tainted):
        if not tainted:
            return False
        if isinstance(node, dict):
            if node.get('type') == 'Identifier' and node.get('name') in tainted:
                return True
            for v in node.values():
                if self._refs(v, tainted):
                    return True
        elif isinstance(node, list):
            for i in node:
                if self._refs(i, tainted):
                    return True
        return False

    def _full(self, node):
        if not isinstance(node, dict):
            return ''
        if node.get('type') == 'Identifier':
            return node.get('name', '')
        if node.get('type') == 'MemberExpression':
            o = self._full(node.get('object'))
            p = node.get('property', {}).get('name', '')
            return f"{o}.{p}" if o else p
        return ''
