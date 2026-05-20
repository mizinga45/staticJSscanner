# scanner/rules/path_traversal.py
from scanner.rules.base_rule import VulnerabilityRule
from scanner.vulnerability import Vulnerability

USER_INPUT_SOURCES = {
    'location.search', 'location.hash', 'location.href',
    'document.cookie', 'document.referrer', 'window.name',
    'req.query', 'req.params', 'req.body', 'req.cookies',
    'request.url', 'request.args', 'request.json',
}

FS_FUNCTIONS = {
    'readFile', 'readFileSync', 'writeFile', 'writeFileSync',
    'appendFile', 'appendFileSync', 'unlink', 'unlinkSync',
    'readdir', 'readdirSync', 'stat', 'statSync',
    'createReadStream', 'createWriteStream', 'access', 'accessSync',
    'open', 'openSync', 'rename', 'renameSync',
}

PATH_SANITIZERS = {'normalize', 'resolve', 'basename', 'join'}


class PathTraversalRule(VulnerabilityRule):
    def __init__(self):
        super().__init__(
            vuln_type="Path Traversal",
            cwe_id="CWE-22",
            description="User input used in file system path without validation."
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
                    name = var_id.get('name')
                    if self._is_from_user_input(init):
                        tainted.add(name)
                    elif self._references_tainted(init, tainted):
                        tainted.add(name)

        elif node_type == 'AssignmentExpression':
            left = node.get('left')
            right = node.get('right')
            if left and left.get('type') == 'Identifier' and right:
                name = left.get('name')
                if self._is_from_user_input(right):
                    tainted.add(name)
                elif self._references_tainted(right, tainted):
                    tainted.add(name)
                else:
                    tainted.discard(name)

        # Detect fs function calls with tainted argument
        if node_type == 'CallExpression':
            callee = node.get('callee')
            func_name = self._get_callee_name(callee)
            if func_name in FS_FUNCTIONS:
                args = node.get('arguments', [])
                if args and self._references_tainted(args[0], tainted):
                    if not self._is_sanitized_path(args[0]):
                        loc = node.get('loc', {}).get('start', {})
                        line = loc.get('line', 0)
                        snippet = code_lines[line - 1].strip() if 0 < line <= len(code_lines) else ''
                        vulns.append(Vulnerability(
                            vuln_type=self.vuln_type,
                            cwe_id=self.cwe_id,
                            file_path=file_path,
                            line_number=line,
                            code_snippet=snippet,
                            description=f"User input passed to fs.{func_name}() without path validation. Attacker can use '../' to access arbitrary files.",
                            remediation=f"Use path.resolve() or path.basename() to normalize the path. Validate it stays within the intended directory.",
                            confidence_score=90,
                            severity='Critical'
                        ))

        # Recurse
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

    def _get_callee_name(self, callee):
        if not isinstance(callee, dict):
            return ''
        if callee.get('type') == 'Identifier':
            return callee.get('name', '')
        if callee.get('type') == 'MemberExpression':
            return callee.get('property', {}).get('name', '')
        return ''

    def _is_sanitized_path(self, node):
        if isinstance(node, dict) and node.get('type') == 'CallExpression':
            callee = node.get('callee')
            name = self._get_callee_name(callee)
            if name in PATH_SANITIZERS:
                return True
        return False

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
