# scanner/rules/insecure_random.py
from scanner.rules.base_rule import VulnerabilityRule
from scanner.vulnerability import Vulnerability


class InsecureRandomRule(VulnerabilityRule):
    """Detects Math.random() assigned to security-sensitive variables."""

    def __init__(self):
        super().__init__(
            vuln_type="Insecure Randomness",
            cwe_id="CWE-330",
            description="Math.random() used for security-sensitive purposes."
        )
        # Variable names that indicate security use
        self.security_var_patterns = {
            'token', 'secret', 'key', 'password', 'hash', 'salt',
            'session', 'csrf', 'nonce', 'otp', 'auth', 'credential',
            'uuid', 'sessionid', 'accesstoken', 'refreshtoken',
            'apikey', 'secretkey', 'privatekey', 'authtoken',
        }
        # Function names that indicate security use
        self.security_func_patterns = {
            'generatetoken', 'createtoken', 'generatesession',
            'generatekey', 'createsecret', 'generateid',
            'generatepassword', 'createnonce', 'generateotp',
            'randomtoken', 'makeid', 'generateuuid',
        }

    def detect(self, ast, file_path, code_lines, **kwargs):
        vulns = []
        self._walk(ast, file_path, code_lines, vulns, in_security_func=False)
        return vulns

    def _walk(self, node, file_path, code_lines, vulns, in_security_func):
        if not isinstance(node, dict):
            return

        node_type = node.get('type')

        # Check if we're inside a security-related function
        if node_type in ('FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression'):
            func_name = ''
            if node_type == 'FunctionDeclaration' and node.get('id'):
                func_name = node['id'].get('name', '').lower()
            # Check parent context for variable assignment name
            in_sec = func_name.replace('_', '').replace('-', '') in self.security_func_patterns
            # Recurse into function body with security context
            body = node.get('body')
            if body:
                self._walk(body, file_path, code_lines, vulns, in_security_func=in_sec or in_security_func)
            return

        # Check: var token = Math.random()... (assignment to security variable)
        if node_type == 'VariableDeclaration':
            for decl in node.get('declarations', []):
                var_id = decl.get('id')
                init = decl.get('init')
                if var_id and var_id.get('type') == 'Identifier' and init:
                    var_name = var_id.get('name', '').lower().replace('_', '').replace('-', '')
                    is_security_var = any(p in var_name for p in self.security_var_patterns)
                    if (is_security_var or in_security_func) and self._contains_math_random(init):
                        loc = decl.get('loc', node.get('loc', {})).get('start', {})
                        line = loc.get('line', 0)
                        snippet = self._get_snippet(code_lines, line)
                        vulns.append(Vulnerability(
                            vuln_type=self.vuln_type,
                            cwe_id=self.cwe_id,
                            file_path=file_path,
                            line_number=line,
                            code_snippet=snippet,
                            description=f"Math.random() used to generate '{var_id.get('name')}'. Math.random() is predictable and not cryptographically secure.",
                            remediation="Use crypto.randomBytes() (Node.js) or crypto.getRandomValues() (browser) instead of Math.random() for security-sensitive values.",
                            confidence_score=85,
                            severity='Medium'
                        ))
                        return  # One finding per declaration

        # Check: return Math.random()... inside security function
        if node_type == 'ReturnStatement' and in_security_func:
            arg = node.get('argument')
            if arg and self._contains_math_random(arg):
                loc = node.get('loc', {}).get('start', {})
                line = loc.get('line', 0)
                snippet = self._get_snippet(code_lines, line)
                vulns.append(Vulnerability(
                    vuln_type=self.vuln_type,
                    cwe_id=self.cwe_id,
                    file_path=file_path,
                    line_number=line,
                    code_snippet=snippet,
                    description="Math.random() returned from a security-sensitive function. The output is predictable.",
                    remediation="Use crypto.randomBytes() (Node.js) or crypto.getRandomValues() (browser) for cryptographic randomness.",
                    confidence_score=90,
                    severity='Medium'
                ))
                return

        # Recurse
        for key, value in node.items():
            if key in ('loc', 'range', 'start', 'end'):
                continue
            if isinstance(value, dict):
                self._walk(value, file_path, code_lines, vulns, in_security_func)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        self._walk(item, file_path, code_lines, vulns, in_security_func)

    def _contains_math_random(self, node):
        """Check if node contains a Math.random() call."""
        if not isinstance(node, dict):
            return False
        if node.get('type') == 'CallExpression':
            callee = node.get('callee')
            if callee and callee.get('type') == 'MemberExpression':
                obj = callee.get('object', {})
                prop = callee.get('property', {})
                if obj.get('name') == 'Math' and prop.get('name') == 'random':
                    return True
        for v in node.values():
            if isinstance(v, dict) and self._contains_math_random(v):
                return True
            elif isinstance(v, list):
                for item in v:
                    if isinstance(item, dict) and self._contains_math_random(item):
                        return True
        return False

    def _get_snippet(self, code_lines, line):
        """Get snippet centered on the line, showing Math.random."""
        if 0 < line <= len(code_lines):
            full_line = code_lines[line - 1]
            idx = full_line.find('Math.random')
            if idx >= 0:
                start = max(0, idx - 30)
                return full_line[start:start + 120].strip()
            return full_line.strip()[:120]
        return ''
