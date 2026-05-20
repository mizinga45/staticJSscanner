# scanner/interprocedural.py
from scanner.vulnerability import Vulnerability

class InterproceduralAnalyzer:
    def __init__(self, rules):
        self.rules = rules

    def analyze(self, ast, code_lines, file_path, tainted_vars_after_intra):
        """
        Second pass: look for function calls with tainted arguments and
        propagate taint into the called function's body.

        Returns additional vulnerabilities found.
        """
        # First, collect function definitions
        functions = {}
        self._collect_functions(ast, functions)

        vulns = []
        # Now walk again to find calls
        self._find_tainted_calls(ast, tainted_vars_after_intra, functions,
                                 code_lines, file_path, vulns)
        return vulns

    def _collect_functions(self, node, funcs):
        if not isinstance(node, dict):
            return
        if node.get('type') == 'FunctionDeclaration':
            func_id = node.get('id')
            if func_id and func_id.get('type') == 'Identifier':
                name = func_id.get('name')
                params = [p.get('name') for p in node.get('params', []) if p.get('type') == 'Identifier']
                body = node.get('body')
                funcs[name] = {'params': params, 'body': body}
        # Also handle variable assignments of function expressions
        if node.get('type') == 'VariableDeclaration':
            for decl in node.get('declarations', []):
                init = decl.get('init')
                if init and (init.get('type') == 'FunctionExpression' or init.get('type') == 'ArrowFunctionExpression'):
                    var_id = decl.get('id')
                    if var_id and var_id.get('type') == 'Identifier':
                        name = var_id.get('name')
                        params = [p.get('name') for p in init.get('params', []) if p.get('type') == 'Identifier']
                        body = init.get('body')
                        funcs[name] = {'params': params, 'body': body}
        # Recurse
        for key, value in node.items():
            if isinstance(value, dict):
                self._collect_functions(value, funcs)
            elif isinstance(value, list):
                for item in value:
                    self._collect_functions(item, funcs)

    def _find_tainted_calls(self, node, tainted_vars, funcs, code_lines, file_path, vulns):
        if not isinstance(node, dict):
            return
        if node.get('type') == 'CallExpression':
            callee = node.get('callee')
            if callee and callee.get('type') == 'Identifier':
                func_name = callee.get('name')
                if func_name in funcs:
                    args = node.get('arguments', [])
                    # Check if any argument contains a tainted variable
                    for arg in args:
                        if self._references_tainted_var(arg, tainted_vars):
                            # Propagate taint: create a set of parameter names that become tainted
                            func_info = funcs[func_name]
                            new_tainted = set()
                            # Map arguments to parameters (only first few)
                            for i, param_name in enumerate(func_info['params']):
                                if i < len(args) and self._references_tainted_var(args[i], tainted_vars):
                                    new_tainted.add(param_name)
                            if new_tainted and func_info['body']:
                                # Run the detection rules on the function body with the new tainted set
                                body = func_info['body']
                                # For simplicity, we use the existing rules' detect method on a synthetic "mini‑AST" of the body
                                for rule in self.rules:
                                    # Each rule's detect expects a full AST, but we can pass just the body node.
                                    # We'll create a fake program node wrapping the body.
                                    fake_ast = {'type': 'Program', 'body': [body] if not isinstance(body, list) else body}
                                    try:
                                        extra_vulns = rule.detect(fake_ast, file_path, code_lines)
                                    except Exception:
                                        continue
                                    for v in extra_vulns:
                                        # Adjust confidence – interprocedural is less direct
                                        v.confidence_score = max(40, v.confidence_score - 20)
                                        v.description += " (detected across function call: " + func_name + ")"
                                        v.remediation += " Check the data flow through function " + func_name + "."
                                        # Avoid duplicates (we don't have global dedup here, will rely on engine)
                                        vulns.append(v)
                            break   # only need one tainted arg to trigger analysis
        # Recurse
        for key, value in node.items():
            if isinstance(value, dict):
                self._find_tainted_calls(value, tainted_vars, funcs, code_lines, file_path, vulns)
            elif isinstance(value, list):
                for item in value:
                    self._find_tainted_calls(item, tainted_vars, funcs, code_lines, file_path, vulns)

    def _references_tainted_var(self, node, tainted_vars):
        if isinstance(node, dict):
            if node.get('type') == 'Identifier' and node.get('name') in tainted_vars:
                return True
            for value in node.values():
                if self._references_tainted_var(value, tainted_vars):
                    return True
        elif isinstance(node, list):
            for item in node:
                if self._references_tainted_var(item, tainted_vars):
                    return True
        return False