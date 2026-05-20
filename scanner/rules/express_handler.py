# scanner/rules/express_handler.py
from scanner.rules.base_rule import VulnerabilityRule
from scanner.vulnerability import Vulnerability

class ExpressHandlerTainter(VulnerabilityRule):
    """
    Pre‑rule: recognises Express/Next route handlers and marks
    'req' (or 'request', 'ctx') as initially tainted.
    """
    def __init__(self):
        super().__init__(
            vuln_type="",
            cwe_id="",
            description=""
        )

    def detect(self, ast, file_path, code_lines):
        # This rule returns no vulnerabilities; it only updates the tainted set.
        # We'll use a separate method to extract the initial tainted set.
        return []

    def get_initial_tainted_vars(self, ast):
        """
        Walk the AST and collect parameter names that represent
        the request object in Express/Next route handlers.
        Returns a set of variable names to pre‑taint.
        """
        tainted = set()
        self._find_handlers(ast, tainted)
        return tainted

    def _find_handlers(self, node, tainted):
        if not isinstance(node, dict):
            return
        # Look for app.get(...), app.post(...), router.get(...), etc.
        if node.get('type') == 'CallExpression':
            callee = node.get('callee')
            if self._is_route_registration(callee):
                args = node.get('arguments', [])
                # The last argument is usually the handler callback
                if len(args) >= 2:
                    handler = args[-1]
                    if isinstance(handler, dict) and (
                        handler.get('type') == 'FunctionExpression' or
                        handler.get('type') == 'ArrowFunctionExpression'
                    ):
                        params = handler.get('params', [])
                        # First parameter is request object
                        if params and isinstance(params[0], dict):
                            req_name = params[0].get('name', '')
                            if req_name:
                                tainted.add(req_name)
                                # Also pre‑taint common sub‑properties when used directly
                                # (they will be resolved by the taint propagation rules,
                                #  but we can add them as tainted sources too)
                                tainted.add(f"{req_name}.query")
                                tainted.add(f"{req_name}.params")
                                tainted.add(f"{req_name}.body")
                                tainted.add(f"{req_name}.cookies")
        # Recurse
        for key, value in node.items():
            if isinstance(value, dict):
                self._find_handlers(value, tainted)
            elif isinstance(value, list):
                for item in value:
                    self._find_handlers(item, tainted)

    def _is_route_registration(self, callee):
        # Check for app.verb(...), router.verb(...), or app.use(...), router.use(...)
        if callee and callee.get('type') == 'MemberExpression':
            obj = callee.get('object')
            prop = callee.get('property')
            if obj and prop:
                obj_name = self._get_name(obj)
                method_name = self._get_name(prop)
                # common Express/Next methods
                route_methods = {'get', 'post', 'put', 'delete', 'patch', 'use', 'all'}
                # object could be 'app', 'router', 'this.router', etc.
                if method_name in route_methods and obj_name in {'app', 'router', 'this.app', 'this.router'}:
                    return True
                # also handle app.get('/path', handler) where app is an identifier
                if method_name in route_methods and obj_name:
                    # If it's a simple identifier like 'app' or 'server', consider it a route handler
                    if obj_name in {'app', 'server', 'router'}:
                        return True
        return False

    def _get_name(self, node):
        if isinstance(node, dict) and node.get('type') == 'Identifier':
            return node.get('name', '')
        return ''