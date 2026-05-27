# scanner/parser.py
import subprocess
import json
import os


class Parser:
    """Parses JavaScript into an AST using Acorn (Node.js)."""

    def __init__(self):
        self.script_path = os.path.join(os.path.dirname(__file__), 'parser_script.js')

    def parse_to_ast(self, js_code):
        """Run node parser_script.js, feed it js_code, return AST dict."""
        # Remove invalid unicode surrogates that crash the subprocess
        clean_code = js_code.encode('utf-8', errors='replace').decode('utf-8')
        result = subprocess.run(
            ['node', self.script_path],
            input=clean_code,
            capture_output=True,
            text=True,
            timeout=15
        )
        if result.returncode != 0:
            raise SyntaxError(result.stderr.strip())
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            raise SyntaxError("Failed to parse AST output")
