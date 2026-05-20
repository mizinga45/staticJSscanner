 # scanner/code_extractor.py
from bs4 import BeautifulSoup
import re

class CodeExtractor:
    def __init__(self):
        self.raw_content = ""

    def extract_with_origins(self, content, external_js=None):
        parts = []
        if external_js is None:
            external_js = []

        if not self._contains_markup(content):
            parts.append(('source', content, 0))
            for url, js_content, html_line in external_js:
                parts.append((url, js_content, html_line))
            return parts

        inline_scripts = self._extract_inline_scripts_with_lines(content)
        for start_line, code in inline_scripts:
            parts.append(('inline_script', code, start_line))

        for url, js_content, html_line in external_js:
            parts.append((url, js_content, html_line))

        return parts

    def _extract_inline_scripts_with_lines(self, html):
        scripts = []
        lines = html.split('\n')
        in_script = False
        script_start_line = 0
        script_content = []
        for i, line in enumerate(lines, start=1):
            if not in_script:
                match = re.search(r'<script\b(?![^>]*\bsrc\s*=)[^>]*>', line, re.IGNORECASE)
                if match:
                    in_script = True
                    script_start_line = i
                    # Get only content AFTER the <script> tag
                    after_tag = line[match.end():]
                    if '</script>' in after_tag:
                        end_content = after_tag[:after_tag.find('</script>')]
                        if end_content.strip():
                            scripts.append((script_start_line, end_content))
                        in_script = False
                    elif after_tag.strip():
                        script_content.append(after_tag)
            else:
                if '</script>' in line:
                    end_content = line[:line.find('</script>')]
                    if end_content.strip():
                        script_content.append(end_content)
                    scripts.append((script_start_line, '\n'.join(script_content)))
                    in_script = False
                    script_content = []
                else:
                    script_content.append(line)
        return scripts

    def _contains_markup(self, content):
        markers = ['<html', '<body', '<div', '<script', '<?php', '<%']
        content_lower = content.lower()
        return any(m in content_lower for m in markers)

    @staticmethod
    def is_obfuscated(code):
        """Detect if code is obfuscated (not just minified)."""
        lines = code.splitlines()
        if not lines:
            return False
        # Check for common obfuscation indicators
        obfuscation_signs = [
            r'eval\s*\(\s*atob\s*\(',          # eval(atob(...))
            r'eval\s*\(\s*unescape\s*\(',      # eval(unescape(...))
            r'eval\s*\(\s*String\.fromCharCode', # eval(String.fromCharCode(...))
            r'\\x[0-9a-f]{2}.*\\x[0-9a-f]{2}.*\\x[0-9a-f]{2}',  # Heavy hex encoding
            r'\\u[0-9a-f]{4}.*\\u[0-9a-f]{4}.*\\u[0-9a-f]{4}',  # Heavy unicode encoding
            r'_0x[a-f0-9]{4,}',                # obfuscator.io style variables
            r'\[\"\\x',                         # Hex string array access
        ]
        import re
        first_500 = code[:500]
        for pattern in obfuscation_signs:
            if re.search(pattern, first_500, re.IGNORECASE):
                return True
        return False

    @staticmethod
    def is_minified(code):
        """Detect if code is minified (compressed but not obfuscated)."""
        lines = code.splitlines()
        if not lines:
            return False
        # Single very long line = minified
        if len(lines) <= 3 and len(code) > 500:
            return True
        # Average line length > 200 with few lines = minified
        avg_len = sum(len(l) for l in lines) / len(lines)
        if avg_len > 200 and len(lines) < 10:
            return True
        return False

    @staticmethod
    def beautify(js_code):
        """Deobfuscate / pretty-print minified JavaScript."""
        try:
            import jsbeautifier
            opts = jsbeautifier.default_options()
            opts.indent_size = 2
            opts.preserve_newlines = True
            return jsbeautifier.beautify(js_code, opts)
        except Exception:
            return js_code