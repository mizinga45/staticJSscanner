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
            if re.search(r'<script\b(?![^>]*\bsrc\s*=)[^>]*>', line, re.IGNORECASE):
                in_script = True
                script_start_line = i
                after_tag = re.sub(r'<script\b[^>]*>', '', line, count=1, flags=re.IGNORECASE)
                if after_tag.strip():
                    script_content.append(after_tag)
                if '</script>' in after_tag:
                    end_content = after_tag[:after_tag.find('</script>')]
                    script_content = [end_content]
                    scripts.append((script_start_line, '\n'.join(script_content)))
                    in_script = False
                    script_content = []
            elif in_script:
                if '</script>' in line:
                    end_content = line[:line.find('</script>')]
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
        lines = code.splitlines()
        if not lines:
            return False
        if len(lines) == 1 and len(lines[0]) > 500:
            return True
        avg_len = sum(len(line) for line in lines) / len(lines)
        if avg_len > 300 and len(lines) < 5:
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