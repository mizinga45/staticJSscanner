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
        obfuscation_signs = [
            r'eval\s*\(\s*atob\s*\(',
            r'eval\s*\(\s*unescape\s*\(',
            r'eval\s*\(\s*String\.fromCharCode',
            r'\\x[0-9a-f]{2}.*\\x[0-9a-f]{2}.*\\x[0-9a-f]{2}',
            r'\\u[0-9a-f]{4}.*\\u[0-9a-f]{4}.*\\u[0-9a-f]{4}',
            r'_0x[a-f0-9]{4,}',
            r'\[\"\\x',
            r'atob\s*\(\s*["\'][A-Za-z0-9+/=]{20,}',  # atob with long base64
            r'String\.fromCharCode\s*\(\s*\d+\s*,\s*\d+\s*,\s*\d+',  # 3+ char codes
            r'unescape\s*\(\s*["\']%[0-9a-f]{2}',  # unescape with percent encoding
        ]
        import re
        check = code[:2000]
        for pattern in obfuscation_signs:
            if re.search(pattern, check, re.IGNORECASE):
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
        """Pretty-print minified JavaScript."""
        try:
            import jsbeautifier
            opts = jsbeautifier.default_options()
            opts.indent_size = 2
            opts.preserve_newlines = True
            return jsbeautifier.beautify(js_code, opts)
        except Exception:
            return js_code

    @staticmethod
    def deobfuscate(code):
        """
        Attempt to deobfuscate commonly known obfuscation patterns.
        Returns (deobfuscated_code, method_used) or (original_code, None).
        """
        import re, base64

        original = code
        method = None

        # 1. Hex string decoding: "\x48\x65\x6c\x6c\x6f" → "Hello"
        hex_pattern = r'(?:"|\')((?:\\x[0-9a-fA-F]{2})+)(?:"|\')'
        if re.search(hex_pattern, code):
            def decode_hex(m):
                try:
                    return '"' + bytes.fromhex(m.group(1).replace('\\x', '')).decode('utf-8') + '"'
                except Exception:
                    return m.group(0)
            code = re.sub(hex_pattern, decode_hex, code)
            if code != original:
                method = 'Hex string decoding'

        # 2. Unicode escape decoding: "\u0048\u0065" → "He"
        unicode_pattern = r'(?:"|\')((?:\\u[0-9a-fA-F]{4})+)(?:"|\')'
        if re.search(unicode_pattern, code):
            def decode_unicode(m):
                try:
                    s = m.group(1).encode().decode('unicode_escape')
                    return '"' + s + '"'
                except Exception:
                    return m.group(0)
            code = re.sub(unicode_pattern, decode_unicode, code)
            if code != original and not method:
                method = 'Unicode escape decoding'

        # 3. Base64 decoding: atob("SGVsbG8=") → "Hello"
        atob_pattern = r'atob\s*\(\s*["\']([A-Za-z0-9+/=]+)["\']\s*\)'
        if re.search(atob_pattern, code):
            def decode_atob(m):
                try:
                    decoded = base64.b64decode(m.group(1)).decode('utf-8')
                    return '"' + decoded.replace('"', '\\"').replace('\n', '\\n') + '"'
                except Exception:
                    return m.group(0)
            code = re.sub(atob_pattern, decode_atob, code)
            if code != original and not method:
                method = 'Base64 (atob) decoding'

        # 4. String.fromCharCode: String.fromCharCode(72,101,108) → "Hel"
        charcode_pattern = r'String\.fromCharCode\s*\(([\d,\s]+)\)'
        if re.search(charcode_pattern, code):
            def decode_charcode(m):
                try:
                    chars = [int(c.strip()) for c in m.group(1).split(',')]
                    return '"' + ''.join(chr(c) for c in chars) + '"'
                except Exception:
                    return m.group(0)
            code = re.sub(charcode_pattern, decode_charcode, code)
            if code != original and not method:
                method = 'String.fromCharCode decoding'

        # 5. Array-based obfuscation: var _0x1234=["eval","test"]; _0x1234[0]
        array_pattern = r'var\s+(_0x[a-f0-9]+)\s*=\s*\[((?:"[^"]*"|\'[^\']*\')(?:\s*,\s*(?:"[^"]*"|\'[^\']*\'))*)\];'
        array_match = re.search(array_pattern, code)
        if array_match:
            arr_name = array_match.group(1)
            try:
                items = re.findall(r'["\']([^"\']*)["\']', array_match.group(2))
                def replace_access(m):
                    idx = int(m.group(1))
                    return '"' + items[idx] + '"' if idx < len(items) else m.group(0)
                code = re.sub(re.escape(arr_name) + r'\[(\d+)\]', replace_access, code)
                if code != original and not method:
                    method = 'Array-based string inlining'
            except Exception:
                pass

        # Beautify result if deobfuscation happened
        if method:
            code = CodeExtractor.beautify(code)

        return code, method