# scanner/context_analyzer.py
import re

class ContextAnalyzer:
    """
    Basic data-flow heuristic: checks whether the lines near a potential vulnerability
    mention any known user‑input source. This drastically reduces false positives
    because patterns inside libraries (jQuery, Bootstrap, etc.) are usually
    not connected to user data in the same file.
    """

    # ------------------------------------------------------------------
    # 1. DOM / Browser global sources
    # ------------------------------------------------------------------
    DOM_SOURCES = [
        r'document\.URL',
        r'document\.documentURI',
        r'document\.baseURI',
        r'document\.referrer',
        r'document\.cookie',
        r'document\.lastModified',
        r'document\.title',               # sometimes set by user
        r'location\.href',
        r'location\.search',
        r'location\.hash',
        r'location\.pathname',
        r'location\.origin',
        r'window\.location',
        r'window\.name',
        r'history\.state',
    ]

    # ------------------------------------------------------------------
    # 2. Form / user input elements
    # ------------------------------------------------------------------
    INPUT_SOURCES = [
        r'\.value\b',
        r'\.innerHTML\b',                 # often set by user, but also a sink – we use it as source only if it appears on the right side
        r'\.textContent\b',
        r'\.src\b',
        r'\.href\b',
        r'\.action\b',
        r'\.data\b',
        r'\.files\b',
        r'\.checked\b',
        r'\.selectedIndex\b',
    ]

    # ------------------------------------------------------------------
    # 3. Node.js / Express / HTTP sources
    # ------------------------------------------------------------------
    NODE_SOURCES = [
        r'req\.query\b',
        r'req\.params\b',
        r'req\.body\b',
        r'req\.cookies\b',
        r'req\.headers\b',
        r'req\.url\b',
        r'req\.method\b',
        r'req\.path\b',
        r'req\.socket\b',
        r'process\.argv\b',
        r'process\.env\b',                # environment variables (usually not user‑controlled, but can be unsafe in some contexts)
    ]

    # ------------------------------------------------------------------
    # 4. Web APIs (fetch, XHR, postMessage, WebSocket, etc.)
    # ------------------------------------------------------------------
    API_SOURCES = [
        r'fetch\(\s*["\'][^"\']+["\']',
        r'\.then\(\s*function\s*\(',
        r'\.then\(\s*\w+\s*=>',
        r'XMLHttpRequest\b',
        r'xhr\.response(Text|XML|JSON)?',
        r'postMessage\b',
        r'addEventListener\(\s*["\']message["\']',
        r'WebSocket\b',
        r'EventSource\b',
    ]

    # ------------------------------------------------------------------
    # 5. Storage APIs
    # ------------------------------------------------------------------
    STORAGE_SOURCES = [
        r'localStorage\.getItem\(\s*["\']',
        r'sessionStorage\.getItem\(\s*["\']',
        r'cookie\.get\(',
        r'document\.cookie\s*=',          # often used to read cookies
    ]

    # ------------------------------------------------------------------
    # 6. jQuery / library specific
    # ------------------------------------------------------------------
    JQUERY_SOURCES = [
        r'\$\.get\(',
        r'\$\.ajax\(',
        r'\$\.post\(',
        r'\$\.getJSON\(',
        r'\.load\(',
    ]

    # ------------------------------------------------------------------
    # 7. Node.js File System (user paths)
    # ------------------------------------------------------------------
    FS_SOURCES = [
        r'readFile\(',
        r'readFileSync\(',
        r'writeFile\(',
        r'appendFile\(',
        r'fs\.readFile',
        r'fs\.writeFile',
    ]

    # ------------------------------------------------------------------
    # Combine all patterns into one flat list
    # ------------------------------------------------------------------
    ALL_SOURCE_PATTERNS = (
        DOM_SOURCES + INPUT_SOURCES + NODE_SOURCES +
        API_SOURCES + STORAGE_SOURCES + JQUERY_SOURCES + FS_SOURCES
    )

    def __init__(self, code_lines):
        """
        code_lines: list of strings (lines of the JavaScript file / block)
        """
        self.lines = code_lines

    def is_user_input_present(self, line_number):
        """
        Returns True if any user‑input pattern appears within a window
        of 3 lines before the given line and the line itself.
        """
        start = max(0, line_number - 3)
        end = min(len(self.lines), line_number + 1)
        window = '\n'.join(self.lines[start:end])

        for pattern in self.ALL_SOURCE_PATTERNS:
            if re.search(pattern, window, re.IGNORECASE):
                return True
        return False
