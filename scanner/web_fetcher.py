# scanner/web_fetcher.py
import requests
from urllib.parse import urljoin
import re

class WebFetcher:
    """Fetches HTML content from URLs and downloads linked JavaScript files."""
    
    def __init__(self, timeout=30, max_retries=2):
        self.timeout = timeout
        self.max_retries = max_retries
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (compatible; StaticSecurityScanner/1.0)'
        })
    
    def fetch(self, url):
        """Fetch HTML content from a URL."""
        try:
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()
            return response.text
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                raise ConnectionError(f"URL not found (404): {url}")
            else:
                raise ConnectionError(f"HTTP error {e.response.status_code} for URL: {url}")
        except requests.exceptions.RequestException as e:
            raise ConnectionError(f"Failed to fetch URL '{url}': {e}")
    
    def fetch_js(self, url):
        """Fetch JavaScript file content directly."""
        try:
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()
            return response.text
        except requests.exceptions.RequestException as e:
            raise ConnectionError(f"Failed to fetch JavaScript from '{url}': {e}")
    
    def download_linked_js(self, html_content, base_url):
        """
        Extracts <script src='...'> URLs and downloads each .js file.
        Returns a list of (url, content, html_line_number) tuples.
        """
        script_entries = self._extract_script_srcs(html_content, base_url)
        js_files = []
        for js_url, line_num in script_entries:
            try:
                js_content = self.fetch_js(js_url)
                js_files.append((js_url, js_content, line_num))
            except ConnectionError:
                continue
        return js_files
    
    def _extract_script_srcs(self, html_content, base_url):
        """
        Finds all <script src="..."> tags and returns a list of (absolute_url, html_line_number).
        """
        lines = html_content.split('\n')
        entries = []
        # Find tags line by line to capture line numbers
        for i, line in enumerate(lines, start=1):
            matches = re.findall(r'<script[^>]+src=["\']([^"\']+\.js)["\']', line, re.IGNORECASE)
            for match in matches:
                full_url = urljoin(base_url, match)
                entries.append((full_url, i))
        return entries
