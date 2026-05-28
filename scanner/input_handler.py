 # scanner/input_handler.py
import os
from .web_fetcher import WebFetcher


class InputHandler:
    def __init__(self):
        self.web_fetcher = WebFetcher()

    def accept_input(self, source):
        if source.startswith(('http://', 'https://')):
            html_content = self.web_fetcher.fetch(source)
            external_js = self.web_fetcher.download_linked_js(html_content, source)
            return {'html': html_content, 'external_js': external_js}
        elif os.path.isdir(source):
            return None
        elif os.path.isfile(source):
            with open(source, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
            return {'html': content, 'external_js': []}
        else:
            raise ValueError(f"Invalid source: {source}")

    def get_files_from_folder(self, folder_path, max_depth=6, js_only=False):
        """
        Returns list of file paths with configurable recursion depth.
        max_depth: 0 = current folder only, 6 = up to 6 levels deep
        js_only: if True, only return .js files
        """
        if js_only:
            supported_ext = ('.js',)
        else:
            supported_ext = ('.js', '.html', '.php', '.txt')

        files = []
        folder_path = os.path.abspath(folder_path)
        base_depth = folder_path.rstrip(os.sep).count(os.sep)

        for root, dirs, filenames in os.walk(folder_path):
            current_depth = root.count(os.sep) - base_depth
            if current_depth > max_depth:
                dirs.clear()  # Stop descending
                continue
            for f in filenames:
                if f.lower().endswith(supported_ext):
                    files.append(os.path.join(root, f))
        return files
