 # scanner/input_handler.py
import os
from .web_fetcher import WebFetcher

class InputHandler:
    def __init__(self):
        self.web_fetcher = WebFetcher()
    
    def accept_input(self, source):
        """
        Accepts a file path, URL, or directory path.
        Returns a dict with 'html' (content) and 'external_js' for files/URLs,
        or None if the source is a directory (to be handled separately).
        """
        if source.startswith(('http://', 'https://')):
            html_content = self.web_fetcher.fetch(source)
            external_js = self.web_fetcher.download_linked_js(html_content, source)
            return {'html': html_content, 'external_js': external_js}
        elif os.path.isdir(source):
            return None   # signal that this is a folder
        elif os.path.isfile(source):
            with open(source, 'r', encoding='utf-8') as f:
                content = f.read()
            return {'html': content, 'external_js': []}
        else:
            raise ValueError(f"Invalid source: {source}")
    
    def get_files_from_folder(self, folder_path):
        """
        Recursively returns a list of file paths for all supported files
        in the given folder.
        """
        supported_ext = ('.js', '.html', '.php', '.txt')
        files = []
        for root, dirs, filenames in os.walk(folder_path):
            for f in filenames:
                if f.lower().endswith(supported_ext):
                    files.append(os.path.join(root, f))
        return files