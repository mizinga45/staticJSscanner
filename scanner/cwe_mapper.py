# scanner/cwe_mapper.py
import json
import os

class CWEMapper:
    """Maps vulnerability types to CWE IDs and provides descriptions."""
    
    def __init__(self, cwe_db_path=None):
        if cwe_db_path is None:
            cwe_db_path = os.path.join(
                os.path.dirname(__file__), '..', 'data', 'cwe_database.json'
            )
        with open(cwe_db_path, 'r') as f:
            self.cwe_db = json.load(f)
    
    def get_cwe_details(self, vuln_type):
        """Return CWE details for a given vulnerability type."""
        return self.cwe_db.get(vuln_type, {
            'cwe_id': 'CWE-Unknown',
            'description': 'No description available.',
            'remediation': 'Review the code for potential security issues.'
        })
