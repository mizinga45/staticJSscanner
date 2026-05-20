from abc import ABC, abstractmethod

class VulnerabilityRule(ABC):
    def __init__(self, vuln_type, cwe_id, description):
        self.vuln_type = vuln_type
        self.cwe_id = cwe_id
        self.description = description
    
    @abstractmethod
    def detect(self, ast, file_path, code_lines):
        pass
