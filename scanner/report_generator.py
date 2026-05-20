# scanner/report_generator.py
class ReportGenerator:
    """Generates structured reports from vulnerabilities list."""
    
    @staticmethod
    def generate_summary(vulnerabilities):
        """Return summary dict for web display."""
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        for vuln in vulnerabilities:
            # Simple severity mapping based on CWE (you can enhance this)
            if vuln.cwe_id in ['CWE-89', 'CWE-78']:
                severity_counts['Critical'] += 1
            elif vuln.cwe_id in ['CWE-79', 'CWE-798']:
                severity_counts['High'] += 1
            else:
                severity_counts['Medium'] += 1
        return {
            'total': len(vulnerabilities),
            'severity_counts': severity_counts
        }
    
    @staticmethod
    def to_dict_list(vulnerabilities):
        return [v.to_dict() for v in vulnerabilities]
