# scanner/report_generator.py

class ReportGenerator:
    @staticmethod
    def generate_summary(vulnerabilities):
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        for vuln in vulnerabilities:
            sev = getattr(vuln, 'severity', 'Medium')
            if sev in severity_counts:
                severity_counts[sev] += 1
        return {
            'total': len(vulnerabilities),
            'severity_counts': severity_counts
        }

    @staticmethod
    def to_dict_list(vulnerabilities):
        return [v.to_dict() for v in vulnerabilities]
