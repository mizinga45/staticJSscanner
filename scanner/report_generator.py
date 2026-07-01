# scanner/report_generator.py

SEVERITY_ORDER = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}


def _sort_key(v):
    """Sort key for vulnerability objects or dicts — Critical first."""
    if isinstance(v, dict):
        sev = v.get('severity', 'Medium')
    else:
        sev = getattr(v, 'severity', 'Medium')
    return SEVERITY_ORDER.get(sev, 2)


class ReportGenerator:
    @staticmethod
    def generate_summary(vulnerabilities):
        # Sort by severity before summarising
        sorted_vulns = sorted(vulnerabilities, key=_sort_key)
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        for vuln in sorted_vulns:
            sev = getattr(vuln, 'severity', 'Medium')
            if sev in severity_counts:
                severity_counts[sev] += 1
        return {
            'total': len(vulnerabilities),
            'severity_counts': severity_counts
        }

    @staticmethod
    def to_dict_list(vulnerabilities):
        """Convert to dicts sorted Critical > High > Medium > Low."""
        dicts = [v.to_dict() for v in vulnerabilities]
        return sorted(dicts, key=_sort_key)
