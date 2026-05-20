"""
Test Suite: Evaluates the Static JavaScript Vulnerability Scanner
Tests detection accuracy, false positive rate, and performance.
Run: ./venv/bin/python tests/test_scanner.py
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.input_handler import InputHandler
from scanner.code_extractor import CodeExtractor
from scanner.core_engine import CoreAnalysisEngine
from scanner.report_generator import ReportGenerator

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), 'test_samples')


def scan_file(filepath):
    handler = InputHandler()
    extractor = CodeExtractor()
    engine = CoreAnalysisEngine()
    data = handler.accept_input(filepath)
    parts = extractor.extract_with_origins(data['html'], external_js=data['external_js'])
    vulns, urls = engine.scan(parts, filepath)
    return vulns


def test_positive_detection():
    """Test that known vulnerable files are correctly detected."""
    print("\n" + "=" * 60)
    print("  POSITIVE TESTING - Known Vulnerabilities")
    print("=" * 60)

    test_cases = [
        ('sql_injection_basic.js', 'CWE-89', 'SQL Injection'),
        ('xss_innerHTML.js', 'CWE-79', 'Cross-Site Scripting (XSS)'),
        ('command_injection_exec.js', 'CWE-78', 'Command Injection'),
        ('hardcoded_secret.js', 'CWE-798', 'Hardcoded Secret'),
        ('eval_user_input.js', 'CWE-95', 'Insecure Use of eval()'),
    ]

    passed = 0
    for filename, expected_cwe, vuln_name in test_cases:
        filepath = os.path.join(SAMPLES_DIR, filename)
        vulns = scan_file(filepath)
        cwe_ids = [v.cwe_id for v in vulns]
        detected = expected_cwe in cwe_ids
        status = "✓ PASS" if detected else "✗ FAIL"
        passed += int(detected)
        print(f"  {status} | {filename:35s} | Expected: {expected_cwe} ({vuln_name})")
        if not detected:
            print(f"         Found: {cwe_ids}")

    print(f"\n  Result: {passed}/{len(test_cases)} detected (Recall: {passed/len(test_cases)*100:.0f}%)")
    return passed, len(test_cases)


def test_negative_detection():
    """Test that safe code does NOT trigger false positives."""
    print("\n" + "=" * 60)
    print("  NEGATIVE TESTING - Safe Code (False Positive Check)")
    print("=" * 60)

    filepath = os.path.join(SAMPLES_DIR, 'safe_parameterized_query.js')
    vulns = scan_file(filepath)
    fp_count = len(vulns)
    status = "✓ PASS" if fp_count == 0 else "✗ FAIL"
    print(f"  {status} | safe_parameterized_query.js | Vulnerabilities found: {fp_count}")
    if fp_count > 0:
        for v in vulns:
            print(f"         False positive: [{v.cwe_id}] {v.type} at line {v.line_number}")

    print(f"\n  Result: False positives = {fp_count}")
    return fp_count == 0


def test_performance():
    """Test scanning speed."""
    print("\n" + "=" * 60)
    print("  PERFORMANCE TESTING")
    print("=" * 60)

    filepath = os.path.join(SAMPLES_DIR, 'sql_injection_basic.js')
    start = time.time()
    for _ in range(10):
        scan_file(filepath)
    elapsed = time.time() - start
    avg = elapsed / 10

    status = "✓ PASS" if avg < 2.0 else "✗ SLOW"
    print(f"  {status} | Average scan time: {avg:.3f}s per file")
    print(f"         (10 scans completed in {elapsed:.2f}s)")
    return avg < 2.0


def test_error_handling():
    """Test graceful handling of invalid inputs."""
    print("\n" + "=" * 60)
    print("  ERROR HANDLING - Robustness")
    print("=" * 60)

    # Malformed JS
    malformed = "/tmp/malformed_test.js"
    with open(malformed, 'w') as f:
        f.write("function broken( { var x = ; }")

    try:
        vulns = scan_file(malformed)
        print(f"  ✓ PASS | Malformed JS handled gracefully (no crash)")
    except Exception as e:
        print(f"  ✗ FAIL | Crashed on malformed JS: {e}")
        return False

    # Empty file
    empty = "/tmp/empty_test.js"
    with open(empty, 'w') as f:
        f.write("")

    try:
        vulns = scan_file(empty)
        print(f"  ✓ PASS | Empty file handled gracefully")
    except Exception as e:
        print(f"  ✗ FAIL | Crashed on empty file: {e}")
        return False

    return True


if __name__ == '__main__':
    print("\n" + "╔" + "═" * 58 + "╗")
    print("║  SecScan JS - Scanner Evaluation Test Suite              ║")
    print("╚" + "═" * 58 + "╝")

    tp, total = test_positive_detection()
    no_fp = test_negative_detection()
    fast = test_performance()
    robust = test_error_handling()

    print("\n" + "=" * 60)
    print("  FINAL SUMMARY")
    print("=" * 60)
    print(f"  Detection Rate (Recall):  {tp}/{total} = {tp/total*100:.0f}%")
    print(f"  False Positive Free:      {'Yes' if no_fp else 'No'}")
    print(f"  Performance (<2s/file):   {'Yes' if fast else 'No'}")
    print(f"  Error Handling:           {'Robust' if robust else 'Issues'}")
    print("=" * 60)

    all_pass = (tp == total) and no_fp and fast and robust
    print(f"\n  {'✅ ALL TESTS PASSED' if all_pass else '⚠️  SOME TESTS FAILED'}")
    sys.exit(0 if all_pass else 1)
