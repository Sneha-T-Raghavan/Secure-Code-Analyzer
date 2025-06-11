"""
Adapter module to connect the existing Secure Code Analyzer with the Flask API.
This acts as a bridge between your existing analyzer code and the web interface.
"""

import sys
import os
import json

from .scanner import CodeScanner
from .detector import VulnerabilityDetector

def analyze_code(file_path, language='python'):
    """
    Analyze the code in the given file for security vulnerabilities and fix them.

    Args:
        file_path (str): Path to the file to analyze
        language (str): Programming language of the file

    Returns:
        dict: Contains vulnerabilities found and fixed code (if applicable)
    """
    scanner = CodeScanner()
    parsed_code = scanner.scan_file(file_path)

    if parsed_code is None:
        return {'vulnerabilities': [], 'fixed': False, 'fixed_code': None}

    detector = VulnerabilityDetector()
    vulnerabilities = detector.analyze_code(parsed_code)

    # Attempt to fix vulnerabilities
    success, result = detector.fix_vulnerabilities(parsed_code)
    fixed_code = None
    fixes_applied = []

    if success:
        fixes_applied = result
        # Read the fixed code from the file
        with open(file_path, 'r', encoding='utf-8') as f:
            fixed_code = f.read()
    else:
        if result != "No fixes applied":
            print(f"Fixing vulnerabilities failed: {result}")

    return {
        'vulnerabilities': vulnerabilities,
        'fixed': success,
        'fixed_code': fixed_code,
        'fixes_applied': fixes_applied
    }

def report_vulnerabilities(vulnerabilities):
    """
    Format the vulnerabilities for API response.

    Args:
        vulnerabilities (list): Raw vulnerabilities from the analyzer

    Returns:
        list: Formatted vulnerabilities for API response
    """
    formatted_vulnerabilities = []

    for vuln in vulnerabilities:
        # Ensure severity is lowercase to match frontend expectations
        severity = vuln.get('severity', 'medium').lower()
        formatted_vuln = {
            'type': vuln.get('type', 'Unknown'),
            'line_number': vuln.get('line_number', 0),
            'severity': severity,
            'code_snippet': vuln.get('code_snippet', ''),
            'file_path': vuln.get('file_path', 'unknown'),
            'language': vuln.get('language', 'unknown'),
            'recommendation': get_recommendation(vuln.get('type', 'Unknown'))
        }
        formatted_vulnerabilities.append(formatted_vuln)

    return formatted_vulnerabilities

def get_recommendation(vuln_type):
    """
    Provide a basic recommendation based on vulnerability type.

    Args:
        vuln_type (str): Type of vulnerability

    Returns:
        str: Suggested fix or recommendation
    """
    recommendations = {
        'hardcoded_credentials': 'Avoid hardcoding credentials. Use environment variables or secrets management tools.',
        'sql_injection': 'Use parameterized queries or ORM frameworks to avoid SQL injection.',
        'weak_encryption': 'Use stronger hashing algorithms like SHA-256 or bcrypt.',
        'insecure_api': 'Avoid using insecure functions like eval, exec, or system. Use safer alternatives.'
    }
    return recommendations.get(vuln_type, 'Fix the identified vulnerability.')