import re
import os

class VulnerabilityDetector:
    def __init__(self):
        self.vulnerability_patterns = {
            'hardcoded_credentials': [
                r'password\s*=\s*[\'"][\w\d]+[\'"]',
                r'api_key\s*=\s*[\'"][\w\d]+[\'"]',
                r'secret\s*=\s*[\'"][\w\d]+[\'"]'
            ],
            'sql_injection': [
                r'execute\([\'"]SELECT.*\%s',
                r'execute\([\'"]INSERT.*\%s',
                r'execute\([\'"]UPDATE.*\%s',
                r'execute\([\'"]DELETE.*\%s'
            ],
            'weak_encryption': [
                r'MD5\(',
                r'SHA1\(',
                r'DES\('
            ],
            'insecure_api': [
                r'eval\(',
                r'exec\(',
                r'system\('
            ]
        }
    
    def analyze_code(self, parsed_code):
        vulnerabilities = []
        if not parsed_code or 'content' not in parsed_code:
            return vulnerabilities
        content = parsed_code['content']
        file_path = parsed_code.get('file_path', 'unknown')
        language = parsed_code.get('language', 'unknown')
        for vuln_type, patterns in self.vulnerability_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    line_number = content[:match.start()].count('\n') + 1
                    code_snippet = match.group(0)
                    vulnerabilities.append({
                        'type': vuln_type,
                        'file_path': file_path,
                        'language': language,
                        'line_number': line_number,
                        'code_snippet': code_snippet,
                        'severity': self._determine_severity(vuln_type)
                    })
        return vulnerabilities
        
    def _determine_severity(self, vuln_type):
        severity_levels = {
            'hardcoded_credentials': 'high',
            'sql_injection': 'high',
            'weak_encryption': 'medium',
            'insecure_api': 'high'
        }
        return severity_levels.get(vuln_type, 'medium')
        
    def generate_report(self, vulnerabilities):
        if not vulnerabilities:
            return {
                'total_vulnerabilities': 0,
                'vulnerability_types': {},
                'severity_counts': {},
                'details': []
            }
        vuln_types = {}
        severity_counts = {'high': 0, 'medium': 0, 'low': 0}
        for vuln in vulnerabilities:
            vuln_type = vuln['type']
            severity = vuln['severity']
            vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        return {
            'total_vulnerabilities': len(vulnerabilities),
            'vulnerability_types': vuln_types,
            'severity_counts': severity_counts,
            'details': vulnerabilities
        }

    def fix_vulnerabilities(self, parsed_code):
        """Fix detected vulnerabilities in the code."""
        if not parsed_code or 'content' not in parsed_code or 'file_path' not in parsed_code:
            return False, "Invalid parsed code or missing file path"

        content = parsed_code['content']
        file_path = parsed_code['file_path']
        language = parsed_code.get('language', 'unknown')
        vulnerabilities = self.analyze_code(parsed_code)
        fixes_applied = []
        modified_content = content

        # Fix hardcoded credentials by replacing with environment variables
        for vuln in vulnerabilities:
            if vuln['type'] == 'hardcoded_credentials':
                code_snippet = vuln['code_snippet']
                var_name = code_snippet.split('=')[0].strip()
                env_var_name = var_name.upper()
                new_code = f"{var_name} = os.environ.get(\"{env_var_name}\")"
                lines = modified_content.split('\n')
                line_number = vuln['line_number'] - 1
                lines[line_number] = new_code
                modified_content = '\n'.join(lines)
                fixes_applied.append({
                    'type': vuln['type'],
                    'file_path': file_path,
                    'line_number': vuln['line_number'],
                    'original': code_snippet,
                    'fixed': new_code
                })
            elif vuln['type'] == 'sql_injection' and language == 'python':
                # Example fix for SQL injection: Replace %s with parameterized query placeholder
                code_snippet = vuln['code_snippet']
                if '%s' in code_snippet:
                    # Simplified fix: Replace %s with a placeholder (e.g., :param)
                    new_code = code_snippet.replace('%s', ':param')
                    lines = modified_content.split('\n')
                    line_number = vuln['line_number'] - 1
                    lines[line_number] = new_code
                    modified_content = '\n'.join(lines)
                    fixes_applied.append({
                        'type': vuln['type'],
                        'file_path': file_path,
                        'line_number': vuln['line_number'],
                        'original': code_snippet,
                        'fixed': new_code
                    })
            elif vuln['type'] == 'weak_encryption':
                # Example fix: Replace MD5/SHA1/DES with SHA-256
                code_snippet = vuln['code_snippet']
                new_code = code_snippet.replace('MD5', 'SHA256').replace('SHA1', 'SHA256').replace('DES', 'SHA256')
                lines = modified_content.split('\n')
                line_number = vuln['line_number'] - 1
                lines[line_number] = new_code
                modified_content = '\n'.join(lines)
                fixes_applied.append({
                    'type': vuln['type'],
                    'file_path': file_path,
                    'line_number': vuln['line_number'],
                    'original': code_snippet,
                    'fixed': new_code
                })

        # Write the modified content back to the file
        if fixes_applied:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(modified_content)
                return True, fixes_applied
            except Exception as e:
                return False, f"Failed to write fixes to file: {str(e)}"
        return False, "No fixes applied"