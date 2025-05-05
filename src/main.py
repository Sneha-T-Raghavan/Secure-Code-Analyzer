"""
Main Module

Entry point for the Secure Code Analyzer & Encryption Framework.
"""
import argparse
import os
import json
from code_scanner.scanner import CodeScanner
from vulnerability_detector.detector import VulnerabilityDetector
from encryption.encryptor import EncryptionFramework

def parse_arguments():
    parser = argparse.ArgumentParser(description='Secure Code Analyzer & Encryption Framework')
    
    parser.add_argument('--scan', '-s', help='Path to file or directory to scan')
    parser.add_argument('--encrypt', '-e', help='Path to file to encrypt')
    parser.add_argument('--algorithm', '-a', choices=['aes', 'chacha20', 'blowfish', 'rsa'], 
                        help='Encryption algorithm to use')
    parser.add_argument('--output', '-o', help='Output file for scan results')
    
    return parser.parse_args()

def main():
    args = parse_arguments()
    
    if args.scan:
        # Initialize scanner and detector
        scanner = CodeScanner(args.scan)
        detector = VulnerabilityDetector()
        
        print(f'Scanning {args.scan} for vulnerabilities...')
        
        if os.path.isfile(args.scan):
            # Scan single file
            parsed_code = scanner.scan_file(args.scan)
            results = [parsed_code] if parsed_code else []
        else:
            # Scan directory
            results = scanner.scan_directory(args.scan)
        
        print(f'Scanned {len(results)} files')
        
        # Analyze for vulnerabilities
        all_vulnerabilities = []
        for result in results:
            vulnerabilities = detector.analyze_code(result)
            all_vulnerabilities.extend(vulnerabilities)
        
        # Generate report
        report = detector.generate_report(all_vulnerabilities)
        
        # Output report
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(report, f, indent=2)
            print(f'Vulnerability report saved to {args.output}')
        else:
            print('Vulnerability Report:')
            print(f'Total vulnerabilities: {report["total_vulnerabilities"]}')
            print('Vulnerability types:')
            for vuln_type, count in report['vulnerability_types'].items():
                print(f'  - {vuln_type}: {count}')
            print('Severity counts:')
            for severity, count in report['severity_counts'].items():
                print(f'  - {severity}: {count}')
            
            if report['details']:
                print('\nTop 5 vulnerabilities:')
                for vuln in report['details'][:5]:
                    print(f'  - {vuln["type"]} ({vuln["severity"]}) in {vuln["file_path"]} line {vuln["line_number"]}')
    
    if args.encrypt:
        # Initialize encryption framework
        encryptor = EncryptionFramework()
        
        print(f'Encrypting {args.encrypt}...')
        result = encryptor.encrypt_file(args.encrypt, args.algorithm)
        
        if result['success']:
            print(f'Successfully encrypted using {result["algorithm"]}')
            print(f'Encrypted file: {result["encrypted_file"]}')
            print(f'Key file: {result["key_file"]}')
            print(f'Encryption time: {result["encryption_time"]:.4f} seconds')
        else:
            print(f'Encryption failed: {result.get("error", "Unknown error")}')

if __name__ == '__main__':
    main()