import argparse
import os
import json
from code_scanner.scanner import CodeScanner
from vulnerability_detector.detector import VulnerabilityDetector
from encryption.encryptor import EncryptionFramework
from monitoring.monitor import monitor_directory

def parse_arguments():
    parser = argparse.ArgumentParser(
        description=(
            "Secure Code Analyzer & Encryption Framework\n\n"
            "This tool helps you scan source code for vulnerabilities, encrypt files using various algorithms, "
            "and compare encryption algorithms for performance and security. Use the options below to specify "
            "the desired action. All paths should be valid file or directory paths."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '--scan', '-s',
        help=(
            "Path to a file or directory to scan for vulnerabilities. "
            "If a directory is provided, the tool will recursively scan all supported files. "
            "Supported file extensions: .py, .js, .java, .php, .c, .cpp."
        )
    )
    parser.add_argument(
        '--fix', '-f',
        action='store_true',
        help=(
            "Automatically fix detected vulnerabilities after scanning. "
            "Currently supports replacing hardcoded credentials with environment variables."
        )
    )
    parser.add_argument(
        '--encrypt', '-e',
        help=(
            "Path to a file to encrypt. The file will be encrypted using the specified algorithm, "
            "or the tool will automatically select the best algorithm if none is specified. "
            "Encrypted file and key will be saved with .encrypted and .key extensions."
        )
    )
    parser.add_argument(
        '--compare', '-c',
        help=(
            "Path to a file for comparing encryption algorithms. The tool will benchmark all supported algorithms "
            "on a 4KB sample of the file and generate performance and security comparison plots."
        )
    )
    parser.add_argument(
        '--algorithm', '-a',
        choices=['aes', 'chacha20', 'blowfish', 'rsa', 'tripledes', 'camellia', 'hybrid'],
        help=(
            "Encryption algorithm to use for the --encrypt option. If not specified, the tool will automatically "
            "select the best algorithm based on a balanced priority of speed and security."
        )
    )
    parser.add_argument(
        '--hash-algorithm',
        choices=['sha256', 'sha3_256'],
        default='sha256',
        help=(
            "Hash algorithm to use for integrity checking during encryption. "
            "Options: sha256 (default), sha3_256."
        )
    )
    parser.add_argument(
        '--verify', '-v',
        help=(
            "Path to a file to verify its integrity against the stored hash. "
            "Requires the corresponding .key file from encryption."
        )
    )
    parser.add_argument(
        '--monitor', '-m',
        help=(
            "Path to a directory to monitor for changes in real-time. "
            "The tool will re-scan modified files for vulnerabilities and report new issues."
        )
    )
    parser.add_argument(
        '--output', '-o',
        help=(
            "Output file path for scan results, comparison plots, or unified reports. "
            "For --scan/--encrypt, results are saved as a JSON file. For --compare, plots are saved as PNG files. "
            "If not specified, results are printed to the console, and plots use a default filename."
        )
    )
    
    return parser.parse_args()

def main():
    args = parse_arguments()
    
    # Initialize components
    unified_report = {}
    scanner = None
    detector = None
    encryptor = EncryptionFramework()

    # Handle scanning and fixing vulnerabilities
    if args.scan:
        scanner = CodeScanner(args.scan)
        detector = VulnerabilityDetector()
        print(f'Scanning {args.scan} for vulnerabilities...')
        if os.path.isfile(args.scan):
            parsed_code = scanner.scan_file(args.scan)
            results = [parsed_code] if parsed_code else []
        else:
            results = scanner.scan_directory(args.scan)
        print(f'Scanned {len(results)} files')
        all_vulnerabilities = []
        for result in results:
            vulnerabilities = detector.analyze_code(result)
            all_vulnerabilities.extend(vulnerabilities)
        
        # Add vulnerability report to unified report
        vuln_report = detector.generate_report(all_vulnerabilities)
        unified_report['vulnerability_report'] = vuln_report

        # Fix vulnerabilities if requested
        if args.fix and os.path.isfile(args.scan):
            print(f"Attempting to fix vulnerabilities in {args.scan}...")
            success, fixes = detector.fix_vulnerabilities(results[0])
            if success:
                print("Fixes applied:")
                for fix in fixes:
                    print(f"  - {fix['type']} at line {fix['line_number']}: {fix['original']} -> {fix['fixed']}")
                # Re-scan after fixes
                print("Re-scanning after fixes...")
                parsed_code = scanner.scan_file(args.scan)
                new_vulnerabilities = detector.analyze_code(parsed_code)
                new_vuln_report = detector.generate_report(new_vulnerabilities)
                unified_report['vulnerability_report_after_fixes'] = new_vuln_report
            else:
                print(f"Fixing failed: {fixes}")

        # Print vulnerability report if not encrypting (to avoid redundancy)
        if not args.encrypt:
            print('Vulnerability Report:')
            print(f'Total vulnerabilities: {vuln_report["total_vulnerabilities"]}')
            print('Vulnerability types:')
            for vuln_type, count in vuln_report['vulnerability_types'].items():
                print(f'  - {vuln_type}: {count}')
            print('Severity counts:')
            for severity, count in vuln_report['severity_counts'].items():
                print(f'  - {severity}: {count}')
            if vuln_report['details']:
                print('\nTop 5 vulnerabilities:')
                for vuln in vuln_report['details'][:5]:
                    print(f'  - {vuln["type"]} ({vuln["severity"]}) in {vuln["file_path"]} line {vuln["line_number"]}')

    # Handle encryption
    if args.encrypt:
        print(f'Encrypting {args.encrypt}...')
        result = encryptor.encrypt_file(args.encrypt, args.algorithm, args.hash_algorithm)
        if result['success']:
            print(f'Successfully encrypted using {result["algorithm"]}')
            print(f'Encrypted file: {result["encrypted_file"]}')
            print(f'Key file: {result["key_file"]}')
            print(f'Encryption time: {result["encryption_time"]:.4f} seconds')
            print(f'Integrity hash ({args.hash_algorithm}): {result["integrity_hash"]}')
            unified_report['encryption_report'] = result
        else:
            print(f'Encryption failed: {result.get("error", "Unknown error")}')
            unified_report['encryption_report'] = {'success': False, 'error': result.get('error')}

    # Handle algorithm comparison
    if args.compare:
        print(f'Comparing encryption algorithms for {args.compare}...')
        with open(args.compare, 'rb') as f:
            data = f.read()[:4096]
        comparison = encryptor.compare_algorithms(data, args.output or 'algorithm_comparison.png')
        if comparison.get('success', True):
            print('Algorithm Comparison Results:')
            print('Performance Metrics:')
            for alg, metrics in comparison['performance'].items():
                print(f'  - {alg}: Time={metrics["time"]:.4f}s, Size={metrics["size"]} bytes')
            print('Security Metrics:')
            for alg, metrics in comparison['security'].items():
                print(f'  - {alg}: Score={metrics["score"]}, Key Strength={metrics["key_strength"]} bits, Vulnerabilities={metrics["vulnerabilities"]}')
            print(f'Best for Speed: {comparison["best_speed"]}')
            print(f'Best for Security: {comparison["best_security"]}')
            print(f'Plots saved: {", ".join(comparison["plots"])}')
            unified_report['comparison_report'] = comparison
        else:
            print(f'Comparison failed: {comparison.get("error", "Unknown error")}')
            unified_report['comparison_report'] = {'success': False, 'error': comparison.get('error')}

    # Handle integrity verification
    if args.verify:
        print(f'Verifying integrity of {args.verify}...')
        key_file = args.verify + '.key'
        if not os.path.exists(key_file):
            print(f"Key file {key_file} not found")
            return
        with open(key_file, 'r') as f:
            key_data = json.load(f)
        integrity_hash = key_data.get('integrity_hash')
        hash_algorithm = key_data.get('hash_algorithm', 'sha256')
        if not integrity_hash:
            print("No integrity hash found in key file")
            return
        with open(args.verify, 'rb') as f:
            data = f.read()
        if encryptor.verify_integrity_hash(data, integrity_hash, hash_algorithm):
            print("Integrity verified: The file has not been tampered with")
        else:
            print("Integrity verification failed: The file may have been tampered with")

    # Handle real-time monitoring
    if args.monitor:
        monitor_directory(args.monitor)

    # Generate unified report if both scan and encrypt are used
    if args.scan and args.encrypt and unified_report.get('vulnerability_report') and unified_report.get('encryption_report'):
        print("\nUnified Security Report:")
        print("1. Vulnerability Analysis:")
        vuln_report = unified_report['vulnerability_report']
        print(f"   Total vulnerabilities: {vuln_report['total_vulnerabilities']}")
        print("   Vulnerability types:")
        for vuln_type, count in vuln_report['vulnerability_types'].items():
            print(f"     - {vuln_type}: {count}")
        print("   Severity counts:")
        for severity, count in vuln_report['severity_counts'].items():
            print(f"     - {severity}: {count}")
        if vuln_report['details']:
            print("   Top vulnerabilities:")
            for vuln in vuln_report['details'][:5]:
                print(f"     - {vuln['type']} ({vuln['severity']}) in {vuln['file_path']} line {vuln['line_number']}")
        if 'vulnerability_report_after_fixes' in unified_report:
            print("\n2. Vulnerability Analysis After Fixes:")
            fixed_report = unified_report['vulnerability_report_after_fixes']
            print(f"   Total vulnerabilities: {fixed_report['total_vulnerabilities']}")
            print("   Vulnerability types:")
            for vuln_type, count in fixed_report['vulnerability_types'].items():
                print(f"     - {vuln_type}: {count}")
            print("   Severity counts:")
            for severity, count in fixed_report['severity_counts'].items():
                print(f"     - {severity}: {count}")
        print("\n3. Encryption Details:")
        enc_report = unified_report['encryption_report']
        if enc_report['success']:
            print(f"   Algorithm used: {enc_report['algorithm']}")
            print(f"   Encryption time: {enc_report['encryption_time']:.4f} seconds")
            print(f"   Original size: {enc_report['original_size']} bytes")
            print(f"   Encrypted size: {enc_report['encrypted_size']} bytes")
            print(f"   Integrity hash ({args.hash_algorithm}): {enc_report['integrity_hash']}")
        else:
            print(f"   Encryption failed: {enc_report.get('error')}")
        
        # Save unified report if output is specified
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(unified_report, f, indent=2)
            print(f"\nUnified security report saved to {args.output}")

if __name__ == '__main__':
    main()