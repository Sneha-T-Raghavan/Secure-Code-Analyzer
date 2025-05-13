import argparse
import os
import json
from code_scanner.scanner import CodeScanner
from vulnerability_detector.detector import VulnerabilityDetector
from encryption.encryptor import EncryptionFramework

def parse_arguments():
    # Create an ArgumentParser with a detailed description for --help
    parser = argparse.ArgumentParser(
        description=(
            "Secure Code Analyzer & Encryption Framework\n\n"
            "This tool helps you scan source code for vulnerabilities, encrypt files using various algorithms, "
            "and compare encryption algorithms for performance and security. Use the options below to specify "
            "the desired action. All paths should be valid file or directory paths."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Add arguments with detailed help messages
    parser.add_argument(
        '--scan', '-s',
        help=(
            "Path to a file or directory to scan for vulnerabilities. "
            "If a directory is provided, the tool will recursively scan all supported files. "
            "Supported file extensions: .py, .js, .java, .php, .c, .cpp."
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
        choices=['aes', 'chacha20', 'blowfish', 'rsa', 'tripledes', 'camellia'],
        help=(
            "Encryption algorithm to use for the --encrypt option. If not specified, the tool will automatically "
            "select the best algorithm based on a balanced priority of speed and security."
        )
    )
    parser.add_argument(
        '--output', '-o',
        help=(
            "Output file path for scan results or comparison plots. "
            "For --scan, results are saved as a JSON file. For --compare, plots are saved as PNG files. "
            "If not specified, results are printed to the console, and plots use a default filename."
        )
    )
    
    return parser.parse_args()

def main():
    args = parse_arguments()
    
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
        report = detector.generate_report(all_vulnerabilities)
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

    if args.compare:
        encryptor = EncryptionFramework()
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
        else:
            print(f'Comparison failed: {comparison.get("error", "Unknown error")}')

if __name__ == '__main__':
    main()