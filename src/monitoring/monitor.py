import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from code_scanner.scanner import CodeScanner
from vulnerability_detector.detector import VulnerabilityDetector

class CodeChangeHandler(FileSystemEventHandler):
    def __init__(self, directory, detector):
        self.directory = directory
        self.detector = detector
        self.scanner = CodeScanner(directory)

    def on_modified(self, event):
        if event.is_directory:
            return
        file_path = event.src_path
        if not file_path.endswith(tuple(self.scanner.supported_extensions.keys())):
            return
        print(f"\nDetected modification in {file_path} at {time.ctime()}")
        parsed_code = self.scanner.scan_file(file_path)
        if parsed_code:
            vulnerabilities = self.detector.analyze_code(parsed_code)
            if vulnerabilities:
                report = self.detector.generate_report(vulnerabilities)
                print(f"New vulnerabilities detected in {file_path}:")
                print(f"Total vulnerabilities: {report['total_vulnerabilities']}")
                print("Vulnerability types:")
                for vuln_type, count in report['vulnerability_types'].items():
                    print(f"  - {vuln_type}: {count}")
                print("Severity counts:")
                for severity, count in report['severity_counts'].items():
                    print(f"  - {severity}: {count}")
                print("\nDetails:")
                for vuln in report['details']:
                    print(f"  - {vuln['type']} ({vuln['severity']}) in {vuln['file_path']} line {vuln['line_number']}")
            else:
                print(f"No new vulnerabilities detected in {file_path}")

def monitor_directory(directory):
    detector = VulnerabilityDetector()
    event_handler = CodeChangeHandler(directory, detector)
    observer = Observer()
    observer.schedule(event_handler, directory, recursive=True)
    observer.start()
    print(f"Started monitoring directory: {directory}")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("\nStopped monitoring directory")
    observer.join()