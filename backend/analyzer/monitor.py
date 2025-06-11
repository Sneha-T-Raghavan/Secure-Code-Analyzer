import os
import time
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from analyzer.analyzer import analyze_code, report_vulnerabilities
from analyzer.encryptor import EncryptionFramework

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='monitor.log'
)

class CodeChangeHandler(FileSystemEventHandler):
    def __init__(self, directory, hash_algorithm='sha256'):
        self.directory = directory
        self.encryptor = EncryptionFramework()
        self.hash_algorithm = hash_algorithm
        self.results = []  # Store monitoring events and scan results
        self.supported_extensions = {
            '.py': 'python',
            '.js': 'javascript',
            '.java': 'java',
            '.cpp': 'cpp',
            '.c': 'c'
        }

    def on_modified(self, event):
        if event.is_directory:
            return
        file_path = event.src_path
        if not any(file_path.endswith(ext) for ext in self.supported_extensions):
            return
        self.process_file(file_path, "modified")

    def on_created(self, event):
        if event.is_directory:
            return
        file_path = event.src_path
        if not any(file_path.endswith(ext) for ext in self.supported_extensions):
            return
        self.process_file(file_path, "created")

    def process_file(self, file_path, event_type):
        """Analyze the file for vulnerabilities and compute its hash."""
        try:
            # Determine language from file extension
            _, ext = os.path.splitext(file_path)
            language = self.supported_extensions.get(ext, 'python')

            # Analyze the file for vulnerabilities
            result = analyze_code(file_path, language)
            vulnerabilities = report_vulnerabilities(result['vulnerabilities'])
            fixed = result['fixed']
            fixes_applied = result['fixes_applied']

            # Compute integrity hash
            with open(file_path, 'rb') as f:
                data = f.read()
            integrity_hash = self.encryptor.compute_integrity_hash(data, self.hash_algorithm)

            # Store the event
            event_data = {
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'event_type': event_type,
                'file_path': file_path,
                'language': language,
                'vulnerabilities': vulnerabilities,
                'fixed': fixed,
                'fixes_applied': fixes_applied,
                'integrity_hash': integrity_hash,
                'hash_algorithm': self.hash_algorithm
            }
            logging.info(f"{event_type.upper()} event: {file_path} - {len(vulnerabilities)} vulnerabilities found")
            self.results.append(event_data)

        except Exception as e:
            logging.error(f"Error processing {file_path}: {str(e)}")
            self.results.append({
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'event_type': 'error',
                'file_path': file_path,
                'error': str(e)
            })

    def get_results(self):
        """Return the list of monitoring results."""
        return self.results

    def clear_results(self):
        """Clear stored results."""
        self.results = []

class MonitorManager:
    def __init__(self, directory):
        self.directory = os.path.abspath(directory)
        self.observer = None
        self.handler = None
        self.running = False

    def start(self, hash_algorithm='sha256'):
        """Start monitoring the directory."""
        if self.running:
            return {'success': False, 'error': 'Monitoring already running'}
        
        try:
            if not os.path.exists(self.directory):
                os.makedirs(self.directory)
            
            self.handler = CodeChangeHandler(self.directory, hash_algorithm)
            self.observer = Observer()
            self.observer.schedule(self.handler, self.directory, recursive=True)
            self.observer.start()
            self.running = True
            logging.info(f"Started monitoring {self.directory}")
            return {'success': True}
        except Exception as e:
            logging.error(f"Failed to start monitoring: {str(e)}")
            return {'success': False, 'error': str(e)}

    def stop(self):
        """Stop monitoring the directory."""
        if not self.running:
            return {'success': False, 'error': 'Monitoring not running'}
        
        try:
            self.observer.stop()
            self.observer.join()
            self.running = False
            logging.info(f"Stopped monitoring {self.directory}")
            return {'success': True}
        except Exception as e:
            logging.error(f"Failed to stop monitoring: {str(e)}")
            return {'success': False, 'error': str(e)}

    def get_results(self):
        """Return monitoring results if running."""
        if self.handler:
            return {'success': True, 'results': self.handler.get_results()}
        return {'success': False, 'error': 'Monitoring not running'}

    def clear_results(self):
        """Clear monitoring results."""
        if self.handler:
            self.handler.clear_results()
            return {'success': True}
        return {'success': False, 'error': 'Monitoring not running'}