import os

class CodeScanner:
    def __init__(self, target_path=None):
        self.target_path = target_path
        self.supported_extensions = {
            '.py': 'python',
            '.js': 'javascript',
            '.java': 'java',
            '.php': 'php',
            '.c': 'c',
            '.cpp': 'cpp'
        }
        
    def scan_file(self, file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            _, ext = os.path.splitext(file_path)
            language = self.supported_extensions.get(ext.lower(), 'unknown')
            if language == 'unknown':
                print(f'Warning: Unsupported file type {ext}')
                return None
            parsed_content = self.parse_code(content, language)
            return {
                'file_path': file_path,
                'language': language,
                'content': content,
                'parsed': parsed_content
            }
        except Exception as e:
            print(f'Error scanning file {file_path}: {str(e)}')
            return None
        
    def scan_directory(self, directory_path=None):
        if directory_path is None:
            directory_path = self.target_path
        if directory_path is None:
            raise ValueError('No directory specified for scanning')
        results = []
        for root, _, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                _, ext = os.path.splitext(file_path)
                if ext.lower() in self.supported_extensions:
                    result = self.scan_file(file_path)
                    if result:
                        results.append(result)
        return results
        
    def parse_code(self, content, language):
        lines = content.split('\n')
        return {
            'lines': lines,
            'line_count': len(lines)
        }