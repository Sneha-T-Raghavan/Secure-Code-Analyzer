"""
Code Scanner Module

This module is responsible for parsing source code files and preparing them for 
vulnerability analysis.
"""

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
        """Scan a single file for code parsing
        
        Args:
            file_path (str): Path to the file to scan
            
        Returns:
            dict: Parsed representation of the file content
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # Determine file language from extension
            import os
            _, ext = os.path.splitext(file_path)
            language = self.supported_extensions.get(ext.lower(), 'unknown')
            
            if language == 'unknown':
                print(f'Warning: Unsupported file type {ext}')
                return None
                
            # Parse the content based on language
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
        """Scan all files in a directory recursively
        
        Args:
            directory_path (str, optional): Directory to scan. Defaults to self.target_path.
            
        Returns:
            list: List of parsed file contents
        """
        if directory_path is None:
            directory_path = self.target_path
            
        if directory_path is None:
            raise ValueError('No directory specified for scanning')
        
        results = []
        import os
        
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
        """Parse code content based on the programming language
        
        Args:
            content (str): Source code content
            language (str): Programming language
            
        Returns:
            dict: Parsed representation of the code
        """
        # This is a placeholder. In a real implementation, you would use
        # language-specific parsers or AST generators.
        
        # For now, just return lines of code
        lines = content.split('\n')
        return {
            'lines': lines,
            'line_count': len(lines)
        }