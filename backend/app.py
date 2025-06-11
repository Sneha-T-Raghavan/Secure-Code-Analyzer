from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import os
import sys
import tempfile
import logging
import traceback

from analyzer.analyzer import analyze_code, report_vulnerabilities
from analyzer.encryptor import EncryptionFramework

app = Flask(__name__)
CORS(app)  # Enable Cross-Origin Resource Sharing

# Initialize the encryption framework
encryptor = EncryptionFramework()


@app.route('/api/analyze-file', methods=['POST'])
def analyze_file():
    """
    Analyze, fix vulnerabilities, and optionally encrypt code from an uploaded file.
    Expects a file and optional 'encrypt' (bool) and 'algorithm' (str) in form data.
    """
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    # Determine the language from the file extension
    _, extension = os.path.splitext(file.filename)
    language = extension[1:] if extension else 'python'  # Remove the dot from the extension
    
    # Get encryption options from form data
    encrypt = request.form.get('encrypt', 'false').lower() == 'true'
    algorithm = request.form.get('algorithm', None)

    # Create a temporary file to analyze
    with tempfile.NamedTemporaryFile(suffix=extension, delete=False) as temp:
        temp_file_path = temp.name
        file.save(temp_file_path)
    
    try:
        # Analyze the code and fix vulnerabilities
        result = analyze_code(temp_file_path, language)
        vulnerabilities = result['vulnerabilities']
        fixed = result['fixed']
        fixed_code = result['fixed_code']
        fixes_applied = result['fixes_applied']
        
        # Format the vulnerabilities for the response
        formatted_vulnerabilities = report_vulnerabilities(vulnerabilities)
        
        encryption_result = None
        if encrypt:
            # Encrypt the file (using the fixed version if available)
            encryption_result = encryptor.encrypt_file(temp_file_path, algorithm=algorithm)
            if not encryption_result.get('success', False):
                return jsonify({'error': f'Encryption failed: {encryption_result.get("error", "Unknown error")}'}), 500
        
        response = {
            'success': True,
            'vulnerabilities': formatted_vulnerabilities,
            'fixed': fixed,
            'fixed_code': fixed_code,
            'fixes_applied': fixes_applied,
            'encryption': encryption_result
        }
        return jsonify(response)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        # Clean up the temporary file
        os.unlink(temp_file_path)

@app.route('/api/supported-languages', methods=['GET'])
def supported_languages():
    """
    Return the list of supported languages for analysis.
    """
    languages = ['python', 'javascript', 'java']
    return jsonify({'languages': languages})

@app.route('/api/encryption-algorithms', methods=['GET'])
def encryption_algorithms():
    """
    Return the list of supported encryption algorithms with metadata.
    """
    algorithms = [
        {
            'id': algo,
            'name': encryptor.algorithm_info[algo]['name'],
            'description': encryptor.algorithm_info[algo]['description'],
            'security_score': encryptor.algorithm_info[algo]['security_score'],
            'key_strength': encryptor.algorithm_info[algo]['key_strength'],
            'vulnerabilities': encryptor.algorithm_info[algo]['vulnerabilities']
        }
        for algo in encryptor.algorithms
    ]
    return jsonify({'algorithms': algorithms})

@app.route('/api/supported-hash-algorithms', methods=['GET'])
def supported_hash_algorithms():
    """
    Return the list of supported hash algorithms.
    """
    return jsonify({'hash_algorithms': ['sha256', 'sha3-256']})

@app.route('/api/compute-hash', methods=['POST'])
def compute_hash():
    """
    Compute the hash of code or a file.

    Expects a JSON with 'code' (str) or a file upload with 'file'.
    Optionally includes 'hash_algorithm' (str) to specify the hash algorithm.
    """
    hash_algorithm = request.form.get('hash_algorithm', 'sha256')

    # Check if code or file is provided
    if 'code' in request.form:
        code = request.form['code']
        # Create a temporary file for the code
        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as temp:
            temp_file_path = temp.name
            temp.write(code.encode())
    elif 'file' in request.files:
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        # Create a temporary file for the uploaded file
        with tempfile.NamedTemporaryFile(delete=False) as temp:
            temp_file_path = temp.name
            file.save(temp_file_path)
    else:
        return jsonify({'error': 'No code or file provided'}), 400

    try:
        # Compute the hash
        computed_hash = encryptor.compute_hash(temp_file_path, hash_algorithm)
        return jsonify({
            'success': True,
            'hash_algorithm': hash_algorithm,
            'hash': computed_hash
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        os.unlink(temp_file_path)

@app.route('/api/verify-hash', methods=['POST'])
def verify_hash():
    """
    Verify a hash against code or a file.

    Expects a JSON with 'code' (str) or a file upload with 'file',
    'hash' (str), and optionally 'hash_algorithm' (str).
    """
    if 'hash' not in request.form:
        return jsonify({'error': 'No hash provided'}), 400

    provided_hash = request.form['hash']
    hash_algorithm = request.form.get('hash_algorithm', 'sha256')

    # Check if code or file is provided
    if 'code' in request.form:
        code = request.form['code']
        # Create a temporary file for the code
        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as temp:
            temp_file_path = temp.name
            temp.write(code.encode())
    elif 'file' in request.files:
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        # Create a temporary file for the uploaded file
        with tempfile.NamedTemporaryFile(delete=False) as temp:
            temp_file_path = temp.name
            file.save(temp_file_path)
    else:
        return jsonify({'error': 'No code or file provided'}), 400

    try:
        # Verify the hash
        is_valid = encryptor.verify_hash(temp_file_path, provided_hash, hash_algorithm)
        return jsonify({
            'success': True,
            'is_valid': is_valid,
            'hash_algorithm': hash_algorithm
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        os.unlink(temp_file_path)

@app.route('/api/verify-encryption-hash', methods=['POST'])
def verify_encryption_hash():
    """
    Verify the integrity hash of an encrypted file.

    Expects a JSON with 'file_path' (str) and 'hash' (str).
    Optionally includes 'hash_algorithm' (str).
    """
    if not request.json or 'file_path' not in request.json or 'hash' not in request.json:
        return jsonify({'error': 'File path and hash are required'}), 400

    file_path = request.json['file_path']
    provided_hash = request.json['hash']
    hash_algorithm = request.json.get('hash_algorithm', 'sha256')

    if not os.path.exists(file_path):
        return jsonify({'error': 'Encrypted file not found'}), 404

    try:
        # Verify the hash
        is_valid = encryptor.verify_hash(file_path, provided_hash, hash_algorithm)
        return jsonify({
            'success': True,
            'is_valid': is_valid,
            'hash_algorithm': hash_algorithm
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/download/<file_type>/<path:file_path>', methods=['GET'])
def download_file(file_type, file_path):
    """
    Download the encrypted file or key file.
    Args:
        file_type (str): 'encrypted', 'key', or 'fixed'
        file_path (str): Path to the file
    """
    if file_type not in ['encrypted', 'key', 'fixed']:
        return jsonify({'error': 'Invalid file type'}), 400
    
    if not os.path.exists(file_path):
        return jsonify({'error': 'File not found'}), 404
    
    try:
        # Determine the filename for download
        base_name = os.path.basename(file_path)
        if file_type == 'encrypted':
            filename = f"encrypted_{base_name}"
        elif file_type == 'key':
            filename = f"key_{base_name}"
        else:  # fixed
            filename = f"fixed_{base_name}"
        
        return send_file(file_path, as_attachment=True, download_name=filename)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/download-fixed', methods=['POST'])
def download_fixed():
    """
    Create a temporary file for the fixed code and allow downloading it.
    Expects a JSON with a 'code' field containing the fixed code and a 'language' field.
    """
    if not request.json or 'code' not in request.json or 'language' not in request.json:
        return jsonify({'error': 'No code or language provided'}), 400
    
    fixed_code = request.json['code']
    language = request.json['language']
    
    # Create a temporary file for the fixed code
    with tempfile.NamedTemporaryFile(suffix=f'.{language}', delete=False) as temp:
        temp_file_path = temp.name
        temp.write(fixed_code.encode())
    
    try:
        return send_file(temp_file_path, as_attachment=True, download_name=f'fixed_code.{language}')
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        # Clean up the temporary file
        os.unlink(temp_file_path)

if __name__ == '__main__':
    app.run(debug=True)