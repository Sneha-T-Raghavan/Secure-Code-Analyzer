from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.decrepit.ciphers.algorithms import Blowfish

import os
import time
import json


class EncryptionFramework:
    def __init__(self):
        self.algorithms = ['aes', 'chacha20', 'blowfish', 'rsa']

    def generate_encryption_key(self, algorithm):
        if algorithm == 'aes':
            return {'key': os.urandom(32), 'iv': os.urandom(12)}  # GCM prefers 12-byte IVs
        elif algorithm == 'chacha20':
            return {'key': os.urandom(32), 'nonce': os.urandom(16)}
        elif algorithm == 'blowfish':
            return {'key': os.urandom(16), 'iv': os.urandom(8)}
        elif algorithm == 'rsa':
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            return {'private_key': private_key, 'public_key': private_key.public_key()}
        else:
            raise ValueError(f'Unsupported algorithm: {algorithm}')

    def encrypt_blowfish(self, data, key_data):
        padder = padding.PKCS7(64).padder()
        padded_data = padder.update(data) + padder.finalize()
        cipher = Cipher(Blowfish(key_data['key']), modes.CBC(key_data['iv']))
        encryptor = cipher.encryptor()
        return encryptor.update(padded_data) + encryptor.finalize()

    def encrypt_aes(self, data, key_data):
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        cipher = Cipher(algorithms.AES(key_data['key']), modes.GCM(key_data['iv']))
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(padded_data) + encryptor.finalize()
        return encrypted + encryptor.tag

    def encrypt_chacha20(self, data, key_data):
        cipher = Cipher(algorithms.ChaCha20(key_data['key'], key_data['nonce']), mode=None)
        encryptor = cipher.encryptor()
        return encryptor.update(data) + encryptor.finalize()

    def encrypt_rsa(self, data, key_data):
        return key_data['public_key'].encrypt(
            data,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def benchmark_encryption(self, data):
        results = {}
        for algorithm in self.algorithms:
            if algorithm == 'blowfish' and len(data) > 4096:
                results[algorithm] = {'time': float('inf'), 'size': 0, 'error': 'Data too large'}
                continue

            try:
                key_data = self.generate_encryption_key(algorithm)
                start_time = time.time()

                if algorithm == 'aes':
                    encrypted = self.encrypt_aes(data, key_data)
                elif algorithm == 'chacha20':
                    encrypted = self.encrypt_chacha20(data, key_data)
                elif algorithm == 'blowfish':
                    encrypted = self.encrypt_blowfish(data, key_data)
                elif algorithm == 'rsa':
                    if len(data) <= 190:
                        encrypted = self.encrypt_rsa(data, key_data)
                    else:
                        results[algorithm] = {'time': float('inf'), 'size': 0, 'error': 'Data too large for RSA'}
                        continue

                elapsed = time.time() - start_time
                results[algorithm] = {
                    'time': elapsed,
                    'size': len(encrypted),
                    'encrypted_data': encrypted
                }
            except Exception as e:
                results[algorithm] = {'time': float('inf'), 'size': 0, 'error': str(e)}

        return results

    def select_best_algorithm(self, results, priority='balanced'):
        valid = {k: v for k, v in results.items() if 'error' not in v}
        if not valid:
            return None

        if priority == 'speed':
            return min(valid.items(), key=lambda x: x[1]['time'])[0]
        elif priority == 'security':
            order = ['rsa', 'aes', 'chacha20', 'blowfish']
            for algo in order:
                if algo in valid:
                    return algo
        else:
            scores = {}
            fastest = min(v['time'] for v in valid.values())
            security = {'rsa': 1.0, 'aes': 0.8, 'chacha20': 0.7, 'blowfish': 0.5}
            for algo, result in valid.items():
                score = (fastest / result['time'] + security.get(algo, 0.5)) / 2
                scores[algo] = score
            return max(scores.items(), key=lambda x: x[1])[0]

    def encrypt_file(self, file_path, algorithm=None):
        try:
            with open(file_path, 'rb') as f:
                data = f.read()

            if algorithm is None:
                sample = data[:4096]
                benchmark = self.benchmark_encryption(sample)
                algorithm = self.select_best_algorithm(benchmark)
                if algorithm is None:
                    return {'success': False, 'error': 'No suitable algorithm'}

            key_data = self.generate_encryption_key(algorithm)
            start = time.time()

            if algorithm == 'aes':
                encrypted = self.encrypt_aes(data, key_data)
            elif algorithm == 'chacha20':
                encrypted = self.encrypt_chacha20(data, key_data)
            elif algorithm == 'blowfish':
                encrypted = self.encrypt_blowfish(data, key_data)
            elif algorithm == 'rsa':
                if len(data) <= 190:
                    encrypted = self.encrypt_rsa(data, key_data)
                else:
                    return {'success': False, 'error': 'Data too large for RSA'}
            else:
                return {'success': False, 'error': f'Unsupported algorithm: {algorithm}'}

            elapsed = time.time() - start
            enc_file = file_path + '.encrypted'
            with open(enc_file, 'wb') as f:
                f.write(encrypted)

            key_path = file_path + '.key'
            serializable_keys = {}
            for k, v in key_data.items():
                if isinstance(v, bytes):
                    serializable_keys[k] = v.hex()

            with open(key_path, 'w') as f:
                json.dump({'algorithm': algorithm, 'key_data': serializable_keys}, f)

            return {
                'success': True,
                'algorithm': algorithm,
                'original_size': len(data),
                'encrypted_size': len(encrypted),
                'encryption_time': elapsed,
                'encrypted_file': enc_file,
                'key_file': key_path
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
