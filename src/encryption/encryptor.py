import os
import time
import json
import matplotlib.pyplot as plt
import numpy as np
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.decrepit.ciphers.algorithms import Blowfish, TripleDES

class EncryptionFramework:
    def __init__(self):
        self.algorithms = ['aes', 'chacha20', 'blowfish', 'rsa', 'tripledes', 'camellia', 'hybrid']
        self.security_metrics = {
            'aes': {'key_strength': 256, 'vulnerabilities': [], 'security_score': 0.9},
            'chacha20': {'key_strength': 256, 'vulnerabilities': [], 'security_score': 0.85},
            'blowfish': {'key_strength': 128, 'vulnerabilities': ['limited key size'], 'security_score': 0.5},
            'rsa': {'key_strength': 2048, 'vulnerabilities': ['padding oracle'], 'security_score': 0.95},
            'tripledes': {'key_strength': 168, 'vulnerabilities': ['block size issues'], 'security_score': 0.6},
            'camellia': {'key_strength': 256, 'vulnerabilities': [], 'security_score': 0.88},
            'hybrid': {'key_strength': 256, 'vulnerabilities': [], 'security_score': 0.92}  # RSA+AES
        }

    def generate_encryption_key(self, algorithm):
        if algorithm == 'aes':
            return {'key': os.urandom(32), 'iv': os.urandom(12)}
        elif algorithm == 'chacha20':
            return {'key': os.urandom(32), 'nonce': os.urandom(16)}
        elif algorithm == 'blowfish':
            return {'key': os.urandom(16), 'iv': os.urandom(8)}
        elif algorithm == 'rsa':
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            return {'private_key': private_key, 'public_key': private_key.public_key()}
        elif algorithm == 'tripledes':
            return {'key': os.urandom(24), 'iv': os.urandom(8)}
        elif algorithm == 'camellia':
            return {'key': os.urandom(32), 'iv': os.urandom(16)}
        elif algorithm == 'hybrid':
            # Generate RSA key pair for key exchange
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            # Generate AES key and IV for data encryption
            aes_key = os.urandom(32)
            aes_iv = os.urandom(12)
            return {
                'private_key': private_key,
                'public_key': private_key.public_key(),
                'aes_key': aes_key,
                'aes_iv': aes_iv
            }
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

    def encrypt_tripledes(self, data, key_data):
        padder = padding.PKCS7(64).padder()
        padded_data = padder.update(data) + padder.finalize()
        cipher = Cipher(algorithms.TripleDES(key_data['key']), modes.CBC(key_data['iv']))
        encryptor = cipher.encryptor()
        return encryptor.update(padded_data) + encryptor.finalize()

    def encrypt_camellia(self, data, key_data):
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        cipher = Cipher(algorithms.Camellia(key_data['key']), modes.CBC(key_data['iv']))
        encryptor = cipher.encryptor()
        return encryptor.update(padded_data) + encryptor.finalize()

    def encrypt_hybrid(self, data, key_data):
        # Step 1: Encrypt the data with AES
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        cipher = Cipher(algorithms.AES(key_data['aes_key']), modes.GCM(key_data['aes_iv']))
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        tag = encryptor.tag

        # Step 2: Encrypt the AES key with RSA
        encrypted_aes_key = key_data['public_key'].encrypt(
            key_data['aes_key'],
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Combine the encrypted AES key, IV, tag, and encrypted data
        return encrypted_aes_key + key_data['aes_iv'] + tag + encrypted_data

    def compute_integrity_hash(self, data, hash_algorithm='sha256'):
        """Compute the integrity hash of the data using SHA-256 or SHA-3."""
        if hash_algorithm == 'sha256':
            hasher = hashes.Hash(hashes.SHA256())
        elif hash_algorithm == 'sha3_256':
            hasher = hashes.Hash(hashes.SHA3_256())
        else:
            raise ValueError(f'Unsupported hash algorithm: {hash_algorithm}')
        hasher.update(data)
        return hasher.finalize().hex()

    def verify_integrity_hash(self, data, stored_hash, hash_algorithm='sha256'):
        """Verify the integrity of the data by comparing the computed hash with the stored hash."""
        computed_hash = self.compute_integrity_hash(data, hash_algorithm)
        return computed_hash == stored_hash

    def benchmark_encryption(self, data, iterations=5):
        results = {}
        for algorithm in self.algorithms:
            if algorithm == 'blowfish' and len(data) > 4096:
                results[algorithm] = {'time': float('inf'), 'size': 0, 'error': 'Data too large'}
                continue
            if algorithm == 'rsa' and len(data) > 190:
                results[algorithm] = {'time': float('inf'), 'size': 0, 'error': 'Data too large for RSA'}
                continue

            times = []
            sizes = []
            try:
                for _ in range(iterations):
                    key_data = self.generate_encryption_key(algorithm)
                    start_time = time.time()
                    if algorithm == 'aes':
                        encrypted = self.encrypt_aes(data, key_data)
                    elif algorithm == 'chacha20':
                        encrypted = self.encrypt_chacha20(data, key_data)
                    elif algorithm == 'blowfish':
                        encrypted = self.encrypt_blowfish(data, key_data)
                    elif algorithm == 'rsa':
                        encrypted = self.encrypt_rsa(data, key_data)
                    elif algorithm == 'tripledes':
                        encrypted = self.encrypt_tripledes(data, key_data)
                    elif algorithm == 'camellia':
                        encrypted = self.encrypt_camellia(data, key_data)
                    elif algorithm == 'hybrid':
                        encrypted = self.encrypt_hybrid(data, key_data)
                    elapsed = time.time() - start_time
                    times.append(elapsed)
                    sizes.append(len(encrypted))
                avg_time = sum(times) / iterations
                avg_size = sum(sizes) / iterations
                results[algorithm] = {
                    'avg_time': avg_time,
                    'avg_size': avg_size,
                    'security_score': self.security_metrics[algorithm]['security_score'],
                    'key_strength': self.security_metrics[algorithm]['key_strength'],
                    'vulnerabilities': self.security_metrics[algorithm]['vulnerabilities']
                }
            except Exception as e:
                results[algorithm] = {'avg_time': float('inf'), 'avg_size': 0, 'error': str(e)}
        return results

    def compare_algorithms(self, data, output_path='algorithm_comparison.png'):
        results = self.benchmark_encryption(data)
        valid = {k: v for k, v in results.items() if 'error' not in v}
        if not valid:
            return {'success': False, 'error': 'No valid algorithms for comparison'}

        algorithms = list(valid.keys())
        times = [valid[alg]['avg_time'] for alg in algorithms]
        sizes = [valid[alg]['avg_size'] for alg in algorithms]
        security_scores = [valid[alg]['security_score'] for alg in algorithms]
        key_strengths = [valid[alg]['key_strength'] for alg in algorithms]

        plt.figure(figsize=(12, 8))
        fig, (ax1, ax2) = plt.subplots(2, 1)
        x = np.arange(len(algorithms))
        width = 0.35

        ax1.bar(x - width/2, times, width, label='Average Time (s)', color='skyblue')
        ax1.set_ylabel('Time (seconds)')
        ax1.set_title('Encryption Algorithm Performance Comparison')
        ax1.set_xticks(x)
        ax1.set_xticklabels(algorithms, rotation=45)
        ax1.legend()

        ax2.bar(x + width/2, sizes, width, label='Output Size (bytes)', color='lightgreen')
        ax2.set_ylabel('Size (bytes)')
        ax2.set_xticks(x)
        ax2.set_xticklabels(algorithms, rotation=45)
        ax2.legend()

        plt.tight_layout()
        plt.savefig(output_path)
        plt.close()

        plt.figure(figsize=(12, 6))
        plt.subplot(1, 2, 1)
        plt.bar(algorithms, security_scores, color='salmon')
        plt.title('Security Score Comparison')
        plt.ylabel('Security Score')
        plt.xticks(rotation=45)

        plt.subplot(1, 2, 2)
        plt.bar(algorithms, key_strengths, color='lightcoral')
        plt.title('Key Strength Comparison')
        plt.ylabel('Key Strength (bits)')
        plt.xticks(rotation=45)

        plt.tight_layout()
        plt.savefig(output_path.replace('.png', '_security.png'))
        plt.close()

        comparison_report = {
            'algorithms': algorithms,
            'performance': {alg: {'time': valid[alg]['avg_time'], 'size': valid[alg]['avg_size']} for alg in algorithms},
            'security': {alg: {'score': valid[alg]['security_score'], 'key_strength': valid[alg]['key_strength'], 'vulnerabilities': valid[alg]['vulnerabilities']} for alg in algorithms},
            'best_speed': min(valid.items(), key=lambda x: x[1]['avg_time'])[0] if valid else None,
            'best_security': max(valid.items(), key=lambda x: x[1]['security_score'])[0] if valid else None,
            'plots': [output_path, output_path.replace('.png', '_security.png')]
        }
        return comparison_report

    def encrypt_file(self, file_path, algorithm=None, hash_algorithm='sha256'):
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            # Compute integrity hash
            integrity_hash = self.compute_integrity_hash(data, hash_algorithm)

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
            elif algorithm == 'tripledes':
                encrypted = self.encrypt_tripledes(data, key_data)
            elif algorithm == 'camellia':
                encrypted = self.encrypt_camellia(data, key_data)
            elif algorithm == 'hybrid':
                encrypted = self.encrypt_hybrid(data, key_data)
            else:
                return {'success': False, 'error': f'Unsupported algorithm: {algorithm}'}
            elapsed = time.time() - start
            enc_file = file_path + '.encrypted'
            with open(enc_file, 'wb') as f:
                f.write(encrypted)
            key_path = file_path + '.key'

            # Serialize key data, handling RSA keys specially
            serializable_keys = {}
            for key, value in key_data.items():
                if isinstance(value, bytes):
                    serializable_keys[key] = value.hex()
                elif isinstance(value, rsa.RSAPrivateKey):
                    # Serialize private key as PEM, then to hex
                    pem = value.private_bytes(
                        encoding=Encoding.PEM,
                        format=PrivateFormat.PKCS8,
                        encryption_algorithm=NoEncryption()
                    )
                    serializable_keys[key] = pem.hex()
                elif isinstance(value, rsa.RSAPublicKey):
                    # Serialize public key as PEM, then to hex
                    pem = value.public_bytes(
                        encoding=Encoding.PEM,
                        format=PublicFormat.SubjectPublicKeyInfo
                    )
                    serializable_keys[key] = pem.hex()
                else:
                    serializable_keys[key] = value

            with open(key_path, 'w') as f:
                json.dump({
                    'algorithm': algorithm,
                    'key_data': serializable_keys,
                    'integrity_hash': integrity_hash,
                    'hash_algorithm': hash_algorithm
                }, f)
            return {
                'success': True,
                'algorithm': algorithm,
                'original_size': len(data),
                'encrypted_size': len(encrypted),
                'encryption_time': elapsed,
                'encrypted_file': enc_file,
                'key_file': key_path,
                'integrity_hash': integrity_hash
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def select_best_algorithm(self, results, priority='balanced'):
        valid = {k: v for k, v in results.items() if 'error' not in v}
        if not valid:
            return None
        if priority == 'speed':
            return min(valid.items(), key=lambda x: x[1]['avg_time'])[0]
        elif priority == 'security':
            order = ['rsa', 'hybrid', 'aes', 'camellia', 'chacha20', 'tripledes', 'blowfish']
            for algo in order:
                if algo in valid:
                    return algo
        else:
            scores = {}
            fastest = min(v['avg_time'] for v in valid.values())
            for algo, result in valid.items():
                score = (fastest / result['avg_time'] + result['security_score']) / 2
                scores[algo] = score
            return max(scores.items(), key=lambda x: x[1])[0]