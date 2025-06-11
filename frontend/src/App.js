import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './App.css';

const App = () => {
    const [file, setFile] = useState(null);
    const [encrypt, setEncrypt] = useState(false);
    const [algorithm, setAlgorithm] = useState('');
    const [algorithms, setAlgorithms] = useState([]);
    const [hashAlgorithm, setHashAlgorithm] = useState('sha256');
    const [hashInput, setHashInput] = useState('');
    const [computedHash, setComputedHash] = useState(null);
    const [hashVerificationResult, setHashVerificationResult] = useState(null);
    const [vulnerabilities, setVulnerabilities] = useState([]);
    const [encryptionResult, setEncryptionResult] = useState(null);
    const [fixed, setFixed] = useState(false);
    const [fixedCode, setFixedCode] = useState(null);
    const [fixesApplied, setFixesApplied] = useState([]);
    const [error, setError] = useState(null);
    const [monitorDirectory, setMonitorDirectory] = useState('monitored_files');
    const [monitoring, setMonitoring] = useState(false);
    const [monitorResults, setMonitorResults] = useState([]);
    const [monitorHashAlgorithm, setMonitorHashAlgorithm] = useState('sha256');

    useEffect(() => {
        // Fetch encryption algorithms
        axios.get('http://localhost:5000/api/encryption-algorithms')
            .then(response => {
                setAlgorithms(response.data.algorithms);
                setAlgorithm('');
            })
            .catch(err => {
                console.error('Error fetching algorithms:', err);
                setError('Failed to fetch encryption algorithms');
            });

        // Poll for monitoring results when monitoring is active
        let interval;
        if (monitoring) {
            interval = setInterval(() => {
                axios.get('http://localhost:5000/api/monitor/results')
                    .then(response => {
                        if (response.data.success) {
                            setMonitorResults(response.data.results);
                        } else {
                            setError(response.data.error || 'Failed to fetch monitoring results');
                        }
                    })
                    .catch(err => {
                        console.error('Error fetching monitoring results:', err);
                        setError('Failed to fetch monitoring results');
                    });
            }, 2000); // Poll every 2 seconds
        }
        return () => clearInterval(interval);
    }, [monitoring]);

    const handleFileSubmit = (e) => {
        e.preventDefault();
        setError(null);
        setVulnerabilities([]);
        setEncryptionResult(null);
        setFixed(false);
        setFixedCode(null);
        setFixesApplied([]);
        setComputedHash(null);
        setHashVerificationResult(null);

        if (!file) {
            setError('Please select a file to upload');
            return;
        }

        const formData = new FormData();
        formData.append('file', file);
        formData.append('encrypt', encrypt.toString());
        if (encrypt && algorithm) {
            formData.append('algorithm', algorithm);
        }

        axios.post('http://localhost:5000/api/analyze-file', formData)
            .then(response => {
                if (response.data.success) {
                    setVulnerabilities(response.data.vulnerabilities);
                    setEncryptionResult(response.data.encryption);
                    setFixed(response.data.fixed);
                    setFixedCode(response.data.fixed_code);
                    setFixesApplied(response.data.fixes_applied);
                } else {
                    setError(response.data.error || 'Analysis failed');
                }
            })
            .catch(err => {
                console.error('Error analyzing file:', err);
                setError('Failed to analyze file');
            });
    };

    const handleComputeHash = (e) => {
        e.preventDefault();
        setError(null);
        setComputedHash(null);
        setHashVerificationResult(null);

        if (!file) {
            setError('Please select a file to compute hash');
            return;
        }

        const formData = new FormData();
        formData.append('file', file);
        formData.append('hash_algorithm', hashAlgorithm);

        axios.post('http://localhost:5000/api/compute-hash', formData)
            .then(response => {
                if (response.data.success) {
                    setComputedHash({
                        hash: response.data.hash,
                        algorithm: response.data.hash_algorithm
                    });
                } else {
                    setError(response.data.error || 'Hash computation failed');
                }
            })
            .catch(err => {
                console.error('Error computing hash:', err);
                setError('Failed to compute hash');
            });
    };

    const handleVerifyHash = (e) => {
        e.preventDefault();
        setError(null);
        setComputedHash(null);
        setHashVerificationResult(null);

        if (!file) {
            setError('Please select a file to verify');
            return;
        }

        if (!hashInput) {
            setError('Please provide a hash to verify');
            return;
        }

        const formData = new FormData();
        formData.append('file', file);
        formData.append('hash', hashInput);
        formData.append('hash_algorithm', hashAlgorithm);

        axios.post('http://localhost:5000/api/verify-hash', formData)
            .then(response => {
                if (response.data.success) {
                    setHashVerificationResult({
                        isValid: response.data.is_valid,
                        algorithm: response.data.hash_algorithm
                    });
                } else {
                    setError(response.data.error || 'Hash verification failed');
                }
            })
            .catch(err => {
                console.error('Error verifying hash:', err);
                setError('Failed to verify hash');
            });
    };

    const handleStartMonitoring = (e) => {
        e.preventDefault();
        setError(null);
        axios.post('http://localhost:5000/api/monitor/start', {
            directory: monitorDirectory,
            hash_algorithm: monitorHashAlgorithm
        })
            .then(response => {
                if (response.data.success) {
                    setMonitoring(true);
                    setMonitorResults([]);
                } else {
                    setError(response.data.error || 'Failed to start monitoring');
                }
            })
            .catch(err => {
                console.error('Error starting monitoring:', err);
                setError('Failed to start monitoring');
            });
    };

    const handleStopMonitoring = (e) => {
        e.preventDefault();
        setError(null);
        axios.post('http://localhost:5000/api/monitor/stop')
            .then(response => {
                if (response.data.success) {
                    setMonitoring(false);
                } else {
                    setError(response.data.error || 'Failed to stop monitoring');
                }
            })
            .catch(err => {
                console.error('Error stopping monitoring:', err);
                setError('Failed to stop monitoring');
            });
    };

    const handleClearMonitorResults = (e) => {
        e.preventDefault();
        setError(null);
        axios.post('http://localhost:5000/api/monitor/clear')
            .then(response => {
                if (response.data.success) {
                    setMonitorResults([]);
                } else {
                    setError(response.data.error || 'Failed to clear monitoring results');
                }
            })
            .catch(err => {
                console.error('Error clearing monitoring results:', err);
                setError('Failed to clear monitoring results');
            });
    };

    const handleDownload = (filePath, fileType) => {
        const url = `http://localhost:5000/api/download/${fileType}/${encodeURIComponent(filePath)}`;
        const link = document.createElement('a');
        link.href = url;
        link.download = fileType === 'encrypted' ? 'encrypted_file' : 'key_file';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    };

    const handleDownloadFixed = () => {
        axios.post('http://localhost:5000/api/download-fixed', {
            code: fixedCode,
            language: 'python'
        }, { responseType: 'blob' })
            .then(response => {
                const url = window.URL.createObjectURL(new Blob([response.data]));
                const link = document.createElement('a');
                link.href = url;
                link.setAttribute('download', `fixed_code.py`);
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
                window.URL.revokeObjectURL(url);
            })
            .catch(err => {
                console.error('Error downloading fixed code:', err);
                setError('Failed to download fixed code');
            });
    };

    const getSeverityClass = (severity) => {
        switch (severity.toLowerCase()) {
            case 'high':
                return 'bg-danger';
            case 'medium':
                return 'bg-warning';
            case 'low':
                return 'bg-info';
            default:
                return 'bg-secondary';
        }
    };

    return (
        <div className="min-h-screen bg-gradient-to-br from-blue-100 to-indigo-200 flex flex-col items-center p-6">
            <h1 className="text-4xl font-extrabold mb-8 text-indigo-800 tracking-tight">
                Code Security Analyzer
            </h1>

            {/* Upload Form */}
            <div className="w-full max-w-2xl bg-white rounded-xl shadow-lg overflow-hidden">
                <div className="p-6">
                    <form onSubmit={handleFileSubmit} className="space-y-4">
                        <input
                            type="file"
                            onChange={(e) => setFile(e.target.files[0])}
                            className="w-full p-3 border rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 text-gray-800"
                        />
                        <div className="flex flex-col sm:flex-row sm:space-x-4 space-y-4 sm:space-y-0">
                            <label className="flex items-center space-x-2">
                                <input
                                    type="checkbox"
                                    checked={encrypt}
                                    onChange={(e) => setEncrypt(e.target.checked)}
                                    className="form-checkbox h-5 w-5 text-indigo-600"
                                />
                                <span className="text-gray-700">Encrypt File</span>
                            </label>
                            {encrypt && (
                                <select
                                    className="p-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 flex-1"
                                    value={algorithm}
                                    onChange={(e) => setAlgorithm(e.target.value)}
                                >
                                    <option value="">Select Best Algorithm</option>
                                    {algorithms.map(alg => (
                                        <option key={alg.id} value={alg.id}>
                                            {alg.name} (Security: {alg.security_score})
                                        </option>
                                    ))}
                                </select>
                            )}
                        </div>
                        <button
                            type="submit"
                            className="w-full bg-indigo-600 text-white p-3 rounded-lg hover:bg-indigo-700 transition duration-200 font-medium"
                        >
                            Analyze File
                        </button>
                    </form>

                    {/* Hash Computation Form */}
                    <form onSubmit={handleComputeHash} className="space-y-4 mt-4">
                        <div className="flex flex-col sm:flex-row sm:space-x-4 space-y-4 sm:space-y-0">
                            <select
                                className="p-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 flex-1"
                                value={hashAlgorithm}
                                onChange={(e) => setHashAlgorithm(e.target.value)}
                            >
                                <option value="sha256">SHA-256</option>
                                <option value="sha3_256">SHA-3-256</option>
                            </select>
                            <button
                                type="submit"
                                className="w-full sm:w-auto bg-blue-600 text-white p-3 rounded-lg hover:bg-blue-700 transition duration-200 font-medium"
                            >
                                Compute Hash
                            </button>
                        </div>
                    </form>

                    {/* Hash Verification Form */}
                    <form onSubmit={handleVerifyHash} className="space-y-4 mt-4">
                        <div className="flex flex-col sm:flex-row sm:space-x-4 space-y-4 sm:space-y-0">
                            <input
                                type="text"
                                placeholder="Enter hash to verify"
                                value={hashInput}
                                onChange={(e) => setHashInput(e.target.value)}
                                className="p-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 flex-1"
                            />
                            <select
                                className="p-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500"
                                value={hashAlgorithm}
                                onChange={(e) => setHashAlgorithm(e.target.value)}
                            >
                                <option value="sha256">SHA-256</option>
                                <option value="sha3_256">SHA-3-256</option>
                            </select>
                            <button
                                type="submit"
                                className="w-full sm:w-auto bg-blue-600 text-white p-3 rounded-lg hover:bg-blue-700 transition duration-200 font-medium"
                            >
                                Verify Hash
                            </button>
                        </div>
                    </form>

                    {/* Monitoring Control Form */}
                    <form onSubmit={monitoring ? handleStopMonitoring : handleStartMonitoring} className="space-y-4 mt-4">
                        <div className="flex flex-col sm:flex-row sm:space-x-4 space-y-4 sm:space-y-0">
                            <input
                                type="text"
                                placeholder="Enter directory to monitor"
                                value={monitorDirectory}
                                onChange={(e) => setMonitorDirectory(e.target.value)}
                                className="p-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 flex-1"
                                disabled={monitoring}
                            />
                            <select
                                className="p-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500"
                                value={monitorHashAlgorithm}
                                onChange={(e) => setMonitorHashAlgorithm(e.target.value)}
                                disabled={monitoring}
                            >
                                <option value="sha256">SHA-256</option>
                                <option value="sha3_256">SHA-3-256</option>
                            </select>
                            <button
                                type="submit"
                                className={`w-full sm:w-auto p-3 rounded-lg transition duration-200 font-medium ${
                                    monitoring
                                        ? 'bg-red-600 text-white hover:bg-red-700'
                                        : 'bg-green-600 text-white hover:bg-green-700'
                                }`}
                            >
                                {monitoring ? 'Stop Monitoring' : 'Start Monitoring'}
                            </button>
                        </div>
                    </form>
                    {monitoring && (
                        <button
                            onClick={handleClearMonitorResults}
                            className="mt-4 w-full sm:w-auto bg-gray-600 text-white p-3 rounded-lg hover:bg-gray-700 transition duration-200 font-medium"
                        >
                            Clear Monitoring Results
                        </button>
                    )}
                </div>
            </div>

            {/* Results */}
            <div className="w-full max-w-2xl mt-8">
                {error && (
                    <div className="mb-6 p-4 bg-red-100 text-red-700 rounded-lg shadow-md">
                        <p>{error}</p>
                    </div>
                )}

                {monitorResults.length > 0 && (
                    <div className="mb-8 p-6 bg-white rounded-xl shadow-lg">
                        <h2 className="text-2xl font-semibold mb-4 text-indigo-800">Monitoring Results</h2>
                        <ul className="space-y-4">
                            {monitorResults.map((result, index) => (
                                <li key={index} className="p-4 bg-gray-50 rounded-lg border border-gray-200">
                                    <p><strong>Timestamp:</strong> {result.timestamp}</p>
                                    <p><strong>Event:</strong> {result.event_type.toUpperCase()}</p>
                                    <p><strong>File:</strong> {result.file_path}</p>
                                    {result.language && <p><strong>Language:</strong> {result.language}</p>}
                                    {result.integrity_hash && (
                                        <p><strong>Integrity Hash ({result.hash_algorithm.toUpperCase()}):</strong> <pre className="break-all">{result.integrity_hash}</pre></p>
                                    )}
                                    {result.vulnerabilities && result.vulnerabilities.length > 0 ? (
                                        <>
                                            <p><strong>Vulnerabilities Found:</strong> {result.vulnerabilities.length}</p>
                                            <ul className="space-y-2 mt-2">
                                                {result.vulnerabilities.map((vuln, vIndex) => (
                                                    <li
                                                        key={vIndex}
                                                        className={`p-2 rounded-lg ${getSeverityClass(vuln.severity)}`}
                                                    >
                                                        <p><strong>Type:</strong> {vuln.type}</p>
                                                        <p><strong>Severity:</strong> {vuln.severity}</p>
                                                        <p><strong>Line:</strong> {vuln.line_number}</p>
                                                        <p><strong>Code Snippet:</strong> <pre>{vuln.code_snippet}</pre></p>
                                                        <p><strong>Recommendation:</strong> {vuln.recommendation}</p>
                                                    </li>
                                                ))}
                                            </ul>
                                        </>
                                    ) : (
                                        <p><strong>Vulnerabilities:</strong> None</p>
                                    )}
                                    {result.fixed && (
                                        <p><strong>Fixed:</strong> {result.fixes_applied.length} issues fixed</p>
                                    )}
                                    {result.error && (
                                        <p><strong>Error:</strong> {result.error}</p>
                                    )}
                                </li>
                            ))}
                        </ul>
                    </div>
                )}

                {computedHash && (
                    <div className="mb-8 p-6 bg-white rounded-xl shadow-lg">
                        <h2 className="text-2xl font-semibold mb-4 text-indigo-800">Computed Hash</h2>
                        <p><strong>Algorithm:</strong> {computedHash.algorithm.toUpperCase()}</p>
                        <p><strong>Hash:</strong> <pre className="break-all">{computedHash.hash}</pre></p>
                    </div>
                )}

                {hashVerificationResult && (
                    <div className="mb-8 p-6 bg-white rounded-xl shadow-lg">
                        <h2 className="text-2xl font-semibold mb-4 text-indigo-800">Hash Verification Result</h2>
                        <p><strong>Algorithm:</strong> {hashVerificationResult.algorithm.toUpperCase()}</p>
                        <p><strong>Result:</strong> {hashVerificationResult.isValid ? 'Hash matches (file is unchanged)' : 'Hash does not match (file modified)'}</p>
                    </div>
                )}

                {vulnerabilities.length > 0 && (
                    <div className="mb-8 p-6 bg-white rounded-xl shadow-lg">
                        <h2 className="text-2xl font-semibold mb-4 text-indigo-800">Vulnerabilities Found</h2>
                        <ul className="space-y-4">
                            {vulnerabilities.map((vuln, index) => (
                                <li
                                    key={index}
                                    className={`p-4 rounded-lg vulnerability-card ${getSeverityClass(vuln.severity)}`}
                                >
                                    <div className="card-header">{vuln.severity.toUpperCase()} Severity</div>
                                    <div className="mt-2">
                                        <p><strong>Type:</strong> {vuln.type}</p>
                                        <p><strong>File:</strong> {vuln.file_path}</p>
                                        <p><strong>Line:</strong> {vuln.line_number}</p>
                                        <p><strong>Code Snippet:</strong> <pre>{vuln.code_snippet}</pre></p>
                                        <p><strong>Recommendation:</strong> {vuln.recommendation}</p>
                                    </div>
                                </li>
                            ))}
                        </ul>
                    </div>
                )}

                {fixed && fixedCode && (
                    <div className="mb-8 p-6 bg-white rounded-xl shadow-lg">
                        <h2 className="text-2xl font-semibold mb-4 text-indigo-800">Fixed Code</h2>
                        <p className="mb-2 text-gray-700">The following vulnerabilities were fixed:</p>
                        <ul className="space-y-4 mb-4">
                            {fixesApplied.map((fix, index) => (
                                <li key={index} className="p-4 bg-gray-50 rounded-lg border border-gray-200">
                                    <p><strong>Type:</strong> {fix.type}</p>
                                    <p><strong>Line:</strong> {fix.line_number}</p>
                                    <p><strong>Original:</strong> <pre>{fix.original}</pre></p>
                                    <p><strong>Fixed:</strong> <pre>{fix.fixed}</pre></p>
                                </li>
                            ))}
                        </ul>
                        <textarea
                            className="w-full p-3 border rounded-lg bg-gray-100 focus:outline-none focus:ring-2 focus:ring-indigo-500 resize-y text-gray-800 form-control"
                            rows="6"
                            value={fixedCode}
                            readOnly
                        />
                        <button
                            onClick={handleDownloadFixed}
                            className="mt-4 bg-indigo-600 text-white p-2 rounded-lg hover:bg-indigo-700 transition duration-200 font-medium"
                        >
                            Download Fixed Code
                        </button>
                    </div>
                )}

                {encryptionResult && encryptionResult.success && (
                    <div className="p-6 bg-white rounded-xl shadow-lg">
                        <h2 className="text-2xl font-semibold mb-4 text-indigo-800">Encryption Results</h2>
                        <p><strong>Algorithm Used:</strong> {encryptionResult.algorithm}</p>
                        {encryptionResult.default_algorithm_reason && (
                            <p><strong>Why Chosen:</strong> {encryptionResult.default_algorithm_reason}</p>
                        )}
                        <p><strong>Original Size:</strong> {encryptionResult.original_size} bytes</p>
                        <p><strong>Encrypted Size:</strong> {encryptionResult.encrypted_size} bytes</p>
                        <p><strong>Encryption Time:</strong> {encryptionResult.encryption_time.toFixed(3)} seconds</p>
                        <p><strong>Integrity Hash:</strong> <pre className="break-all">{encryptionResult.integrity_hash}</pre></p>
                        <div className="mt-4 flex space-x-4">
                            <button
                                onClick={() => handleDownload(encryptionResult.encrypted_file, 'encrypted')}
                                className="bg-green-600 text-white p-2 rounded-lg hover:bg-green-700 transition duration-200 font-medium"
                            >
                                Download Encrypted File
                            </button>
                            <button
                                onClick={() => handleDownload(encryptionResult.key_file, 'key')}
                                className="bg-green-600 text-white p-2 rounded-lg hover:bg-green-700 transition duration-200 font-medium"
                            >
                                Download Key File
                            </button>
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
};

export default App;