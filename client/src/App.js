import React, { useState } from 'react';
import axios from 'axios';
import './App.css';

function App() {
  const [urlInput, setUrlInput] = useState('');
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [showRecommendations, setShowRecommendations] = useState(true);
  const [expandedResults, setExpandedResults] = useState(new Set());
  const [uploadedFile, setUploadedFile] = useState(null);

  const validateUrls = async () => {
    let urls = [];
    
    // Get URLs from text input
    if (urlInput.trim()) {
      urls = urlInput
        .split('\n')
        .map(url => url.trim())
        .filter(url => url.length > 0);
    }
    
    // Get URLs from uploaded file
    if (uploadedFile) {
      try {
        const fileContent = await readFileContent(uploadedFile);
        const fileUrls = fileContent
          .split('\n')
          .map(url => url.trim())
          .filter(url => url.length > 0);
        urls = [...urls, ...fileUrls];
      } catch (err) {
        setError('Failed to read uploaded file');
        return;
      }
    }
    
    // Remove duplicates
    urls = [...new Set(urls)];

    if (urls.length === 0) {
      setError('Please enter at least one URL or upload a file with URLs');
      return;
    }

    if (urls.length > 50) {
      setError('Maximum 50 URLs allowed per batch');
      return;
    }

    setLoading(true);
    setError('');
    setResults([]);

    try {
      const response = await axios.post('/api/validate-batch', {
        urls: urls
      });
      setResults(response.data);
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to validate URLs');
    } finally {
      setLoading(false);
    }
  };

  const readFileContent = (file) => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = (e) => resolve(e.target.result);
      reader.onerror = (e) => reject(e);
      reader.readAsText(file);
    });
  };

  const handleFileUpload = (event) => {
    const file = event.target.files[0];
    if (file) {
      if (file.type !== 'text/plain' && !file.name.endsWith('.txt')) {
        setError('Please upload a .txt file');
        return;
      }
      setUploadedFile(file);
      setError('');
    }
  };

  const clearResults = () => {
    setResults([]);
    setError('');
    setUrlInput('');
    setUploadedFile(null);
    setExpandedResults(new Set());
    // Reset file input
    const fileInput = document.getElementById('file-upload');
    if (fileInput) fileInput.value = '';
  };

  const exportToCSV = () => {
    if (results.length === 0) return;
    
    const headers = [
      'URL',
      'Status',
      'Redirected',
      'Final URL',
      'Security Score',
      'HSTS',
      'CSP',
      'X-Frame-Options',
      'X-Content-Type-Options',
      'Referrer-Policy',
      'Permissions-Policy',
      'XSS-Protection',
      'CORS',
      'Error'
    ];
    
    const csvData = results.map(result => {
      const security = result.security || {};
      const score = calculateSecurityScore(security);
      
      return [
        result.url,
        result.status || 'N/A',
        result.wasRedirected ? 'Yes' : 'No',
        result.finalUrl || result.url,
        `${score}/8`,
        security.hsts?.enabled ? 'Enabled' : 'Missing',
        security.csp?.enabled ? 'Enabled' : 'Missing',
        security.xFrameOptions?.enabled ? 'Enabled' : 'Missing',
        security.xContentTypeOptions?.enabled ? 'Enabled' : 'Missing',
        security.referrerPolicy?.enabled ? 'Enabled' : 'Missing',
        security.permissionsPolicy?.enabled ? 'Enabled' : 'Missing',
        security.xssProtection?.enabled ? 'Enabled' : 'Missing',
        security.cors?.enabled ? 'Enabled' : 'Missing',
        result.error || ''
      ];
    });
    
    const csvContent = [headers, ...csvData]
      .map(row => row.map(field => `"${field}"`).join(','))
      .join('\n');
    
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    const url = URL.createObjectURL(blob);
    link.setAttribute('href', url);
    link.setAttribute('download', `security-headers-report-${new Date().toISOString().split('T')[0]}.csv`);
    link.style.visibility = 'hidden';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const toggleResultExpansion = (index) => {
    const newExpanded = new Set(expandedResults);
    if (newExpanded.has(index)) {
      newExpanded.delete(index);
    } else {
      newExpanded.add(index);
    }
    setExpandedResults(newExpanded);
  };

  const getSecurityItemClass = (enabled) => {
    return `security-item ${enabled ? 'enabled' : 'disabled'}`;
  };

  const getPriorityClass = (priority) => {
    return priority ? priority.toLowerCase() : 'medium';
  };

  const renderSecurityHeaders = (security) => {
    const headers = [
      { key: 'hsts', name: 'HSTS', fullName: 'HTTP Strict Transport Security' },
      { key: 'csp', name: 'CSP', fullName: 'Content Security Policy' },
      { key: 'xFrameOptions', name: 'X-Frame-Options', fullName: 'X-Frame-Options' },
      { key: 'xContentTypeOptions', name: 'X-Content-Type', fullName: 'X-Content-Type-Options' },
      { key: 'referrerPolicy', name: 'Referrer Policy', fullName: 'Referrer-Policy' },
      { key: 'permissionsPolicy', name: 'Permissions', fullName: 'Permissions-Policy' },
      { key: 'xssProtection', name: 'XSS Protection', fullName: 'X-XSS-Protection' },
      { key: 'cors', name: 'CORS', fullName: 'Cross-Origin Resource Sharing' }
    ];

    return (
      <div className="security-grid">
        {headers.map(header => (
          <div key={header.key} className={getSecurityItemClass(security[header.key]?.enabled)}>
            <div className="security-name" title={header.fullName}>
              {header.name}
            </div>
            <div className="security-status">
              {security[header.key]?.enabled ? '✅ Enabled' : '❌ Missing'}
            </div>
          </div>
        ))}
      </div>
    );
  };

  const renderRecommendations = (result) => {
    if (!showRecommendations) return null;

    const recommendations = getRecommendations(result);
    
    if (recommendations.length === 0) {
      return (
        <div className="recommendations">
          <h4>🎉 Recommendations</h4>
          <div className="success-message">
            All critical security headers are properly configured!
          </div>
        </div>
      );
    }

    return (
      <div className="recommendations">
        <h4>🔧 Security Recommendations ({recommendations.length})</h4>
        {recommendations.map((rec, index) => (
          <div key={index} className={`recommendation-item ${getPriorityClass(rec.priority)}`}>
            <div className="recommendation-header">
              {rec.priority === 'HIGH' ? '🔴' : rec.priority === 'MEDIUM' ? '🟡' : '🟢'} 
              {rec.priority} - {rec.header}: {rec.issue}
            </div>
            <div className="recommendation-fix">
              💡 Fix: {rec.fix}
            </div>
            <div>
              🎯 Impact: {rec.impact}
            </div>
          </div>
        ))}
      </div>
    );
  };

  const getRecommendations = (result) => {
    const recommendations = [];
    const security = result.security;
    
    if (!security) return recommendations;
    
    if (!security.hsts?.enabled) {
      recommendations.push({
        header: 'HSTS',
        issue: 'Missing HTTP Strict Transport Security',
        fix: 'Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
        priority: 'HIGH',
        impact: 'Prevents HTTPS downgrade attacks and man-in-the-middle attacks'
      });
    }
    
    if (!security.csp?.enabled) {
      recommendations.push({
        header: 'CSP',
        issue: 'Missing Content Security Policy',
        fix: 'Add header: Content-Security-Policy: default-src \'self\'; script-src \'self\' \'unsafe-inline\'',
        priority: 'HIGH',
        impact: 'Prevents XSS attacks and code injection vulnerabilities'
      });
    }
    
    if (!security.xFrameOptions?.enabled) {
      recommendations.push({
        header: 'X-Frame-Options',
        issue: 'Missing X-Frame-Options protection',
        fix: 'Add header: X-Frame-Options: DENY',
        priority: 'MEDIUM',
        impact: 'Prevents clickjacking attacks and UI redressing'
      });
    }
    
    if (!security.xContentTypeOptions?.enabled) {
      recommendations.push({
        header: 'X-Content-Type-Options',
        issue: 'Missing MIME type protection',
        fix: 'Add header: X-Content-Type-Options: nosniff',
        priority: 'MEDIUM',
        impact: 'Prevents MIME-type sniffing attacks and file upload exploits'
      });
    }
    
    if (!security.referrerPolicy?.enabled) {
      recommendations.push({
        header: 'Referrer-Policy',
        issue: 'Missing referrer policy',
        fix: 'Add header: Referrer-Policy: strict-origin-when-cross-origin',
        priority: 'MEDIUM',
        impact: 'Protects user privacy and prevents information leakage'
      });
    }
    
    if (!security.permissionsPolicy?.enabled) {
      recommendations.push({
        header: 'Permissions-Policy',
        issue: 'Missing permissions policy',
        fix: 'Add header: Permissions-Policy: camera=(), microphone=(), geolocation=()',
        priority: 'LOW',
        impact: 'Limits browser feature access and reduces attack surface'
      });
    }
    
    if (security.cors?.enabled && security.cors?.details?.isWildcard) {
      recommendations.push({
        header: 'CORS',
        issue: 'Overly permissive CORS policy (wildcard)',
        fix: 'Replace Access-Control-Allow-Origin: * with specific domains',
        priority: 'HIGH',
        impact: 'Prevents unauthorized cross-origin requests and data theft'
      });
    }
    
    return recommendations;
  };

  const calculateSecurityScore = (security) => {
    if (!security) return 0;
    
    let score = 0;
    const headers = ['hsts', 'csp', 'xFrameOptions', 'xContentTypeOptions', 'referrerPolicy', 'permissionsPolicy', 'xssProtection', 'cors'];
    
    headers.forEach(header => {
      if (security[header]?.enabled) {
        // Deduct points for CORS wildcard
        if (header === 'cors' && security[header]?.details?.isWildcard) {
          score += 0.5;
        } else {
          score += 1;
        }
      }
    });
    
    return Math.round(score);
  };

  const getScoreClass = (score) => {
    if (score >= 7) return 'excellent';
    if (score >= 5) return 'good';
    if (score >= 3) return 'fair';
    return 'poor';
  };

  return (
    <div className="container">
      <div className="header">
        <div className="brand-section">
          <div className="brand-text">
            <span className="verify-text">VERIFY</span>
            <div className="security-icon">🔒</div>
            <span className="your-text">YOUR</span>
          </div>
          <div className="website-text">
            <span className="website">WEBSITE</span>
            <span className="brackets">&lt;/&gt;</span>
            <span className="security">SECURITY</span>
          </div>
          <div className="headers-text">
            <span className="headers-script">HEADERS</span>
            <span className="headers">VALIDATION</span>
          </div>
        </div>
        <div className="subtitle">
          <span>Comprehensive security header analysis and recommendations</span>
          <div className="more-info">
            <span>START SCAN</span>
            <span className="arrow">&gt;</span>
          </div>
        </div>
      </div>

      <div className="input-section">
        <div className="input-group">
          <label htmlFor="url-input">URLs to Validate</label>
          <textarea
            id="url-input"
            value={urlInput}
            onChange={(e) => setUrlInput(e.target.value)}
            placeholder="Enter URLs, one per line (max 50):&#10;google.com&#10;github.com&#10;stackoverflow.com"
            disabled={loading}
          />
        </div>

        <div className="input-group">
          <label htmlFor="file-upload">Or Upload a .txt file with URLs</label>
          <div className="file-upload-container">
            <input
              id="file-upload"
              type="file"
              accept=".txt,text/plain"
              onChange={handleFileUpload}
              disabled={loading}
              className="file-input"
            />
            <label htmlFor="file-upload" className="file-upload-label">
              📁 {uploadedFile ? uploadedFile.name : 'Choose file'}
            </label>
            {uploadedFile && (
              <button
                type="button"
                onClick={() => {
                  setUploadedFile(null);
                  document.getElementById('file-upload').value = '';
                }}
                className="file-remove-btn"
                disabled={loading}
              >
                ✕
              </button>
            )}
          </div>
        </div>

        <div className="button-group">
          <button
            className="btn btn-primary"
            onClick={validateUrls}
            disabled={loading || (!urlInput.trim() && !uploadedFile)}
          >
            {loading ? <div className="spinner"></div> : '🔍'} Validate URLs
          </button>
          
          <button
            className="btn btn-secondary"
            onClick={clearResults}
            disabled={loading}
          >
            🗑️ Clear All
          </button>
          
          {results.length > 0 && (
            <button
              className="btn btn-success"
              onClick={exportToCSV}
              disabled={loading}
            >
              📊 Export CSV
            </button>
          )}
        </div>

        <div className="options-section">
          <label className="checkbox-label">
            <input
              type="checkbox"
              checked={showRecommendations}
              onChange={(e) => setShowRecommendations(e.target.checked)}
            />
            <span>Show security recommendations</span>
          </label>
        </div>
      </div>

      {loading && (
        <div className="loading">
          <div className="spinner"></div>
          Validating security headers...
        </div>
      )}

      {error && (
        <div className="error-message">
          ❌ {error}
        </div>
      )}

      {results.length > 0 && (
        <div className="results-section">
          <div className="results-header">
            <h2>📊 Validation Results ({results.length} URL{results.length > 1 ? 's' : ''})</h2>
            <button
              className="btn btn-success btn-small"
              onClick={exportToCSV}
              disabled={loading}
            >
              📊 Export CSV
            </button>
          </div>
          
          {results.map((result, index) => {
            const isExpanded = expandedResults.has(index);
            const securityScore = calculateSecurityScore(result.security);
            
            return (
              <div key={index} className="accordion-item">
                <div 
                  className="accordion-header" 
                  onClick={() => toggleResultExpansion(index)}
                >
                  <div className="accordion-title">
                    <div className="url-info">
                      <span className="url-text">{result.url}</span>
                      {!result.error && (
                        <div className="security-score">
                          <span className={`score-badge ${getScoreClass(securityScore)}`}>
                            {securityScore}/8
                          </span>
                          <span className="score-label">Security Score</span>
                        </div>
                      )}
                    </div>
                    <div className="status-info">
                      {result.error ? (
                        <span className="status-error">❌ Error</span>
                      ) : (
                        <>
                          <span className="status-code">Status: {result.status}</span>
                          {result.wasRedirected && (
                            <span className="redirect-badge">🔄 Redirected</span>
                          )}
                        </>
                      )}
                    </div>
                  </div>
                  <div className={`accordion-icon ${isExpanded ? 'expanded' : ''}`}>
                    ▼
                  </div>
                </div>
                
                {isExpanded && (
                  <div className="accordion-content">
                    {result.error ? (
                      <div className="error-details">
                        <h4>❌ Error Details</h4>
                        <p>{result.error}</p>
                      </div>
                    ) : (
                      <>
                        {result.wasRedirected && (
                          <div className="redirect-info">
                            <h4>🔄 Redirect Information</h4>
                            <p><strong>Final URL:</strong> {result.finalUrl}</p>
                          </div>
                        )}
                        
                        <div className="security-analysis">
                          <h4>🛡️ Security Headers Analysis</h4>
                          {renderSecurityHeaders(result.security)}
                        </div>
                        
                        {renderRecommendations(result)}
                      </>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

export default App;
