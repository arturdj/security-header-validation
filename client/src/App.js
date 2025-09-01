import React, { useState, useRef, useEffect } from 'react';
import axios from 'axios';
import './App.css';

function App() {
  const [urlInput, setUrlInput] = useState('');
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [showRecommendations, setShowRecommendations] = useState(true);
  const [expandedResults, setExpandedResults] = useState(new Set());
  const [mousePosition, setMousePosition] = useState({ x: 0, y: 0 });
  const [isMouseInHeader, setIsMouseInHeader] = useState(false);
  const [terminalLines, setTerminalLines] = useState([]);
  const [glitchText, setGlitchText] = useState({
    verify: 'VERIFY',
    your: 'YOUR',
    website: 'WEBSITE',
    security: 'SECURITY',
    headers: 'HEADERS',
    validation: 'VALIDATION'
  });
  const headerRef = useRef(null);
  const [uploadedFile, setUploadedFile] = useState(null);

  // Initialize terminal lines with cURL commands
  useEffect(() => {
    const curlCommands = [
      { type: 'command', text: '$ curl -I https://github.com' },
      { type: 'response', text: 'HTTP/2 200' },
      { type: 'header', text: 'strict-transport-security: max-age=31536000' },
      { type: 'header', text: 'x-frame-options: deny' },
      { type: 'command', text: '$ curl -I https://stackoverflow.com' },
      { type: 'response', text: 'HTTP/1.1 200 OK' },
      { type: 'header', text: 'content-security-policy: upgrade-insecure-requests' },
      { type: 'header', text: 'x-content-type-options: nosniff' },
      { type: 'command', text: '$ curl -I https://google.com' },
      { type: 'response', text: 'HTTP/2 301' },
      { type: 'header', text: 'referrer-policy: origin' },
      { type: 'header', text: 'x-xss-protection: 0' },
      { type: 'command', text: '$ curl -I https://cloudflare.com' },
      { type: 'response', text: 'HTTP/2 200' },
      { type: 'header', text: 'permissions-policy: interest-cohort=()' },
      { type: 'header', text: 'cross-origin-embedder-policy: require-corp' }
    ];

    const initLines = curlCommands.map((cmd, index) => ({
      id: index,
      text: cmd.text,
      type: cmd.type,
      x: Math.random() * 70 + 15, // Random x position 15-85%
      y: (index * 5) + Math.random() * 2, // Staggered vertical positions
      targetX: Math.random() * 70 + 15,
      targetY: (index * 5) + Math.random() * 2,
      color: cmd.type === 'command' ? '#475569' : cmd.type === 'header' ? '#059669' : '#64748b',
      opacity: 0.2,
      highlighted: false
    }));
    setTerminalLines(initLines);
  }, []);

  // Animate terminal lines
  useEffect(() => {
    const animateInterval = setInterval(() => {
      setTerminalLines(prev => prev.map(line => ({
        ...line,
        x: line.x + (line.targetX - line.x) * 0.02,
        y: line.y + (line.targetY - line.y) * 0.02,
        targetX: Math.abs(line.x - line.targetX) < 1 ? Math.random() * 80 + 10 : line.targetX,
        targetY: Math.abs(line.y - line.targetY) < 1 ? Math.random() * 80 + 10 : line.targetY
      })));
    }, 50);

    return () => clearInterval(animateInterval);
  }, []);

  // Enhanced glitch effect for text
  useEffect(() => {
    const glitchChars = '█▓▒░!@#$%^&*()_+-=[]{}|;:,.<>?~`0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const originalTexts = {
      verify: 'VERIFY',
      your: 'YOUR', 
      website: 'WEBSITE',
      security: 'SECURITY',
      headers: 'HEADERS',
      validation: 'VALIDATION'
    };

    const glitchInterval = setInterval(() => {
      if (Math.random() < 0.7) { // 70% chance to glitch - more frequent
        const keys = Object.keys(originalTexts);
        const randomKey = keys[Math.floor(Math.random() * keys.length)];
        const originalText = originalTexts[randomKey];
        
        let glitchedText = '';
        for (let i = 0; i < originalText.length; i++) {
          if (Math.random() < 0.4) { // 40% chance per character - more intense
            glitchedText += glitchChars[Math.floor(Math.random() * glitchChars.length)];
          } else {
            glitchedText += originalText[i];
          }
        }
        
        setGlitchText(prev => ({ ...prev, [randomKey]: glitchedText }));
        
        // Multiple glitch phases for game-like effect
        setTimeout(() => {
          let secondGlitch = '';
          for (let i = 0; i < originalText.length; i++) {
            if (Math.random() < 0.3) {
              secondGlitch += glitchChars[Math.floor(Math.random() * glitchChars.length)];
            } else {
              secondGlitch += originalText[i];
            }
          }
          setGlitchText(prev => ({ ...prev, [randomKey]: secondGlitch }));
        }, 80);
        
        // Final reset
        setTimeout(() => {
          setGlitchText(prev => ({ ...prev, [randomKey]: originalText }));
        }, 200);
      }
    }, 400); // Faster interval - more game-like

    return () => clearInterval(glitchInterval);
  }, []);

  // Mouse movement handler with enter/leave detection
  useEffect(() => {
    const handleMouseMove = (e) => {
      if (headerRef.current) {
        const rect = headerRef.current.getBoundingClientRect();
        const x = ((e.clientX - rect.left) / rect.width) * 100;
        const y = ((e.clientY - rect.top) / rect.height) * 100;
        setMousePosition({ x, y });
        
        // Highlight nearby terminal lines
        setTerminalLines(prev => prev.map(line => {
          const distance = Math.sqrt(Math.pow(line.x - x, 2) + Math.pow(line.y - y, 2));
          const isNear = distance < 25;
          return {
            ...line,
            highlighted: isNear,
            opacity: isNear ? 0.8 : 0.2,
            color: isNear ? 
              (line.type === 'header' ? '#10b981' : line.type === 'command' ? '#f97316' : '#94a3b8') :
              (line.type === 'command' ? '#475569' : line.type === 'header' ? '#059669' : '#64748b')
          };
        }));
      }
    };

    const handleMouseEnter = () => {
      setIsMouseInHeader(true);
    };

    const handleMouseLeave = () => {
      setIsMouseInHeader(false);
      // Reset all terminal lines to original color
      setTerminalLines(prev => prev.map(line => ({
        ...line,
        highlighted: false,
        opacity: 0.2,
        color: line.type === 'command' ? '#475569' : line.type === 'header' ? '#059669' : '#64748b'
      })));
    };

    const header = headerRef.current;
    if (header) {
      header.addEventListener('mousemove', handleMouseMove);
      header.addEventListener('mouseenter', handleMouseEnter);
      header.addEventListener('mouseleave', handleMouseLeave);
      return () => {
        header.removeEventListener('mousemove', handleMouseMove);
        header.removeEventListener('mouseenter', handleMouseEnter);
        header.removeEventListener('mouseleave', handleMouseLeave);
      };
    }
  }, []);

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
      <div className="header" ref={headerRef}>
        <div className="terminal-background">
          {terminalLines.map((line) => (
            <div 
              key={line.id} 
              className="terminal-line animated"
              style={{
                left: `${line.x}%`,
                top: `${line.y}%`,
                color: line.color,
                opacity: line.opacity,
                transform: `translate(-50%, -50%)`,
                transition: 'color 0.3s ease, opacity 0.3s ease'
              }}
            >
              {line.type === 'command' ? (
                <><span className="terminal-prompt">$</span> {line.text.replace('$ ', '')}</>
              ) : (
                line.text
              )}
            </div>
          ))}
        </div>
        <div className="brand-section">
          <div className="brand-text">
            <span className="verify-text glitch-text">{glitchText.verify}</span>
            <div className="security-icon">🔒</div>
            <span className="your-text glitch-text">{glitchText.your}</span>
          </div>
          <div className="website-text">
            <span className="website glitch-text">{glitchText.website}</span>
            <span className="brackets">&lt;/&gt;</span>
            <span className="security glitch-text">{glitchText.security}</span>
          </div>
          <div className="headers-text">
            <span className="headers-script glitch-text">{glitchText.headers}</span>
            <span className="headers glitch-text">{glitchText.validation}</span>
          </div>
        </div>
        <div className="subtitle">
          <span>Comprehensive security header analysis and recommendations</span>
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
