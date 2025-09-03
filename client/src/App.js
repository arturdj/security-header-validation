import React, { useState, useRef, useEffect } from 'react';
import axios from 'axios';
import './App.css';

function App() {
  const [urlInput, setUrlInput] = useState('');
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [expandedResults, setExpandedResults] = useState(new Set()); 
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
        // Mouse position tracking removed
        
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
      // Mouse tracking removed
    };

    const handleMouseLeave = () => {
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

    const api = axios.create({
      baseURL: process.env.REACT_APP_API_BASE_URL,
      withCredentials: true, // importante se usar cookies/session
    });

    try {
      const response = await api.post('/api/validate-batch', {
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


  const getStatusLegend = (status) => {
    if (status >= 200 && status < 300) return 'Success';
    if (status >= 300 && status < 400) return 'Redirect';
    if (status >= 400 && status < 500) return 'Client Error';
    if (status >= 500) return 'Server Error';
    return 'Unknown';
  };

  const getHeaderRecommendation = (headerKey, headerData, isEnabled, isCorsWildcard) => {
    const hasIssue = !isEnabled || isCorsWildcard;
    
    if (hasIssue) {
      const recommendations = {
        hsts: {
          issue: 'Missing HTTP Strict Transport Security',
          fix: 'Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
          impact: 'Prevents HTTPS downgrade attacks and man-in-the-middle attacks'
        },
        csp: {
          issue: 'Missing Content Security Policy',
          fix: 'Add header: Content-Security-Policy: default-src \'self\'; script-src \'self\'',
          impact: 'Prevents XSS attacks and code injection vulnerabilities'
        },
        xFrameOptions: {
          issue: 'Missing X-Frame-Options protection',
          fix: 'Add header: X-Frame-Options: DENY',
          impact: 'Prevents clickjacking attacks and UI redressing'
        },
        xContentTypeOptions: {
          issue: 'Missing MIME type protection',
          fix: 'Add header: X-Content-Type-Options: nosniff',
          impact: 'Prevents MIME-type sniffing attacks and file upload exploits'
        },
        referrerPolicy: {
          issue: 'Missing referrer policy',
          fix: 'Add header: Referrer-Policy: strict-origin-when-cross-origin',
          impact: 'Protects user privacy and prevents information leakage'
        },
        permissionsPolicy: {
          issue: 'Missing permissions policy',
          fix: 'Add header: Permissions-Policy: camera=(), microphone=(), geolocation=()',
          impact: 'Limits browser feature access and reduces attack surface'
        },
        cors: {
          issue: isCorsWildcard ? 'Overly permissive CORS policy (wildcard)' : 'CORS configuration detected',
          fix: isCorsWildcard ? 'Replace Access-Control-Allow-Origin: * with specific domains' : 'Review CORS configuration for security',
          impact: isCorsWildcard ? 'Prevents unauthorized cross-origin requests and data theft' : 'Ensure proper cross-origin access control'
        },
        xssProtection: {
          issue: 'Legacy XSS protection header',
          fix: 'Consider using CSP instead of X-XSS-Protection',
          impact: 'Modern CSP provides better XSS protection than legacy headers'
        }
      };
      return recommendations[headerKey] || null;
    } else {
      // Explanations for properly configured headers
      const explanations = {
        hsts: {
          explanation: 'HSTS is properly configured',
          meaning: headerData?.details ? `Forces HTTPS for ${Math.floor((headerData.details.maxAge || 0) / 86400)} days${headerData.details.includeSubDomains ? ', includes subdomains' : ''}${headerData.details.preload ? ', eligible for browser preload list' : ''}` : 'Enforces secure HTTPS connections',
          benefit: 'Protects against protocol downgrade attacks and cookie hijacking'
        },
        csp: {
          explanation: 'Content Security Policy is active',
          meaning: headerData?.details ? `Policy contains ${headerData.details.directiveCount || 0} directives${headerData.details.hasDefaultSrc ? ', has default-src' : ''}${headerData.details.hasScriptSrc ? ', has script-src' : ''}` : 'Controls resource loading and execution',
          benefit: 'Prevents XSS attacks by controlling which resources can be loaded'
        },
        xFrameOptions: {
          explanation: 'Frame protection is enabled',
          meaning: headerData?.value ? `Set to "${headerData.value}" - ${headerData.value.toUpperCase() === 'DENY' ? 'completely blocks framing' : headerData.value.toUpperCase() === 'SAMEORIGIN' ? 'allows framing by same origin only' : 'custom frame policy'}` : 'Prevents page from being embedded in frames',
          benefit: 'Protects against clickjacking and UI redressing attacks'
        },
        xContentTypeOptions: {
          explanation: 'MIME type sniffing protection active',
          meaning: 'Set to "nosniff" - browsers will not try to guess content types',
          benefit: 'Prevents MIME confusion attacks and malicious file uploads'
        },
        referrerPolicy: {
          explanation: 'Referrer policy is configured',
          meaning: headerData?.value ? `Policy: "${headerData.value}" - ${headerData.details?.isStrict ? 'strict privacy protection' : 'balanced privacy and functionality'}` : 'Controls referrer information sent with requests',
          benefit: 'Protects user privacy and prevents information leakage'
        },
        permissionsPolicy: {
          explanation: 'Permissions policy is active',
          meaning: headerData?.details ? `Controls ${headerData.details.featureCount || 0} browser features` : 'Restricts access to browser APIs and features',
          benefit: 'Reduces attack surface by limiting available browser capabilities'
        },
        cors: {
          explanation: 'CORS policy is configured',
          meaning: headerData?.details ? `Origin: ${headerData.details.allowOrigin || 'not set'}, Methods: ${headerData.details.allowMethods || 'not set'}` : 'Cross-origin resource sharing is configured',
          benefit: 'Controls which domains can access your resources'
        },
        xssProtection: {
          explanation: 'XSS protection header present',
          meaning: headerData?.value ? `Set to "${headerData.value}"` : 'Legacy XSS protection is enabled',
          benefit: 'Provides basic XSS protection in older browsers (consider upgrading to CSP)'
        }
      };
      return explanations[headerKey] || null;
    }
  };

  const renderSecurityHeaders = (security) => {
    const headers = [
      { key: 'hsts', name: 'HSTS', fullName: 'HTTP Strict Transport Security', priority: 'HIGH', description: 'Forces HTTPS connections' },
      { key: 'csp', name: 'CSP', fullName: 'Content Security Policy', priority: 'HIGH', description: 'Prevents XSS and injection attacks' },
      { key: 'xFrameOptions', name: 'X-Frame-Options', fullName: 'X-Frame-Options', priority: 'MEDIUM', description: 'Prevents clickjacking attacks' },
      { key: 'xContentTypeOptions', name: 'X-Content-Type-Options', fullName: 'X-Content-Type-Options', priority: 'MEDIUM', description: 'Prevents MIME-type sniffing' },
      { key: 'referrerPolicy', name: 'Referrer-Policy', fullName: 'Referrer-Policy', priority: 'MEDIUM', description: 'Controls referrer information' },
      { key: 'cors', name: 'CORS', fullName: 'Cross-Origin Resource Sharing', priority: 'MEDIUM', description: 'Controls cross-origin requests' },
      { key: 'permissionsPolicy', name: 'Permissions-Policy', fullName: 'Permissions-Policy', priority: 'LOW', description: 'Controls browser features' },
      { key: 'xssProtection', name: 'X-XSS-Protection', fullName: 'X-XSS-Protection', priority: 'LOW', description: 'Legacy XSS protection' }
    ];

    // Sort by status (disabled/missing first) then by priority (high to low)
    const priorityOrder = { 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3 };
    const sortedHeaders = headers.sort((a, b) => {
      const aEnabled = security[a.key]?.enabled;
      const bEnabled = security[b.key]?.enabled;
      const aCorsWildcard = a.key === 'cors' && security[a.key]?.details?.isWildcard;
      const bCorsWildcard = b.key === 'cors' && security[b.key]?.details?.isWildcard;
      
      // First sort by status: disabled/missing/problematic first
      if ((!aEnabled || aCorsWildcard) && (bEnabled && !bCorsWildcard)) return -1;
      if ((aEnabled && !aCorsWildcard) && (!bEnabled || bCorsWildcard)) return 1;
      
      // Then sort by priority: high to low
      return priorityOrder[a.priority] - priorityOrder[b.priority];
    });

    return (
      <div className="security-table-container">
        <table className="security-table">
          <thead>
            <tr>
              <th>Security Header</th>
              <th>Status & Value</th>
              <th>Analysis & Recommendations</th>
            </tr>
          </thead>
          <tbody>
            {sortedHeaders.map(header => {
              const headerData = security[header.key];
              const isEnabled = headerData?.enabled;
              const isCorsWildcard = header.key === 'cors' && headerData?.details?.isWildcard;
              const hasIssue = !isEnabled || isCorsWildcard;
              const headerValue = headerData?.value || headerData?.reason || 'Not set';
              const recommendation = getHeaderRecommendation(header.key, headerData, isEnabled, isCorsWildcard);
              
              return (
                <tr key={header.key} className={hasIssue ? 'header-disabled' : 'header-enabled'}>
                  <td>
                    <div className="header-name">
                      <div className="header-title">
                        <strong>{header.name}</strong>
                        <span className={`priority-tag priority-${header.priority.toLowerCase()}`}>
                          {header.priority}
                        </span>
                      </div>
                      <div className="header-full-name">{header.fullName}</div>
                      <div className="header-description">{header.description}</div>
                    </div>
                  </td>
                  <td className="status-value-cell">
                    <div className="status-indicator-wrapper">
                      <span className={`status-indicator ${hasIssue ? 'disabled' : 'enabled'}`}>
                        {hasIssue ? (isCorsWildcard ? '⚠️ Issue' : '❌ Missing') : '✅ Found'}
                      </span>
                    </div>
                    <div className="header-value">
                      <code>{headerValue}</code>
                    </div>
                  </td>
                  <td className="recommendation-cell">
                    {recommendation ? (
                      hasIssue ? (
                        <div className="inline-recommendation issue">
                          <div className="recommendation-issue">
                            <strong>Issue:</strong> {recommendation.issue}
                          </div>
                          <div className="recommendation-fix">
                            <strong>Fix:</strong> {recommendation.fix}
                          </div>
                          <div className="recommendation-impact">
                            <strong>Impact:</strong> {recommendation.impact}
                          </div>
                        </div>
                      ) : (
                        <div className="inline-recommendation success">
                          <div className="recommendation-explanation">
                            <strong>✅ {recommendation.explanation}</strong>
                          </div>
                          <div className="recommendation-meaning">
                            <strong>Current setting:</strong> {recommendation.meaning}
                          </div>
                          <div className="recommendation-benefit">
                            <strong>Security benefit:</strong> {recommendation.benefit}
                          </div>
                        </div>
                      )
                    ) : (
                      <span className="no-analysis">No analysis available</span>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    );
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
                          <span className="status-code">
                            Status: {result.status} ({getStatusLegend(result.status)})
                          </span>
                          {result.statusDescription && (
                            <span className="status-description-inline">
                              {result.statusDescription}
                            </span>
                          )}
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
                          <h4>🛡️ Security Headers Analysis & Recommendations</h4>
                          {renderSecurityHeaders(result.security)}
                        </div>
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
