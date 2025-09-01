const axios = require('axios');
const { URL } = require('url');

class SecurityHeaderValidator {
    constructor() {
        this.timeout = 10000; // 10 seconds timeout
    }

    async validateUrl(url, showProgress = false) {
        try {
            // Ensure URL has protocol
            const fullUrl = url.includes('://') ? url : `https://${url}`;
            
            if (!showProgress) {
                console.log(`🔍 Checking ${fullUrl}...`);
            }
            
            // Make HEAD request to properly follow redirects and get final headers
            const response = await axios.head(fullUrl, {
                timeout: this.timeout,
                maxRedirects: 5,
                validateStatus: () => true // Accept any status code
            });

            const headers = response.headers;
            const finalUrl = response.request.res.responseUrl || response.config.url || fullUrl;
            const wasRedirected = finalUrl !== fullUrl;
            
            return {
                url: fullUrl,
                finalUrl,
                wasRedirected,
                status: response.status,
                security: {
                    hsts: this.evaluateHSTS(headers),
                    csp: this.evaluateCSP(headers),
                    xFrameOptions: this.evaluateXFrameOptions(headers),
                    xContentTypeOptions: this.evaluateXContentTypeOptions(headers),
                    referrerPolicy: this.evaluateReferrerPolicy(headers),
                    permissionsPolicy: this.evaluatePermissionsPolicy(headers),
                    xssProtection: this.evaluateXSSProtection(headers),
                    cors: await this.evaluateCORS(finalUrl, headers)
                }
            };
        } catch (error) {
            return {
                url: url.includes('://') ? url : `https://${url}`,
                finalUrl: url.includes('://') ? url : `https://${url}`,
                wasRedirected: false,
                error: error.message,
                security: {
                    hsts: { enabled: false, reason: 'Request failed' },
                    csp: { enabled: false, reason: 'Request failed' },
                    xFrameOptions: { enabled: false, reason: 'Request failed' },
                    xContentTypeOptions: { enabled: false, reason: 'Request failed' },
                    referrerPolicy: { enabled: false, reason: 'Request failed' },
                    permissionsPolicy: { enabled: false, reason: 'Request failed' },
                    xssProtection: { enabled: false, reason: 'Request failed' },
                    cors: { enabled: false, reason: 'Request failed' }
                }
            };
        }
    }

    async validateUrls(urls, showProgress = false) {
        const batchSize = 10; // Process 10 URLs concurrently
        const results = [];
        let completedCount = 0;
        
        console.log(`🔍 Checking ${urls.length} URLs in batches of ${batchSize}...`);
        
        for (let i = 0; i < urls.length; i += batchSize) {
            const batch = urls.slice(i, i + batchSize);
            const batchNumber = Math.floor(i / batchSize) + 1;
            const totalBatches = Math.ceil(urls.length / batchSize);
            
            console.log(`📦 Processing batch ${batchNumber}/${totalBatches} (${batch.length} URLs)...`);
            
            // Create promises for current batch
            const batchPromises = batch.map(async (url) => {
                try {
                    const result = await this.validateUrl(url, showProgress);
                    completedCount++;
                    return result;
                } catch (error) {
                    completedCount++;
                    return {
                        url: url.includes('://') ? url : `https://${url}`,
                        finalUrl: url.includes('://') ? url : `https://${url}`,
                        wasRedirected: false,
                        error: error.message,
                        security: {
                            hsts: { enabled: false, reason: 'Request failed' },
                            csp: { enabled: false, reason: 'Request failed' },
                            xFrameOptions: { enabled: false, reason: 'Request failed' },
                            xContentTypeOptions: { enabled: false, reason: 'Request failed' },
                            referrerPolicy: { enabled: false, reason: 'Request failed' },
                            permissionsPolicy: { enabled: false, reason: 'Request failed' },
                            xssProtection: { enabled: false, reason: 'Request failed' },
                            cors: { enabled: false, reason: 'Request failed' }
                        }
                    };
                }
            });
            
            // Wait for current batch to complete
            const batchResults = await Promise.all(batchPromises);
            results.push(...batchResults);
            
            // Small delay between batches to be respectful to servers
            if (i + batchSize < urls.length) {
                await new Promise(resolve => setTimeout(resolve, 500));
            }
        }
        
        console.log('✅ Validation complete!');
        return results;
    }

    evaluateHSTS(headers) {
        const hsts = headers['strict-transport-security'];
        if (!hsts) {
            return { enabled: false, reason: 'Header not present', value: null };
        }

        const maxAge = hsts.match(/max-age=(\d+)/);
        const includeSubDomains = hsts.includes('includeSubDomains');
        const preload = hsts.includes('preload');

        return {
            enabled: true,
            value: hsts,
            details: {
                maxAge: maxAge ? parseInt(maxAge[1]) : null,
                includeSubDomains,
                preload
            }
        };
    }

    evaluateCSP(headers) {
        const csp = headers['content-security-policy'] || headers['content-security-policy-report-only'];
        if (!csp) {
            return { enabled: false, reason: 'Header not present', value: null };
        }

        const directives = csp.split(';').map(d => d.trim()).filter(d => d);
        const hasDefaultSrc = directives.some(d => d.startsWith('default-src'));
        const hasScriptSrc = directives.some(d => d.startsWith('script-src'));
        
        return {
            enabled: true,
            value: csp,
            details: {
                directiveCount: directives.length,
                hasDefaultSrc,
                hasScriptSrc,
                directives: directives.slice(0, 5) // Show first 5 directives
            }
        };
    }

    evaluateXFrameOptions(headers) {
        const xfo = headers['x-frame-options'];
        if (!xfo) {
            return { enabled: false, reason: 'Header not present', value: null };
        }

        const validValues = ['DENY', 'SAMEORIGIN'];
        const isValid = validValues.includes(xfo.toUpperCase()) || xfo.toUpperCase().startsWith('ALLOW-FROM');

        return {
            enabled: true,
            value: xfo,
            details: {
                isValid,
                recommendation: isValid ? 'Good' : 'Consider using DENY or SAMEORIGIN'
            }
        };
    }

    evaluateXContentTypeOptions(headers) {
        const xcto = headers['x-content-type-options'];
        if (!xcto) {
            return { enabled: false, reason: 'Header not present', value: null };
        }

        const isNosniff = xcto.toLowerCase() === 'nosniff';
        return {
            enabled: true,
            value: xcto,
            details: {
                isNosniff,
                recommendation: isNosniff ? 'Good' : 'Should be "nosniff"'
            }
        };
    }

    evaluateReferrerPolicy(headers) {
        const rp = headers['referrer-policy'];
        if (!rp) {
            return { enabled: false, reason: 'Header not present', value: null };
        }

        const strictPolicies = ['no-referrer', 'strict-origin', 'strict-origin-when-cross-origin'];
        const isStrict = strictPolicies.includes(rp.toLowerCase());

        return {
            enabled: true,
            value: rp,
            details: {
                isStrict,
                recommendation: isStrict ? 'Good' : 'Consider stricter policy'
            }
        };
    }

    evaluatePermissionsPolicy(headers) {
        const pp = headers['permissions-policy'] || headers['feature-policy'];
        if (!pp) {
            return { enabled: false, reason: 'Header not present', value: null };
        }

        const features = pp.split(',').map(f => f.trim()).filter(f => f);
        return {
            enabled: true,
            value: pp,
            details: {
                featureCount: features.length,
                features: features.slice(0, 3) // Show first 3 features
            }
        };
    }

    evaluateXSSProtection(headers) {
        const xss = headers['x-xss-protection'];
        if (!xss) {
            return { enabled: false, reason: 'Header not present', value: null };
        }

        return {
            enabled: true,
            value: xss,
            details: {
                recommendation: 'Consider using CSP instead of X-XSS-Protection'
            }
        };
    }

    async evaluateCORS(url, headers) {
        try {
            const origin = new URL(url).origin;
            const corsResponse = await axios.options(url, {
                headers: { 'Origin': 'https://example.com' },
                timeout: this.timeout,
                maxRedirects: 5,
                validateStatus: () => true
            });

            const corsHeaders = corsResponse.headers;
            const allowOrigin = corsHeaders['access-control-allow-origin'];
            const allowMethods = corsHeaders['access-control-allow-methods'];
            const allowHeaders = corsHeaders['access-control-allow-headers'];

            return {
                enabled: !!(allowOrigin || allowMethods || allowHeaders),
                details: {
                    allowOrigin: allowOrigin || 'Not set',
                    allowMethods: allowMethods || 'Not set',
                    allowHeaders: allowHeaders || 'Not set',
                    isWildcard: allowOrigin === '*'
                }
            };
        } catch (error) {
            return {
                enabled: false,
                reason: 'CORS check failed',
                error: error.message
            };
        }
    }

    generateRecommendations(result) {
        const recommendations = [];
        const security = result.security;
        
        if (!security) return recommendations;
        
        if (!security.hsts.enabled) {
            recommendations.push({
                header: 'HSTS',
                issue: 'Missing HTTP Strict Transport Security',
                fix: `Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`,
                priority: 'HIGH',
                impact: 'Prevents HTTPS downgrade attacks and man-in-the-middle attacks'
            });
        }
        
        if (!security.csp.enabled) {
            recommendations.push({
                header: 'CSP',
                issue: 'Missing Content Security Policy',
                fix: `Add header: Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'`,
                priority: 'HIGH',
                impact: 'Prevents XSS attacks and code injection vulnerabilities'
            });
        }
        
        if (!security.xFrameOptions.enabled) {
            recommendations.push({
                header: 'X-Frame-Options',
                issue: 'Missing X-Frame-Options protection',
                fix: `Add header: X-Frame-Options: DENY`,
                priority: 'MEDIUM',
                impact: 'Prevents clickjacking attacks and UI redressing'
            });
        }
        
        if (!security.xContentTypeOptions.enabled) {
            recommendations.push({
                header: 'X-Content-Type-Options',
                issue: 'Missing MIME type protection',
                fix: `Add header: X-Content-Type-Options: nosniff`,
                priority: 'MEDIUM',
                impact: 'Prevents MIME-type sniffing attacks and file upload exploits'
            });
        }
        
        if (!security.referrerPolicy.enabled) {
            recommendations.push({
                header: 'Referrer-Policy',
                issue: 'Missing referrer policy',
                fix: `Add header: Referrer-Policy: strict-origin-when-cross-origin`,
                priority: 'MEDIUM',
                impact: 'Protects user privacy and prevents information leakage'
            });
        }
        
        if (!security.permissionsPolicy.enabled) {
            recommendations.push({
                header: 'Permissions-Policy',
                issue: 'Missing permissions policy',
                fix: `Add header: Permissions-Policy: camera=(), microphone=(), geolocation=()`,
                priority: 'LOW',
                impact: 'Limits browser feature access and reduces attack surface'
            });
        }
        
        if (security.cors.enabled && security.cors.details && security.cors.details.isWildcard) {
            recommendations.push({
                header: 'CORS',
                issue: 'Overly permissive CORS policy (wildcard)',
                fix: `Replace Access-Control-Allow-Origin: * with specific domains`,
                priority: 'HIGH',
                impact: 'Prevents unauthorized cross-origin requests and data theft'
            });
        }
        
        return recommendations;
    }
}

module.exports = SecurityHeaderValidator;
