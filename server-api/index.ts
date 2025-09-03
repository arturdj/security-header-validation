import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { secureHeaders } from 'hono/secure-headers';
import { serveStatic } from 'hono/cloudflare-workers';

// Types
interface SecurityHeaderDetails {
    maxAge?: number | null;
    includeSubDomains?: boolean;
    preload?: boolean;
    directiveCount?: number;
    hasDefaultSrc?: boolean;
    hasScriptSrc?: boolean;
    directives?: string[];
    isValid?: boolean;
    recommendation?: string;
    isNosniff?: boolean;
    isStrict?: boolean;
    featureCount?: number;
    features?: string[];
    allowOrigin?: string;
    allowMethods?: string;
    allowHeaders?: string;
    isWildcard?: boolean;
}

interface SecurityHeaderResult {
    enabled: boolean;
    reason?: string;
    value?: string | null;
    details?: SecurityHeaderDetails;
    error?: string;
}

interface SecurityResult {
    hsts: SecurityHeaderResult;
    csp: SecurityHeaderResult;
    xFrameOptions: SecurityHeaderResult;
    xContentTypeOptions: SecurityHeaderResult;
    referrerPolicy: SecurityHeaderResult;
    permissionsPolicy: SecurityHeaderResult;
    xssProtection: SecurityHeaderResult;
    cors: SecurityHeaderResult;
}

interface ValidationResult {
    url: string;
    finalUrl: string;
    wasRedirected: boolean;
    status?: number;
    statusText?: string;
    statusDescription?: string;
    error?: string;
    security: SecurityResult;
}

interface Recommendation {
    header: string;
    issue: string;
    fix: string;
    priority: 'HIGH' | 'MEDIUM' | 'LOW';
    impact: string;
}

class SecurityHeaderValidator {
    private timeout: number;

    constructor() {
        this.timeout = 10000; // 10 seconds timeout
    }

    private getStatusDescription(status: number): { text: string; description: string } {
        const statusMap: Record<number, { text: string; description: string }> = {
            // 1xx Informational
            100: { text: 'Continue', description: 'Request received, please continue' },
            101: { text: 'Switching Protocols', description: 'Switching to new protocol' },
            
            // 2xx Success
            200: { text: 'OK', description: 'Request successful' },
            201: { text: 'Created', description: 'Resource created successfully' },
            202: { text: 'Accepted', description: 'Request accepted for processing' },
            204: { text: 'No Content', description: 'Request successful, no content to return' },
            
            // 3xx Redirection
            301: { text: 'Moved Permanently', description: 'Resource permanently moved to new location' },
            302: { text: 'Found', description: 'Resource temporarily moved' },
            304: { text: 'Not Modified', description: 'Resource not modified since last request' },
            307: { text: 'Temporary Redirect', description: 'Temporary redirect, method preserved' },
            308: { text: 'Permanent Redirect', description: 'Permanent redirect, method preserved' },
            
            // 4xx Client Error
            400: { text: 'Bad Request', description: 'Invalid request syntax or parameters' },
            401: { text: 'Unauthorized', description: 'Authentication required' },
            403: { text: 'Forbidden', description: 'Access denied' },
            404: { text: 'Not Found', description: 'Resource not found' },
            405: { text: 'Method Not Allowed', description: 'HTTP method not supported' },
            408: { text: 'Request Timeout', description: 'Request took too long' },
            429: { text: 'Too Many Requests', description: 'Rate limit exceeded' },
            
            // 5xx Server Error
            500: { text: 'Internal Server Error', description: 'Server encountered an error' },
            502: { text: 'Bad Gateway', description: 'Invalid response from upstream server' },
            503: { text: 'Service Unavailable', description: 'Server temporarily unavailable' },
            504: { text: 'Gateway Timeout', description: 'Upstream server timeout' },
            520: { text: 'Web Server Error', description: 'Unknown server error (Cloudflare)' },
            521: { text: 'Web Server Down', description: 'Origin server refused connection' },
            522: { text: 'Connection Timed Out', description: 'Connection to origin server timed out' },
            523: { text: 'Origin Unreachable', description: 'Origin server unreachable' },
            524: { text: 'Timeout Occurred', description: 'Origin server timeout (Cloudflare)' }
        };
        
        return statusMap[status] || { text: 'Unknown', description: `HTTP status code ${status}` };
    }

    async validateUrl(url: string, showProgress: boolean = false): Promise<ValidationResult> {
        try {
            // Ensure URL has protocol
            const fullUrl = url.includes('://') ? url : `https://${url}`;
            
            if (!showProgress) {
                console.log(`🔍 Checking ${fullUrl}...`);
            }
            
            // Make HEAD request to properly follow redirects and get final headers
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), this.timeout);
            
            const response = await fetch(fullUrl, {
                method: 'HEAD',
                signal: controller.signal,
                redirect: 'follow'
            });
            
            clearTimeout(timeoutId);

            const headers: Record<string, string> = Object.fromEntries(response.headers.entries());
            const finalUrl = response.url || fullUrl;
            const wasRedirected = finalUrl !== fullUrl;
            const statusInfo = this.getStatusDescription(response.status);
            
            return {
                url: fullUrl,
                finalUrl,
                wasRedirected,
                status: response.status,
                statusText: statusInfo.text,
                statusDescription: statusInfo.description,
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
        } catch (error: any) {
            return {
                url: url.includes('://') ? url : `https://${url}`,
                finalUrl: url.includes('://') ? url : `https://${url}`,
                wasRedirected: false,
                error: error.name === 'AbortError' ? 'Request timeout' : error.message,
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

    async validateUrls(urls: string[], showProgress: boolean = false): Promise<ValidationResult[]> {
        const batchSize = 10; // Process 10 URLs concurrently
        const results: ValidationResult[] = [];
        let completedCount = 0;
        
        console.log(`🔍 Checking ${urls.length} URLs in batches of ${batchSize}...`);
        
        for (let i = 0; i < urls.length; i += batchSize) {
            const batch = urls.slice(i, i + batchSize);
            const batchNumber = Math.floor(i / batchSize) + 1;
            const totalBatches = Math.ceil(urls.length / batchSize);
            
            console.log(`📦 Processing batch ${batchNumber}/${totalBatches} (${batch.length} URLs)...`);
            
            // Create promises for current batch
            const batchPromises = batch.map(async (url: string) => {
                try {
                    const result = await this.validateUrl(url, showProgress);
                    completedCount++;
                    return result;
                } catch (error: any) {
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

    evaluateHSTS(headers: Record<string, string>): SecurityHeaderResult {
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

    evaluateCSP(headers: Record<string, string>): SecurityHeaderResult {
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

    evaluateXFrameOptions(headers: Record<string, string>): SecurityHeaderResult {
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

    evaluateXContentTypeOptions(headers: Record<string, string>): SecurityHeaderResult {
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

    evaluateReferrerPolicy(headers: Record<string, string>): SecurityHeaderResult {
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

    evaluatePermissionsPolicy(headers: Record<string, string>): SecurityHeaderResult {
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

    evaluateXSSProtection(headers: Record<string, string>): SecurityHeaderResult {
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

    async evaluateCORS(url: string, headers: Record<string, string>): Promise<SecurityHeaderResult> {
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), this.timeout);
            
            const corsResponse = await fetch(url, {
                method: 'OPTIONS',
                headers: { 'Origin': 'https://example.com' },
                signal: controller.signal,
                redirect: 'follow'
            });
            
            clearTimeout(timeoutId);

            const corsHeaders: Record<string, string> = Object.fromEntries(corsResponse.headers.entries());
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
        } catch (error: any) {
            return {
                enabled: false,
                reason: 'CORS check failed',
                error: error.name === 'AbortError' ? 'Request timeout' : error.message
            };
        }
    }

    generateRecommendations(result: ValidationResult): Recommendation[] {
        const recommendations: Recommendation[] = [];
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

const app = new Hono();

// Middleware
app.use('*', secureHeaders());
app.use('*', cors({
    origin: ['http://localhost:3000', 'http://localhost:3333', '*'],
    allowHeaders: ['Content-Type', 'Authorization'],
    allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    credentials: true
}));

// Initialize validator
const validator = new SecurityHeaderValidator();

// API Routes
// Validate single URL
app.post('/api/validate', async (c) => {
    try {
        const body = await c.req.json();
        const { url } = body;
        
        if (!url) {
            return c.json({ error: 'URL is required' }, 400);
        }
        
        const result = await validator.validateUrl(url);
        return c.json(result);
    } catch (error: any) {
        return c.json({ error: error.message }, 500);
    }
});

// Validate multiple URLs
app.post('/api/validate-batch', async (c) => {
    try {
        const body = await c.req.json();
        const { urls } = body;
        
        if (!urls || !Array.isArray(urls) || urls.length === 0) {
            return c.json({ error: 'URLs array is required' }, 400);
        }
        
        if (urls.length > 50) {
            return c.json({ error: 'Maximum 50 URLs allowed per batch' }, 400);
        }
        
        const results = await validator.validateUrls(urls);
        return c.json(results);
    } catch (error: any) {
        return c.json({ error: error.message }, 500);
    }
});

// Get recommendations for a result
app.post('/api/recommendations', async (c) => {
    try {
        const body = await c.req.json();
        const { result } = body;
        
        if (!result) {
            return c.json({ error: 'Result object is required' }, 400);
        }
        
        const recommendations = validator.generateRecommendations(result);
        return c.json({ recommendations });
    } catch (error: any) {
        return c.json({ error: error.message }, 500);
    }
});

// Health check endpoint
app.get('/api/health', (c) => {
    return c.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Serve static files from React build (for Cloudflare Workers)
app.get('/static/*', serveStatic({ root: './client/build/', manifest: {} }));
app.get('/manifest.json', serveStatic({ path: './client/build/manifest.json', manifest: {} }));
app.get('/favicon.ico', serveStatic({ path: './client/build/favicon.ico', manifest: {} }));

// Serve React app for all other routes
app.get('*', serveStatic({ path: './client/build/index.html', manifest: {} }));

// Export for edge runtime
export default app;


// // For Node.js compatibility
// if (typeof process !== 'undefined' && process.env.NODE_ENV !== 'production') {
//     try {
//         const { serve } = await import('@hono/node-server');
//         const port = parseInt(process.env.PORT || '5001');
        
//         console.log(`🚀 Server running on port ${port}`);
//         console.log(`🌐 Frontend: http://localhost:${port}`);
//         console.log(`🔧 API: http://localhost:${port}/api`);
        
//         serve({
//             fetch: app.fetch,
//             port
//         });
//     } catch (error) {
//         console.log('⚠️ @hono/node-server not available. Running in edge runtime mode.');
//     }
// }