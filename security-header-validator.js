const axios = require('axios');
const { URL } = require('url');

class SecurityHeaderValidator {
    constructor() {
        this.timeout = 10000; // 10 seconds timeout
    }

    async validateUrl(url, showProgress = false) {
        try {
            if (!showProgress) {
                console.log(`🔍 Checking ${url}...`);
            }
            
            // Make HEAD request to properly follow redirects and get final headers
            const response = await axios.head(url, {
                timeout: this.timeout,
                maxRedirects: 5,
                validateStatus: () => true // Accept any status code
            });

            const headers = response.headers;
            const finalUrl = response.request.res.responseUrl || response.config.url || url;
            const wasRedirected = finalUrl !== url;
            
            return {
                url,
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
                url,
                finalUrl: url,
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

    async validateUrls(urls, showProgress = false) {
        const batchSize = 10; // Process 10 URLs concurrently
        const results = [];
        let completedCount = 0;
        
        console.log(`🔍 Checking ${urls.length} URLs in batches of ${batchSize}...`);
        
        for (let i = 0; i < urls.length; i += batchSize) {
            const batch = urls.slice(i, i + batchSize);
            const batchNumber = Math.floor(i / batchSize) + 1;
            const totalBatches = Math.ceil(urls.length / batchSize);
            
            if (showProgress) {
                this.showProgressBar(completedCount, urls.length, `Starting batch ${batchNumber}/${totalBatches}`);
            } else {
                console.log(`📦 Processing batch ${batchNumber}/${totalBatches} (${batch.length} URLs)...`);
            }
            
            // Create promises for current batch
            const batchPromises = batch.map(async (url) => {
                try {
                    const result = await this.validateUrl(url, showProgress);
                    if (!showProgress) {
                        console.log(`✅ ${url}`);
                    } else {
                        // Only update progress when URL is completed
                        completedCount++;
                        this.showProgressBar(completedCount, urls.length, `Completed: ${url}`);
                    }
                    return result;
                } catch (error) {
                    if (!showProgress) {
                        console.log(`❌ ${url}: ${error.message}`);
                    } else {
                        // Count errors as completed too
                        completedCount++;
                        this.showProgressBar(completedCount, urls.length, `Error: ${url}`);
                    }
                    return {
                        url,
                        finalUrl: url,
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
        
        if (showProgress) {
            console.log('\n✅ Validation complete!');
        }
        
        return results;
    }
    
    showProgressBar(current, total, status = '') {
        const percentage = Math.floor((current / total) * 100);
        const barLength = 40;
        const filledLength = Math.floor((current / total) * barLength);
        const bar = '█'.repeat(filledLength) + '░'.repeat(barLength - filledLength);
        
        // Clear current line and any line below, then write progress bar
        process.stdout.write(`\r\x1b[K🔍 [${bar}] ${percentage}% (${current}/${total})`);
        
        if (status) {
            // Write status on the line below and move cursor back up
            process.stdout.write(`\n\x1b[K${status}\x1b[1A`);
        }
    }

    printResults(results, showDetails = true) {
        console.log('\n📊 SECURITY HEADER VALIDATION RESULTS\n');
        
        // Create table header
        const headers = ['URL', 'Redirected', 'HSTS', 'CSP', 'X-Frame', 'X-Content', 'Referrer', 'Permissions', 'XSS-Protect', 'CORS'];
        const colWidths = [25, 10, 8, 8, 8, 10, 10, 12, 12, 8];
        
        // Print table header
        this.printTableRow(headers, colWidths);
        this.printTableSeparator(colWidths);
        
        // Print each result as a table row
        results.forEach(result => {
            if (result.error) {
                const row = [
                    this.truncateUrl(result.url, colWidths[0]),
                    '❌ ERR', '❌ ERR', '❌ ERR', '❌ ERR', '❌ ERR', 
                    '❌ ERR', '❌ ERR', '❌ ERR', '❌ ERR'
                ];
                this.printTableRow(row, colWidths);
                return;
            }
            
            const security = result.security;
            const row = [
                this.truncateUrl(result.url, colWidths[0]),
                result.wasRedirected ? '🔄 YES' : '❌ NO',
                security.hsts.enabled ? '✅ YES' : '❌ NO',
                security.csp.enabled ? '✅ YES' : '❌ NO',
                security.xFrameOptions.enabled ? '✅ YES' : '❌ NO',
                security.xContentTypeOptions.enabled ? '✅ YES' : '❌ NO',
                security.referrerPolicy.enabled ? '✅ YES' : '❌ NO',
                security.permissionsPolicy.enabled ? '✅ YES' : '❌ NO',
                security.xssProtection.enabled ? '✅ YES' : '❌ NO',
                security.cors.enabled ? '✅ YES' : '❌ NO'
            ];
            
            this.printTableRow(row, colWidths);
        });
        
        this.printTableSeparator(colWidths);
        
        // Print detailed analysis only if requested
        if (showDetails) {
            console.log('\n📋 DETAILED ANALYSIS:\n');
            
            results.forEach((result, index) => {
                if (result.error) {
                    console.log(`${index + 1}. ${result.url} - ❌ Error: ${result.error}\n`);
                    return;
                }
                
                console.log(`${index + 1}. ${result.url} (Status: ${result.status})`);
                if (result.wasRedirected) {
                    console.log(`   🔄 Redirected to: ${result.finalUrl}`);
                }
                
                const security = result.security;
                const details = [];
                
                // Collect important details
                if (security.hsts.enabled && security.hsts.details) {
                    details.push(`HSTS: ${security.hsts.details.maxAge}s, SubDomains: ${security.hsts.details.includeSubDomains ? 'Yes' : 'No'}, Preload: ${security.hsts.details.preload ? 'Yes' : 'No'}`);
                }
                
                if (security.csp.enabled && security.csp.details) {
                    details.push(`CSP: ${security.csp.details.directiveCount} directives, default-src: ${security.csp.details.hasDefaultSrc ? 'Yes' : 'No'}`);
                }
                
                if (security.xFrameOptions.enabled) {
                    details.push(`X-Frame-Options: ${security.xFrameOptions.value} (${security.xFrameOptions.details.isValid ? 'Valid' : 'Invalid'})`);
                }
                
                if (security.cors.enabled && security.cors.details) {
                    details.push(`CORS: Origin=${security.cors.details.allowOrigin}, Wildcard=${security.cors.details.isWildcard ? 'Yes ⚠️' : 'No'}`);
                }
                
                // Print warnings for missing headers
                const missing = [];
                if (!security.hsts.enabled) missing.push('HSTS');
                if (!security.csp.enabled) missing.push('CSP');
                if (!security.xContentTypeOptions.enabled) missing.push('X-Content-Type-Options');
                if (!security.referrerPolicy.enabled) missing.push('Referrer-Policy');
                
                if (details.length > 0) {
                    details.forEach(detail => console.log(`   • ${detail}`));
                }
                
                if (missing.length > 0) {
                    console.log(`   ⚠️  Missing: ${missing.join(', ')}`);
                }
                
                console.log('');
            });
        }
    }
    
    exportToCSV(results, filename) {
        const fs = require('fs');
        
        // CSV headers
        const headers = [
            'URL',
            'Final URL',
            'Redirected',
            'Status',
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
        
        // Convert results to CSV rows
        const csvRows = [headers.join(',')];
        
        results.forEach(result => {
            const row = [
                `"${result.url}"`,
                `"${result.finalUrl || result.url}"`,
                result.wasRedirected ? 'YES' : 'NO',
                result.error ? 'ERROR' : (result.status || 'N/A'),
                result.error ? 'ERROR' : (result.security.hsts.enabled ? 'YES' : 'NO'),
                result.error ? 'ERROR' : (result.security.csp.enabled ? 'YES' : 'NO'),
                result.error ? 'ERROR' : (result.security.xFrameOptions.enabled ? 'YES' : 'NO'),
                result.error ? 'ERROR' : (result.security.xContentTypeOptions.enabled ? 'YES' : 'NO'),
                result.error ? 'ERROR' : (result.security.referrerPolicy.enabled ? 'YES' : 'NO'),
                result.error ? 'ERROR' : (result.security.permissionsPolicy.enabled ? 'YES' : 'NO'),
                result.error ? 'ERROR' : (result.security.xssProtection.enabled ? 'YES' : 'NO'),
                result.error ? 'ERROR' : (result.security.cors.enabled ? 'YES' : 'NO'),
                result.error ? `"${result.error}"` : ''
            ];
            csvRows.push(row.join(','));
        });
        
        // Write CSV file
        const csvContent = csvRows.join('\n');
        fs.writeFileSync(filename, csvContent);
        console.log(`\n📊 CSV results exported to ${filename}`);
    }
    
    printTableRow(columns, widths) {
        let row = '│';
        columns.forEach((col, i) => {
            const padded = col.toString().padEnd(widths[i]);
            row += ` ${padded} │`;
        });
        console.log(row);
    }
    
    printTableSeparator(widths) {
        let separator = '├';
        widths.forEach((width, i) => {
            separator += '─'.repeat(width + 2);
            separator += i < widths.length - 1 ? '┼' : '┤';
        });
        console.log(separator);
    }
    
    truncateUrl(url, maxLength) {
        if (url.length <= maxLength) return url;
        
        // Remove protocol for more space
        let shortened = url.replace(/^https?:\/\//, '');
        
        if (shortened.length <= maxLength) return shortened;
        
        // Truncate and add ellipsis
        return shortened.substring(0, maxLength - 3) + '...';
    }
}

// Example usage
async function main() {
    const validator = new SecurityHeaderValidator();
    
    // Read URLs from a file or command line argument
    const argv = require('yargs')
        .usage('Usage: $0 [options] [urls...]')
        .option('file', {
            alias: 'f',
            describe: 'File containing URLs to check',
            type: 'string'
        })
        .option('urls', {
            alias: 'u',
            describe: 'Comma-separated list of URLs to check',
            type: 'string'
        })
        .option('progress', {
            alias: 'p',
            describe: 'Show progress bar during validation',
            type: 'boolean',
            default: false
        })
        .option('summary', {
            alias: 's',
            describe: 'Show only summary table, hide detailed analysis',
            type: 'boolean',
            default: false
        })
        .option('csv', {
            alias: 'c',
            describe: 'Export results to CSV file (optional filename, defaults to security-results.csv)',
            type: 'string'
        })
        .help('h')
        .argv;
    
    let urlsToCheck;
    if (argv.file) {
        const fs = require('fs');
        urlsToCheck = fs.readFileSync(argv.file, 'utf8')
            .split('\n')
            .map(url => url.trim())
            .filter(url => url.length > 0)
            .map(url => url.includes('://') ? url : `https://${url}`);
    } else if (argv.urls) {
        urlsToCheck = argv.urls.split(',')
            .map(url => url.trim())
            .filter(url => url.length > 0)
            .map(url => url.replace(/,$/, '')) // Remove trailing commas
            .filter(url => url.length > 0)
            .map(url => url.includes('://') ? url : `https://${url}`);
    } else if (argv._.length > 0) {
        // Handle positional arguments - check if any contain commas
        urlsToCheck = [];
        argv._.forEach(arg => {
            if (arg.includes(',')) {
                // Split comma-separated values
                const splitUrls = arg.split(',')
                    .map(url => url.trim())
                    .filter(url => url.length > 0)
                    .map(url => url.replace(/,$/, '')) // Remove trailing commas
                    .filter(url => url.length > 0);
                urlsToCheck.push(...splitUrls);
            } else {
                urlsToCheck.push(arg);
            }
        });
        // Add https:// protocol if missing
        urlsToCheck = urlsToCheck.map(url => url.includes('://') ? url : `https://${url}`);
    } else {
        console.error('Please provide URLs either via --urls, --file, or as arguments');
        process.exit(1);
    }
    
    console.log('🚀 Starting security header validation...');
    console.log(`📋 Checking ${urlsToCheck.length} URLs\n`);
    
    const results = await validator.validateUrls(urlsToCheck, argv.progress);
    
    // Print formatted results
    validator.printResults(results, !argv.summary);
    
    // Export to CSV if requested
    if (argv.csv !== undefined) {
        const csvFilename = argv.csv || 'security-results.csv';
        validator.exportToCSV(results, csvFilename);
    }
    
    // Also save raw JSON results
    const fs = require('fs');
    fs.writeFileSync('security-results.json', JSON.stringify(results, null, 2));
    console.log('\n💾 Raw results saved to security-results.json');
}

// Run if this file is executed directly
if (require.main === module) {
    main().catch(console.error);
}

module.exports = SecurityHeaderValidator;
