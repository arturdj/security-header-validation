# Security Header Validator

A modern React web application to validate security headers on websites and identify potential vulnerabilities.

## 🚀 Features

- **Modern Web Interface** - Beautiful, responsive React frontend
- **Real-time Validation** - Instant security header analysis
- **Single & Batch Processing** - Check one URL or multiple URLs at once
- **Visual Results** - Color-coded security header status grid
- **Security Recommendations** - Actionable fixes with priority levels
- **Redirect Following** - Automatically follows redirects to check final destination
- **Comprehensive Analysis** - Checks 8 critical security headers
- **Mobile Responsive** - Works perfectly on all devices

## Installation

### Prerequisites

- Node.js (v14 or higher)
- npm, yarn, or pnpm

### Setup

1. **Clone the repository**:
```bash
git clone <repository-url>
cd security-headers-validation
```

2. **Install server dependencies**:
```bash
cd server-api
npm install
# or
yarn install
# or
pnpm install
```

3. **Install client dependencies**:
```bash
cd ../client
npm install
# or
yarn install
# or
pnpm install
```

4. **Set up environment variables**:
```bash
# In client directory
cp .env.development .env.local
```

Update `.env.local` with your API server URL:
```
REACT_APP_API_BASE_URL=http://localhost:3333
```

## Usage

### Development Environment

#### Prerequisites
- Ensure both server and client dependencies are installed
- Node.js (v14 or higher) and npm/yarn/pnpm installed

#### Running Development Servers

1. **Start the API server** (in `server-api/` directory):
```bash
cd server-api
npx edge-functions@latest dev
```
   - API server runs on `http://localhost:3333`
   - Hot reload enabled for development

2. **Start the client** (in `client/` directory):
```bash
cd client
npm start
# or
yarn start
```
   - Client opens automatically at `http://localhost:3000`
   - API requests are proxied to `http://localhost:3333`
   - Hot reload enabled for development

#### Development Features
- **Hot Reload**: Changes are reflected immediately in both server and client
- **API Proxy**: Automatic proxying from client to backend server
- **Debug Mode**: Enhanced error messages and logging

### Production Environment

#### Building for Production

1. **Build the API server**:
```bash
cd server-api
npx edge-functions@latest build
```

2. **Build the client**:
```bash
cd client
npm run build
# or
yarn build
```

#### Deployment Options

**Option 1: Azion Edge Platform (Recommended)**
```bash
# Deploy server
cd server-api
npx azion deploy

# Deploy client
cd client
npm run build
npx azion deploy
```

**Option 2: Static Hosting**
```bash
# Build and serve client
cd client
npm run build
npx serve -s build
```

#### Environment Configuration

| Component | Development | Production |
|-----------|-------------|------------|
| **API Server** | http://localhost:3333 | https://secheaders-api.azion.app |
| **Client** | http://localhost:3000 | https://op3o13c4klm.map.azionedge.net |
| **API Endpoint** | http://localhost:3333 | https://secheaders-api.azion.app |

## 📊 Output Formats

### Console Table
Visual summary showing ✅/❌ status for each security header per URL.

### Detailed Analysis
Comprehensive breakdown including:
- Redirect information
- Header values and configurations
- Security recommendations
- Missing header warnings

### Security Recommendations
Actionable security fixes with:
- Priority-based recommendations (HIGH 🔴, MEDIUM 🟡, LOW 🟢)
- Exact HTTP headers to implement
- Security impact explanations
- Copy-paste ready configurations

### CSV Export
Spreadsheet-ready format with:
- Original and final URLs
- Redirect status
- All security header statuses
- Error messages

### JSON Export
Raw data format (`security-results.json`) for programmatic processing.

## 🔧 Example Recommendations Output

When using the `-r` flag, you'll get actionable security fixes:

```
🔧 SECURITY RECOMMENDATIONS:

1. https://example.com - 3 recommendation(s):
   🔴 HIGH - HSTS: Missing HTTP Strict Transport Security
      💡 Fix: Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
      🎯 Impact: Prevents HTTPS downgrade attacks and man-in-the-middle attacks

   🔴 HIGH - CSP: Missing Content Security Policy
      💡 Fix: Add header: Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'
      🎯 Impact: Prevents XSS attacks and code injection vulnerabilities

   🟡 MEDIUM - X-Frame-Options: Missing X-Frame-Options protection
      💡 Fix: Add header: X-Frame-Options: DENY
      🎯 Impact: Prevents clickjacking attacks and UI redressing
```

## 🛡️ Security Headers Checked



## **🔒 HSTS (HTTP Strict Transport Security)**
**Purpose**: Forces HTTPS connections and prevents downgrade attacks

**Why it's critical**:
- **Prevents man-in-the-middle attacks** - Stops attackers from intercepting HTTP traffic
- **Eliminates mixed content vulnerabilities** - Ensures all resources load over HTTPS
- **Protects against SSL stripping** - Prevents attackers from forcing HTTP connections
- **Browser enforcement** - Once set, browsers refuse HTTP connections to your domain

**Real attack scenario**: Without HSTS, an attacker on public WiFi can intercept your login credentials by forcing HTTP connections.

## **🛡️ CSP (Content Security Policy)**
**Purpose**: Controls which resources (scripts, styles, images) can be loaded

**Why it's critical**:
- **Prevents XSS attacks** - Blocks malicious scripts from executing
- **Stops data exfiltration** - Controls where data can be sent
- **Mitigates code injection** - Only allows trusted script sources
- **Reduces attack surface** - Limits what external resources can do

**Real attack scenario**: Without CSP, a single XSS vulnerability can allow attackers to steal user data, hijack sessions, or install malware.

## **🖼️ X-Frame-Options**
**Purpose**: Prevents your site from being embedded in iframes

**Why it's critical**:
- **Stops clickjacking attacks** - Prevents invisible overlays that trick users
- **Protects user interactions** - Ensures users know what site they're interacting with
- **Prevents UI redressing** - Stops attackers from hiding malicious content behind legitimate UI

**Real attack scenario**: Attacker embeds your banking site in an invisible iframe, overlaying fake buttons to steal login credentials.

## **📄 X-Content-Type-Options**
**Purpose**: Prevents browsers from MIME-type sniffing

**Why it's critical**:
- **Stops file upload attacks** - Prevents malicious files from being executed as scripts
- **Eliminates MIME confusion** - Forces browsers to respect declared content types
- **Reduces polyglot attacks** - Prevents files that are valid in multiple formats

**Real attack scenario**: User uploads an image that's actually JavaScript - without this header, the browser might execute it as code.

## **🔗 Referrer-Policy**
**Purpose**: Controls what referrer information is sent with requests

**Why it's critical**:
- **Protects user privacy** - Prevents sensitive URLs from leaking
- **Reduces information disclosure** - Limits what external sites can learn about your users
- **Prevents session token leakage** - Stops URLs with tokens from being exposed

**Real attack scenario**: User visits a private document with a token in the URL, then clicks an external link - the full URL (including token) gets sent to the external site.

## **🔐 Permissions-Policy (Feature-Policy)**
**Purpose**: Controls which browser features can be used

**Why it's critical**:
- **Limits attack vectors** - Disables unnecessary browser APIs
- **Protects user privacy** - Prevents unauthorized access to camera, microphone, location
- **Reduces fingerprinting** - Limits what information sites can collect
- **Enforces principle of least privilege** - Only enables needed features

**Real attack scenario**: Malicious ad tries to access user's camera/microphone without permission - this header blocks such attempts.

## **🚫 X-XSS-Protection**
**Purpose**: Enables browser's built-in XSS filtering (legacy)

**Why it's mostly obsolete**:
- **Replaced by CSP** - Modern CSP provides better XSS protection
- **Can cause vulnerabilities** - Sometimes creates new attack vectors
- **Inconsistent browser support** - Different browsers handle it differently

**Modern recommendation**: Use CSP instead of relying on X-XSS-Protection.

## **🌐 CORS (Cross-Origin Resource Sharing)**
**Purpose**: Controls which domains can access your resources

**Why it's critical**:
- **Prevents unauthorized API access** - Stops malicious sites from using your APIs
- **Protects user data** - Ensures only trusted origins can make requests
- **Enables secure cross-origin communication** - Allows legitimate integrations while blocking attacks

**Real attack scenario**: Malicious site makes requests to your API using the user's cookies, potentially accessing or modifying their data.

## **🎯 Security Impact Summary**

**High Priority** (Must Have):
- **HSTS** - Prevents credential theft
- **CSP** - Stops XSS attacks
- **X-Frame-Options** - Prevents clickjacking

**Medium Priority** (Should Have):
- **X-Content-Type-Options** - Prevents file-based attacks
- **Referrer-Policy** - Protects privacy
- **CORS** - Controls API access

**Low Priority** (Nice to Have):
- **Permissions-Policy** - Limits browser features
- **X-XSS-Protection** - Legacy protection (use CSP instead)

Each header addresses specific attack vectors that are actively exploited in the wild. The combination creates a layered defense strategy that significantly reduces your attack surface.

## **🔍 Validation Logic (Pseudo Code)**

Here's how the security header validator checks each header:

### **🔒 HSTS (HTTP Strict Transport Security)**
```pseudocode
function checkHSTS(headers):
    hsts_header = headers['strict-transport-security']
    
    if hsts_header is missing:
        return FAIL("Header not present")
    
    // Parse max-age value
    max_age = extract_number_from_pattern(hsts_header, "max-age=(\d+)")
    
    // Check for additional directives
    includes_subdomains = hsts_header.contains("includeSubDomains")
    has_preload = hsts_header.contains("preload")
    
    return PASS with details(max_age, includes_subdomains, has_preload)
```

### **🛡️ CSP (Content Security Policy)**
```pseudocode
function checkCSP(headers):
    csp_header = headers['content-security-policy'] OR 
                 headers['content-security-policy-report-only']
    
    if csp_header is missing:
        return FAIL("Header not present")
    
    // Parse directives
    directives = split_by_semicolon(csp_header).filter_non_empty()
    has_default_src = any_directive_starts_with(directives, "default-src")
    has_script_src = any_directive_starts_with(directives, "script-src")
    
    return PASS with details(directive_count, has_default_src, has_script_src)
```

### **🖼️ X-Frame-Options**
```pseudocode
function checkXFrameOptions(headers):
    xfo_header = headers['x-frame-options']
    
    if xfo_header is missing:
        return FAIL("Header not present")
    
    valid_values = ["DENY", "SAMEORIGIN"]
    is_valid = xfo_header.uppercase() in valid_values OR
               xfo_header.uppercase().starts_with("ALLOW-FROM")
    
    recommendation = is_valid ? "Good" : "Use DENY or SAMEORIGIN"
    
    return PASS with details(is_valid, recommendation)
```

### **📄 X-Content-Type-Options**
```pseudocode
function checkXContentTypeOptions(headers):
    xcto_header = headers['x-content-type-options']
    
    if xcto_header is missing:
        return FAIL("Header not present")
    
    is_nosniff = xcto_header.lowercase() == "nosniff"
    recommendation = is_nosniff ? "Good" : "Should be 'nosniff'"
    
    return PASS with details(is_nosniff, recommendation)
```

### **🔗 Referrer-Policy**
```pseudocode
function checkReferrerPolicy(headers):
    rp_header = headers['referrer-policy']
    
    if rp_header is missing:
        return FAIL("Header not present")
    
    strict_policies = ["no-referrer", "strict-origin", "strict-origin-when-cross-origin"]
    is_strict = rp_header.lowercase() in strict_policies
    recommendation = is_strict ? "Good" : "Consider stricter policy"
    
    return PASS with details(is_strict, recommendation)
```

### **🔐 Permissions-Policy (Feature-Policy)**
```pseudocode
function checkPermissionsPolicy(headers):
    pp_header = headers['permissions-policy'] OR headers['feature-policy']
    
    if pp_header is missing:
        return FAIL("Header not present")
    
    features = split_by_comma(pp_header).filter_non_empty()
    
    return PASS with details(feature_count, first_3_features)
```

### **🚫 X-XSS-Protection**
```pseudocode
function checkXSSProtection(headers):
    xss_header = headers['x-xss-protection']
    
    if xss_header is missing:
        return FAIL("Header not present")
    
    // Header exists but is considered legacy
    recommendation = "Consider using CSP instead of X-XSS-Protection"
    
    return PASS with details(recommendation)
```

### **🌐 CORS (Cross-Origin Resource Sharing)**
```pseudocode
function checkCORS(url, headers):
    try:
        // Send OPTIONS request with test origin
        cors_response = send_options_request(url, origin="https://example.com")
        
        allow_origin = cors_response.headers['access-control-allow-origin']
        allow_methods = cors_response.headers['access-control-allow-methods']
        allow_headers = cors_response.headers['access-control-allow-headers']
        
        cors_enabled = (allow_origin OR allow_methods OR allow_headers) is present
        is_wildcard = allow_origin == "*"
        
        return cors_enabled ? PASS : FAIL with details(allow_origin, allow_methods, is_wildcard)
        
    catch network_error:
        return FAIL("CORS check failed")
```

### **🎯 Overall Validation Flow**
```pseudocode
function validateURL(url):
    try:
        // Make HEAD request to get headers
        response = http_head_request(url, follow_redirects=true)
        headers = response.headers
        final_url = response.final_url
        was_redirected = (final_url != url)
        
        // Run all security header checks
        results = {
            hsts: checkHSTS(headers),
            csp: checkCSP(headers),
            xFrameOptions: checkXFrameOptions(headers),
            xContentTypeOptions: checkXContentTypeOptions(headers),
            referrerPolicy: checkReferrerPolicy(headers),
            permissionsPolicy: checkPermissionsPolicy(headers),
            xssProtection: checkXSSProtection(headers),
            cors: checkCORS(url, headers)
        }
        
        return SUCCESS with results(url, final_url, was_redirected, status, results)
        
    catch request_error:
        return ERROR("Request failed: " + error_message)
```

**Validation Pattern**: Each check follows the same pattern:
1. **Look for header** in HTTP response
2. **Parse/validate content** according to specification
3. **Return pass/fail** with detailed analysis
4. **Provide recommendations** for improvement

The validator prioritizes detecting presence first, then evaluating the quality and security effectiveness of each header's configuration.