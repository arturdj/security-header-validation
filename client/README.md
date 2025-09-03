# Security Header Validator - Client

A modern React-based web application for validating security headers on websites. Features an interactive cyberpunk-inspired UI with glitch effects and terminal animations.

## Features

- **Batch URL Validation**: Validate security headers for multiple URLs at once
- **File Upload Support**: Upload text files containing lists of URLs
- **Interactive UI**: Cyberpunk-themed interface with glitch text effects
- **Terminal Animation**: Background terminal commands with hover interactions
- **Real-time Results**: Live validation results with expandable details
- **Responsive Design**: Modern, mobile-friendly interface

## Prerequisites

- Node.js (v14 or higher)
- npm or yarn
- Running instance of the Security Header Validator API server

## Installation

1. Install dependencies:
```bash
npm install
# or
yarn install
```

2. Set up environment variables:
```bash
# Copy environment files and configure API endpoint
cp .env.development .env.local
```

Update `.env.local` with your API server URL:
```
REACT_APP_API_BASE_URL=http://localhost:3333
```

## Development Environment

### Prerequisites
- Ensure the Security Header Validator API server is running on `http://localhost:3333`
- Node.js (v14 or higher) and npm/yarn installed

### Running Development Server

1. **Start the development server**:
```bash
npm start
# or
yarn start
```

2. **Access the application**:
   - Opens automatically at `http://localhost:3000`
   - Hot reload enabled for development
   - API requests are proxied to `http://localhost:3333` (configured in `package.json`)

3. **Environment Configuration**:
   - Uses `.env.development` for configuration
   - Default API endpoint: `http://localhost:3333`
   - Default port: `3000`

### Development Features
- **Hot Reload**: Changes are reflected immediately
- **API Proxy**: Automatic proxying to backend server
- **Debug Mode**: Enhanced error messages and logging

## Production Environment

### Building for Production

1. **Create production build**:
```bash
npm run build
# or
yarn build
```

2. **Build output**:
   - Optimized static files in `build/` directory
   - Minified and compressed assets
   - Production environment variables applied

### Production Configuration

The production build uses `.env.production` with:
- **API Endpoint**: `https://secheaders-api.azion.app`
- **Optimized Build**: Minified code and assets
- **CDN Ready**: Static files optimized for edge delivery

### Deployment Options

#### Option 1: Azion Edge Platform (Recommended)
```bash
# Build and deploy to Azion
npm run build
npx azion deploy
```

**Live URL**: https://op3o13c4klm.map.azionedge.net

#### Option 2: Static Hosting
```bash
# Build the application
npm run build

# Serve the build directory with any static file server
# Examples:
npx serve -s build
# or
python -m http.server 3000 -d build
# or upload build/ contents to your hosting provider
```

### Environment Variables

| Variable | Development | Production |
|----------|-------------|------------|
| `PORT` | 3000 | 3000 |
| `REACT_APP_API_BASE_URL` | http://localhost:3333 | https://secheaders-api.azion.app |

To customize these values:
1. Copy the appropriate `.env` file: `cp .env.development .env.local`
2. Modify values in `.env.local`
3. Restart the development server

## Usage

1. **Single URL Validation**: Enter a URL in the input field and click "Validate"
2. **Batch Validation**: Enter multiple URLs (one per line) in the textarea
3. **File Upload**: Upload a `.txt` file containing URLs (one per line, max 50 URLs)
4. **View Results**: Click on any result to expand and view detailed security header information

## Supported Security Headers

The validator checks for common security headers including:
- Content Security Policy (CSP)
- Strict Transport Security (HSTS)
- X-Frame-Options
- X-Content-Type-Options
- Referrer Policy
- Permissions Policy
- Cross-Origin Embedder Policy
- X-XSS-Protection

## API Integration

The client communicates with the backend API via:
- **Endpoint**: `POST /api/validate-batch`
- **Payload**: `{ urls: string[] }`
- **Response**: Array of validation results with security header analysis

## Project Structure

```
client/
├── public/           # Static assets
├── src/
│   ├── App.js       # Main application component
│   ├── App.css      # Styling and animations
│   ├── index.js     # React entry point
│   └── index.css    # Global styles
├── package.json     # Dependencies and scripts
└── README.md        # This file
```

## Technologies Used

- **React 18**: Frontend framework
- **Axios**: HTTP client for API requests
- **CSS3**: Custom animations and cyberpunk styling
- **Create React App**: Build tooling and development server

## Deployment

The application is configured for deployment on Azion Edge Platform:

```bash
# Build for edge deployment
npx edge-functions@latest build

# Deploy to Azion
npx azion deploy
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is part of the Security Header Validator suite. See the main repository for license information.
