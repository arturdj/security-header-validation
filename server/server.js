const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const path = require('path');
const SecurityHeaderValidator = require('./validator');

const app = express();
const PORT = process.env.PORT || 5001;

// Middleware
app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
}));
app.use(cors({
    origin: ['http://localhost:3000', 'http://localhost:5001', 'http://localhost:3001'],
    credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Serve static files from React build
app.use(express.static(path.join(__dirname, '../client/build')));

// API Routes
const validator = new SecurityHeaderValidator();

// Validate single URL
app.post('/api/validate', async (req, res) => {
    try {
        const { url } = req.body;
        
        if (!url) {
            return res.status(400).json({ error: 'URL is required' });
        }
        
        const result = await validator.validateUrl(url);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Validate multiple URLs
app.post('/api/validate-batch', async (req, res) => {
    try {
        const { urls } = req.body;
        
        if (!urls || !Array.isArray(urls) || urls.length === 0) {
            return res.status(400).json({ error: 'URLs array is required' });
        }
        
        if (urls.length > 50) {
            return res.status(400).json({ error: 'Maximum 50 URLs allowed per batch' });
        }
        
        const results = await validator.validateUrls(urls);
        res.json(results);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get recommendations for a result
app.post('/api/recommendations', async (req, res) => {
    try {
        const { result } = req.body;
        
        if (!result) {
            return res.status(400).json({ error: 'Result object is required' });
        }
        
        const recommendations = validator.generateRecommendations(result);
        res.json({ recommendations });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Serve React app for all other routes
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../client/build/index.html'));
});

app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`🌐 Frontend: http://localhost:${PORT}`);
    console.log(`🔧 API: http://localhost:${PORT}/api`);
});
