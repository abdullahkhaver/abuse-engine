const express = require('express');
const SimpleAbuseDetector = require('./simple-abuse-detector.js');

const app = express();
const abuseDetector = new SimpleAbuseDetector();

// Add abuse detection middleware
app.use(abuseDetector.middleware());

// Parse JSON
app.use(express.json());

// Demo routes
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    
    // Simulate authentication
    if (username === 'admin' && password === 'password123') {
        res.json({ success: true, token: 'fake-jwt-token' });
    } else {
        res.status(401).json({ error: 'Invalid credentials' });
    }
});

app.get('/api/users', (req, res) => {
    res.json({ users: ['user1', 'user2', 'user3'] });
});

app.get('/api/admin', (req, res) => {
    res.json({ admin: true, message: 'Admin area' });
});

app.get('/api/public', (req, res) => {
    res.json({ message: 'Public endpoint', timestamp: new Date().toISOString() });
});

// Stats endpoint to see current state
app.get('/api/stats', (req, res) => {
    res.json(abuseDetector.getStats());
});

// Start cleanup interval (every 5 minutes)
setInterval(() => abuseDetector.cleanup(), 5 * 60 * 1000);

// Start server
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log('Available endpoints:');
    console.log('  POST /api/login');
    console.log('  GET  /api/users');
    console.log('  GET  /api/admin');
    console.log('  GET  /api/public');
    console.log('  GET  /api/stats');
});