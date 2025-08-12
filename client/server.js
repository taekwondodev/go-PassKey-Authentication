const express = require('express');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = 3000;

// Enable CORS for all routes
app.use(cors());

// Serve static files from current directory
app.use(express.static(__dirname));

// Serve index.html for root route
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({ status: 'OK', message: 'WebAuthn Client running' });
});

app.listen(PORT, () => {
    console.log(`WebAuthn Client running on http://localhost:${PORT}`);
    console.log(`Backend API expected at http://localhost:8080`);
});
