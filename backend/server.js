const express = require('express');
const cors = require('cors');
const path = require('path');
const multer = require('multer');
const FormData = require('form-data');
const fetch = require('node-fetch');

const app = express();
const PORT = process.env.PORT || 8080;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../frontend')));

// File upload setup
const upload = multer({ storage: multer.memoryStorage() });

// ✅ VIRUSTOTAL - Scan de arquivos
app.post('/api/virustotal/scan-file', upload.single('file'), async (req, res) => {
    try {
        const formData = new FormData();
        formData.append('file', req.file.buffer, {
            filename: req.file.originalname,
            contentType: req.file.mimetype
        });

        const response = await fetch('https://www.virustotal.com/api/v3/files', {
            method: 'POST',
            headers: {
                'x-apikey': process.env.VIRUSTOTAL_API,
            },
            body: formData
        });

        const data = await response.json();
        res.json(data);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ✅ VIRUSTOTAL - Consultar resultados
app.get('/api/virustotal/analysis/:id', async (req, res) => {
    try {
        const response = await fetch(`https://www.virustotal.com/api/v3/analyses/${req.params.id}`, {
            headers: {
                'x-apikey': process.env.VIRUSTOTAL_API,
            }
        });
        
        const data = await response.json();
        res.json(data);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ✅ ABUSEIPDB - Consultar IP
app.get('/api/abuseipdb/check-ip/:ip', async (req, res) => {
    try {
        const response = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${req.params.ip}`, {
            headers: {
                'Key': process.env.ABUSEIPDB_API,
                'Accept': 'application/json'
            }
        });

        const data = await response.json();
        res.json(data);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ✅ SHODAN - Consultar IP
app.get('/api/shodan/host/:ip', async (req, res) => {
    try {
        const response = await fetch(`https://api.shodan.io/shodan/host/${req.params.ip}?key=${process.env.SHODAN_API}`);
        
        const data = await response.json();
        res.json(data);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ✅ HYBRID ANALYSIS - Scan URL
app.post('/api/hybridanalysis/scan-url', async (req, res) => {
    try {
        const response = await fetch('https://www.hybrid-analysis.com/api/v2/scan/url', {
            method: 'POST',
            headers: {
                'api-key': process.env.HYBRIDANALYSIS_API,
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: `scan_type=all&url=${encodeURIComponent(req.body.url)}`
        });

        const data = await response.json();
        res.json(data);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ✅ HEALTH CHECK
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        message: 'SecureShield Platform Running',
        timestamp: new Date().toISOString()
    });
});

// Serve frontend
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/index.html'));
});

app.listen(PORT, () => {
    console.log(`🚀 SecureShield running on port ${PORT}`);
    console.log(`✅ APIs: VirusTotal, AbuseIPDB, Shodan, Hybrid Analysis`);
});
