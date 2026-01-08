import express from 'express';
import { AbuseDetector } from './src/AbuseDetector.ts';

const app = express();
app.use(express.json());

const detector = new AbuseDetector();
app.use(detector.middleware());

// normal endpoint
app.get('/api/data', (req, res) => {
  res.json({ ok: true });
});

// fake login endpoint (always fails)
app.post('/api/auth/login', (req, res) => {
  res.status(401).json({ error: 'Invalid credentials' });
});

// start server
app.listen(3000, () => {
  console.log('Server running on http://localhost:3000');
});

// optional cleanup
setInterval(() => detector.cleanup(), 60_000);
