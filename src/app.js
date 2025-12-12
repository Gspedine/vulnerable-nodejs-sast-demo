// src/app.js - VERSÃO FINAL 100% VERDE NO NODE 18+
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const { Pool } = require('pg');
const { exec } = require('child_process');
const http = require('http');
const https = require('https');
const url = require('url');
const crypto = require('crypto');
const swaggerJSDoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const pool = new Pool(
  process.env.DATABASE_URL
    ? { connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } }
    : {
        host: process.env.DB_HOST || 'localhost',
        user: process.env.DB_USER || 'postgres',
        password: process.env.DB_PASSWORD || '',
        database: process.env.DB_NAME || 'sast_demo',
        port: process.env.DB_PORT || 5432,
      }
);

const swaggerOptions = {
  definition: { openapi: '3.0.0', info: { title: 'API Vulnerável - SAST Demo', version: '1.0.0' } },
  apis: ['src/app.js'],
};
const swaggerDocs = swaggerJSDoc(swaggerOptions);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocs));

app.get('/users/:id', (req, res) => {
  const query = `SELECT * FROM users WHERE id = ${req.params.id}`;
  pool.query(query, (err, result) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(result?.rows || []);
  });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  pool.query(query, (err, result) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: !!result?.rows?.length });
  });
});

app.post('/execute', (req, res) => {
  exec(req.body.command || '', (err, stdout, stderr) => {
    res.json({ output: stdout || stderr || err?.message || '' });
  });
});

app.get('/download', (req, res) => {
  const file = req.query.file || 'README.md';
  res.sendFile(file, { root: '.' }, () => {});
});

app.get('/search', (req, res) => {
  res.send(`Resultados para: ${req.query.q || ''}`);
});

app.post('/encrypt', (req, res) => {
  const key = Buffer.from('12345678');
  const iv = Buffer.from('12345678');
  const cipher = crypto.createCipheriv('des-cbc', key, iv);
  let encrypted = cipher.update(req.body.data || 'secret', 'utf8', 'hex');
  encrypted += cipher.final('hex');
  res.json({ encrypted });
});

app.get('/fetch-url', (req, res) => {
  const target = req.query.url || '';
  if (!target) return res.status(400).send('url required');
  const lib = target.startsWith('https') ? https : http;
  lib.get(target, r => {
    let d = '';
    r.on('data', c => d += c);
    r.on('end', () => res.send(d));
  }).on('error', () => res.status(500).send('error'));
});

app.post('/calculate', (req, res) => {
  try {
    const result = eval(req.body.expression || '0');
    res.json({ result });
  } catch (e) {
    res.status(500).json({ error: 'eval error' });
  }
});

app.get('/validate-email', (req, res) => {
  const evilRegex = /^([a-zA-Z0-9]+)(\+[a-zA-Z0-9]+)*@evilcorp\.com$/;
  const valid = evilRegex.test(req.query.email || '');
  res.json({ valid });
});

app.get('/generate-token', (req, res) => {
  res.json({ token: Math.random().toString(36).substring(2, 15) });
});

app.post('/merge', (req, res) => {
  const obj = {};
  Object.assign(obj, req.body);
  res.json(obj);
});

app.post('/users', (req, res) => {
  const { username, email, isAdmin } = req.body;
  const query = `INSERT INTO users (username, email, isadmin) VALUES ('${username}', '${email}', ${isAdmin || false}) RETURNING *`;
  pool.query(query, (err, result) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(result?.rows[0] || {});
  });
});

app.post('/verify-token', (req, res) => {
  const token = req.body.token || '';
  const validToken = 'super-secret-token-12345';
  let valid = true;
  for (let i = 0; i < token.length; i++) {
    if (token[i] !== validToken[i]) { valid = false; break; }
  }
  res.json({ valid });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`API rodando na porta ${PORT}`));

module.exports = app;