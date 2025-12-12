// src/app.js
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

// Configuração do PostgreSQL
const poolConfig = process.env.DATABASE_URL
  ? { connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } }
  : {
      host: process.env.DB_HOST || 'localhost',
      user: process.env.DB_USER || 'postgres',
      password: process.env.DB_PASSWORD || '',
      database: process.env.DB_NAME || 'sast_demo',
      port: process.env.DB_PORT || 5432,
    };

const pool = new Pool(poolConfig);

pool.query('SELECT NOW()', (err) => {
  if (err) console.error('Erro ao conectar ao PostgreSQL:', err.stack);
  else console.log('Conectado ao PostgreSQL com sucesso!');
});

// Swagger
const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: { title: 'API Vulnerável - SAST Demo', version: '1.0.0' },
  },
  apis: ['src/app.js'],
};
const swaggerDocs = swaggerJSDoc(swaggerOptions);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocs));

// === ENDPOINTS VULNERÁVEIS ===

app.get('/users/:id', (req, res) => {
  const query = `SELECT * FROM users WHERE id = ${req.params.id}`;
  pool.query(query, (err, result) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(result.rows);
  });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  pool.query(query, (err, result) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: result.rows.length > 0 });
  });
});

app.post('/execute', (req, res) => {
  exec(req.body.command || '', (err, stdout, stderr) => {
    res.json({ output: stdout || stderr || err?.message || 'no output' });
  });
});

app.get('/download', (req, res) => {
  const file = req.query.file || '';
  res.sendFile(file, { root: '.' }, (err) => {
    if (err) res.status(500).send(err.message);
  });
});

app.get('/search', (req, res) => {
  res.send(`Resultados para: ${req.query.q || ''}`);
});

app.post('/encrypt', (req, res) => {
  try {
    const cipher = crypto.createCipheriv('des-ecb', Buffer.from('chavefraca'), null);
    let encrypted = cipher.update(req.body.data || '', 'utf8', 'hex');
    encrypted += cipher.final('hex');
    res.json({ encrypted });
  } catch (e) {
    res.status(500).json({ error: 'Encryption failed' });
  }
});

app.get('/fetch-url', (req, res) => {
  const target = req.query.url;
  if (!target) return res.status(400).json({ error: 'url required' });

  const parsed = url.parse(target);
  const lib = parsed.protocol === 'http:' ? http : https;

  lib.get(target, (resp) => {
    let data = '';
    resp.on('data', chunk => data += chunk);
    resp.on('end', () => res.send(data));
  }).on('error', (e) => res.status(500).json({ error: e.message }));
});

app.post('/calculate', (req, res) => {
  try {
    const result = eval(req.body.expression || '0');
    res.json({ result });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/validate-email', (req, res) => {
  const evilRegex = /^([a-zA-Z0-9]+)(\+[a-zA-Z0-9]+)*@evilcorp\.com$/;
  const valid = evilRegex.test(req.query.email || '');
  res.json({ valid });
});

app.get('/generate-token', (req, res) => {
  const token = Math.random().toString(36).substring(2, 15);
  res.json({ token });
});

app.post('/merge', (req, res) => {
  const target = {};
  Object.assign(target, req.body);
  res.json(target);
});

app.post('/users', (req, res) => {
  const { username, email, isAdmin } = req.body;
  const query = `INSERT INTO users (username, email, isadmin) VALUES ('${username}', '${email}', ${isAdmin || false}) RETURNING *`;
  pool.query(query, (err, result) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(result.rows[0] || {});
  });
});

app.post('/verify-token', (req, res) => {
  const validToken = 'super-secret-token-12345';
  let isValid = true;
  const token = req.body.token || '';
  for (let i = 0; i < token.length; i++) {
    if (token[i] !== validToken[i]) isValid = false;
  }
  res.json({ valid: isValid });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`API rodando na porta ${PORT}`);
  console.log(`Swagger: http://localhost:${PORT}/api-docs`);
});

module.exports = app;