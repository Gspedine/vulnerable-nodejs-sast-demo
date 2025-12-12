// src/app.js
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const { Pool } = require('pg');
const { exec } = require('child_process');
const http = require('http');  // Adicionado para suportar http em /fetch-url
const https = require('https');
const path = require('path');
const crypto = require('crypto');
const swaggerJSDoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Configuração flexível do PostgreSQL (Render + local)
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

// Teste de conexão
pool.query('SELECT NOW()', (err, res) => {
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

// === ENDPOINTS VULNERÁVEIS (compatíveis com app.test.js) ===

// GET /users - SQL Injection (com query.id para compatibilidade com testes)
app.get('/users', (req, res) => {
  const id = req.query.id || 1;
  const query = `SELECT * FROM users WHERE id = ${id}`;
  pool.query(query, (err, result) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(result.rows);
  });
});

// GET /users/:id - SQL Injection
app.get('/users/:id', (req, res) => {
  const query = `SELECT * FROM users WHERE id = ${req.params.id}`;
  pool.query(query, (err, result) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(result.rows);
  });
});

// POST /login - SQL Injection
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  pool.query(query, (err, result) => {
    if (err) return res.status(500).json({ error: err.message });
    if (result.rows.length > 0) res.json({ success: true });
    else res.status(401).json({ success: false });
  });
});

// POST /execute - Command Injection
app.post('/execute', (req, res) => {
  exec(req.body.command, (err, stdout, stderr) => {
    res.json({ output: stdout || stderr || err });
  });
});

// GET /download - Path Traversal
app.get('/download', (req, res) => {
  const file = req.query.file || '';
  res.sendFile(file, { root: '.' }, (err) => {
    if (err) res.status(500).send(err.message);
  });
});

// GET /search - XSS Refletido
app.get('/search', (req, res) => {
  res.send(`Resultados para: ${req.query.q}`);
});

// POST /encrypt - Criptografia Fraca (DES)
app.post('/encrypt', (req, res) => {
  const cipher = crypto.createCipher('des', 'chavefraca');
  let encrypted = cipher.update(req.body.data || '', 'utf8', 'hex');
  encrypted += cipher.final('hex');
  res.json({ encrypted });
});

// GET /fetch-url - SSRF (fix: suporte a http/https dinâmico)
app.get('/fetch-url', (req, res) => {
  if (!req.query.url) return res.status(400).json({ error: 'url required' });
  const urlModule = require('url');
  const parsedUrl = urlModule.parse(req.query.url);
  const protocolLib = parsedUrl.protocol === 'http:' ? http : https;
  protocolLib.get(req.query.url, (resp) => {
    let data = '';
    resp.on('data', chunk => data += chunk);
    resp.on('end', () => res.send(data));
  }).on('error', (err) => res.status(500).json({ error: err.message }));
});

// POST /calculate - Code Injection (eval)
app.post('/calculate', (req, res) => {
  try {
    const result = eval(req.body.expression || '0');
    res.json({ result });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /validate-email - ReDoS (regex vulnerável)
app.get('/validate-email', (req, res) => {
  const evilRegex = /^([a-zA-Z0-9]+)(\+[a-zA-Z0-9]+)*@evilcorp\.com$/;
  const valid = evilRegex.test(req.query.email || '');
  res.json({ valid });
});

// GET /generate-token - Random Inseguro
app.get('/generate-token', (req, res) => {
  const token = Math.random().toString(36).substring(2, 15);
  res.json({ token });
});

// POST /merge - Prototype Pollution
app.post('/merge', (req, res) => {
  const target = {};
  Object.assign(target, req.body);
  res.json(target);
});

// POST /users - Mass Assignment
app.post('/users', (req, res) => {
  const { username, email, isAdmin } = req.body;
  const query = `INSERT INTO users (username, email, isadmin) VALUES ('${username}', '${email}', ${isAdmin || false}) RETURNING *`;
  pool.query(query, (err, result) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(result.rows[0]);
  });
});

// POST /verify-token - Timing Attack
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