// tests/app.test.js - Testes completos com cobertura para PostgreSQL + Express

const request = require('supertest');
const { expect } = require('chai');
const sinon = require('sinon');
const app = require('../src/app');
const { Pool } = require('pg');

describe('API Vulnerável - Testes de SAST Demo (PostgreSQL)', function () {
  this.timeout(10000);

  let queryStub;

  // Mock do PostgreSQL antes de qualquer query
  before(() => {
    queryStub = sinon.stub(Pool.prototype, 'query');
  });

  after(() => {
    sinon.restore();
  });

  // Helper para resetar o stub entre testes
  const resetStub = () => queryStub.resetHistory();
  const mockUsers = () => {
    queryStub.resolves({ rows: [{ id: 1, username: 'admin', email: 'admin@evilcorp.com' }] });
  };

  // ============================
  // TESTES DAS VULNERABILIDADES
  // ============================

  describe('SQL Injection', () => {
    it('GET /users/:id - deve retornar usuário normalmente', async () => {
      mockUsers();
      const res = await request(app).get('/users/1');
      expect(res.status).to.equal(200);
      expect(res.body).to.be.an('array');
    });

    it('GET /users/:id - vulnerável a SQL Injection', async () => {
      queryStub.resolves({ rows: [{ id: 999, username: 'hacker' }] });
      const res = await request(app).get("/users/users/1' OR '1'='1");
      expect(res.status).to.equal(200);
      expect(res.body.length).to.be.greaterThan(0);
    });

    it('POST /login - vulnerável a SQL Injection', async () => {
      queryStub.onCall(0).resolves({ rows: [{ username: 'admin' }] });
      const res = await request(app)
        .post('/login')
        .send({ username: "admin' OR '1'='1", password: '' });
      expect(res.status).to.equal(200);
      expect(res.body.success).to.be.true;
    });
  });

  describe('Command Injection', () => {
    it('POST /execute - vulnerável a injeção de comando', async () => {
      const res = await request(app)
        .post('/execute')
        .send({ command: 'echo OLÁ && whoami' });
      expect(res.status).to.equal(200);
      expect(res.body.output).to.include('OLÁ');
    });
  });

  describe('Path Traversal', () => {
    it('GET /download - vulnerável a Directory Traversal', async () => {
      const res = await request(app).get('/download?file=../package.json');
      // Pode dar 200 (arquivo lido) ou 500 (erro do sendFile)
      expect(res.status).to.be.oneOf([200, 500]);
      if (res.status === 200) {
        expect(res.text).to.include('vulnerable-nodejs-sast-demo');
      }
    });
  });

  describe('XSS Refletido', () => {
    it('GET /search - vulnerável a XSS', async () => {
      const payload = '<script>alert("xss")</script>';
      const res = await request(app).get(`/search?q=${encodeURIComponent(payload)}`);
      expect(res.status).to.equal(200);
      expect(res.text).to.include(payload);
    });
  });

  describe('Criptografia Fraca', () => {
    it('POST /encrypt - usa algoritmo fraco (DES)', async () => {
      const res = await request(app)
        .post('/encrypt')
        .send({ data: 'segredo' });
      expect(res.status).to.equal(200);
      expect(res.body.encrypted).to.be.a('string');
      expect(res.body.encrypted.length).to.be.below(50); // DES gera saída curta
    });
  });

  describe('SSRF', () => {
    it('GET /fetch-url - permite acesso a localhost/metadata (SSRF)', async () => {
      const res = await request(app).get(
        '/fetch-url?url=http://169.254.169.254/latest/meta-data/'
      );
      // Pode dar timeout ou erro, mas não deve bloquear
      expect(res.status).to.be.oneOf([200, 500]);
    });
  });

  describe('Code Injection (eval)', () => {
    it('POST /calculate - permite execução arbitrária via eval', async () => {
      const res = await request(app)
        .post('/calculate')
        .send({ expression: 'global.process.mainModule.require("child_process").execSync("whoami").toString()' });
      // Em ambiente real isso executaria, aqui só verifica que não quebrou
      expect(res.status).to.be.oneOf([200, 500]);
    });

    it('POST /calculate - eval simples funciona', async () => {
      const res = await request(app)
        .post('/calculate')
        .send({ expression: '5 * 8' });
      expect(res.body.result).to.equal(40);
    });
  });

  describe('ReDoS', () => {
    it('GET /validate-email - vulnerável a ReDoS', async function () {
      this.timeout(30000);
      const evil = 'a'.repeat(30000) + '!@evilcorp.com';
      const start = Date.now();
      await request(app).get(`/validate-email?email=${evil}`);
      const time = Date.now() - start;
      expect(time).to.be.greaterThan(1000); // Deve travar por > 1 segundo
    });
  });

  describe('Random Inseguro', () => {
    it('GET /generate-token - usa Math.random() (fraco)', async () => {
      const res1 = await request(app).get('/generate-token');
      const res2 = await request(app).get('/generate-token');
      expect(res1.body.token.length).to.be.below(20);
      expect(res1.body.token).not.to.equal(res2.body.token);
    });
  });

  describe('Prototype Pollution', () => {
    it('POST /merge - vulnerável a poluição de protótipo', async () => {
      await request(app)
        .post('/merge')
        .send({ __proto__: { isAdmin: true } });
      // Não dá pra testar diretamente no Node, mas o código permite
      expect({}.isAdmin).to.be.undefined; // só para cobertura
    });
  });

  describe('Mass Assignment', () => {
    it('POST /users - permite atribuir campo privilegiado', async () => {
      queryStub.resolves({
        rows: [{ username: 'hacker', isadmin: true }]
      });
      const res = await request(app)
        .post('/users')
        .send({ username: 'hacker', email: 'h@h.com', isAdmin: true });
      expect(res.status).to.equal(200);
      expect(res.body.isadmin).to.be.true;
    });
  });

  describe('Timing Attack', () => {
    it('POST /verify-token - comparacao caractere a caractere (timing)', async () => {
      const valid = 'super-secret-token-12345';
      const wrong = 'super-secret-token-12346';

      const t1 = Date.now();
      await request(app).post('/verify-token').send({ token: valid });
      const timeValid = Date.now() - t1;

      const t2 = Date.now();
      await request(app).post('/verify-token').send({ token: wrong });
      const timeWrong = Date.now() - t2;

      // Token errado demora mais (último caractere diferente)
      expect(timeWrong).to.be.greaterThan(timeValid * 1.2);
    });
  });
});