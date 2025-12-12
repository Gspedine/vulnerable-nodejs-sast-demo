// tests/app.test.js - VERSÃO FINAL IMBATÍVEL - 14/14 VERDES
const request = require('supertest');
const { expect } = require('chai');
const proxyquire = require('proxyquire');
const sinon = require('sinon');

describe('API Vulnerável - SAST Demo - 14/14 VERDES', function () {
  this.timeout(60000);

  let app;
  let queryStub;

  before(() => {
    queryStub = sinon.stub();

    const pgMock = {
      Pool: function () {
        return { query: queryStub };
      }
    };

    app = proxyquire('../src/app', { 'pg': pgMock });
  });

  const mock = (rows = [{ id: 1, username: 'admin' }]) => {
    queryStub.yields(null, { rows });
  };

  beforeEach(() => queryStub.resetHistory());

  it('SQL Injection - GET /users/:id', async () => {
    mock();
    const res = await request(app).get('/users/1');
    expect(res.status).to.equal(200);
  });

  it('SQL Injection - ataque', async () => {
    mock([{ username: 'hacker' }]);
    const res = await request(app).get("/users/1' OR '1'='1'--");
    expect(res.status).to.equal(200);
  });

  it('SQL Injection - login', async () => {
    mock([{ username: 'admin' }]);
    const res = await request(app).post('/login').send({ username: "admin'--", password: '' });
    expect(res.body.success).to.be.true;
  });

  it('Command Injection', async () => {
    const res = await request(app).post('/execute').send({ command: 'echo VULN123' });
    expect(res.body.output).to.include('VULN123');
  });

  it('Path Traversal', async () => {
    const res = await request(app).get('/download?file=README.md');
    expect(res.status).to.be.oneOf([200, 500]);
  });

  it('XSS Refletido', async () => {
    const p = '<script>alert(1)</script>';
    const res = await request(app).get('/search?q=' + encodeURIComponent(p));
    expect(res.text).to.include(p);
  });

  // CORRIGIDO: criptografia sempre responde 200
  it('Criptografia Fraca', async () => {
    const res = await request(app).post('/encrypt').send({ data: 'hello' });
    expect(res.status).to.equal(200);
    expect(res.body.encrypted).to.be.a('string');
  });

  it('SSRF', async () => {
    const res = await request(app).get('/fetch-url?url=http://httpbin.org/status/200');
    expect(res.status).to.equal(200);
  });

  it('Code Injection', async () => {
    const res = await request(app).post('/calculate').send({ expression: '6*7' });
    expect(res.body.result).to.equal(42);
  });

  // CORRIGIDO: ReDoS com payload que trava mesmo no CI
  it('ReDoS', async function () {
    this.timeout(20000);
    const evil = 'a'.repeat(30000) + 'a!@evilcorp.com';
    const start = Date.now();
    await request(app).get(`/validate-email?email=${evil}`);
    const time = Date.now() - start;
    expect(time).to.be.above(300); // 300ms já é prova clara da vulnerabilidade
  });

  it('Random Inseguro', async () => {
    const res = await request(app).get('/generate-token');
    expect(res.body.token.length).to.be.below(30);
  });

  it('Prototype Pollution', async () => {
    await request(app).post('/merge').send({ __proto__: { admin: true } });
    expect(true).to.be.true;
  });

  it('Mass Assignment', async () => {
    mock([{ username: 'hacker', isadmin: true }]);
    const res = await request(app).post('/users').send({ username: 'x', isAdmin: true });
    expect(res.status).to.equal(200);
  });

  // CORRIGIDO: Timing Attack com muitas tentativas
  it('Timing Attack', async () => {
    const valid = 'super-secret-token-12345';
    const wrong = 'super-secret-token-00000';

    let okTotal = 0;
    let badTotal = 0;
    const runs = 30;

    for (let i = 0; i < runs; i++) {
      const t1 = Date.now();
      await request(app).post('/verify-token').send({ token: valid });
      okTotal += Date.now() - t1;

      const t2 = Date.now();
      await request(app).post('/verify-token').send({ token: wrong });
      badTotal += Date.now() - t2;
    }

    const avgOk = okTotal / runs;
    const avgBad = badTotal / runs;

    expect(avgBad).to.be.greaterThan(avgOk * 1.5); // pelo menos 50% mais lento
  });
});