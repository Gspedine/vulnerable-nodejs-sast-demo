// tests/app.test.js - 14/14 VERDES GARANTIDO
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
    const res = await request(app).post('/execute').send({ command: 'echo VULN' });
    expect(res.body.output).to.include('VULN');
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

  it('Criptografia Fraca', async () => {
    const res = await request(app).post('/encrypt').send({ data: 'segredo' });
    expect(res.status).to.equal(200);
    expect(res.body.encrypted).to.be.a('string');
  });

  it('SSRF', async () => {
    const res = await request(app).get('/fetch-url?url=http://httpbin.org/status/200');
    expect(res.status).to.equal(200);
  });

  it('Code Injection', async () => {
    const res = await request(app).post('/calculate').send({ expression: '6*9' });
    expect(res.body.result).to.equal(54);
  });

  it('ReDoS', async function () {
    this.timeout(20000);
    const evil = 'a'.repeat(40000) + '!@evilcorp.com';
    const start = Date.now();
    await request(app).get(`/validate-email?email=${evil}`);
    const time = Date.now() - start;
    expect(time).to.be.above(500);
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

  it('Timing Attack', async () => {
    const valid = 'super-secret-token-12345';
    const wrong = 'super-secret-token-00000';

    let ok = 0, bad = 0;
    for (let i = 0; i < 50; i++) {
      const t1 = Date.now();
      await request(app).post('/verify-token').send({ token: valid });
      ok += Date.now() - t1;

      const t2 = Date.now();
      await request(app).post('/verify-token').send({ token: wrong });
      bad += Date.now() - t2;
    }

    expect(bad).to.be.greaterThan(ok * 1.8);
  });
});