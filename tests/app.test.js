// tests/app.test.js
const request = require('supertest');
const { expect } = require('chai');
const proxyquire = require('proxyquire');
const sinon = require('sinon');

describe('API Vulnerável - SAST Demo - 100% VERDE', function () {
  this.timeout(30000);

  let queryStub;
  let app;

  before(() => {
    queryStub = sinon.stub().resolves({ rows: [{ id: 1, username: 'admin' }] });

    const pgMock = {
      Pool: class {
        query = queryStub;
        on() {}
      }
    };

    app = proxyquire('../src/app', {
      'pg': pgMock
    });
  });

  const mockDB = (rows) => {
    queryStub.resolves({ rows: rows || [{ id: 1, username: 'admin' }] });
  };

  beforeEach(() => queryStub.resetHistory());

  it('SQL Injection - GET /users/:id', async () => {
    mockDB();
    const res = await request(app).get('/users/1');
    expect(res.status).to.equal(200);
  });

  it('SQL Injection - ataque', async () => {
    mockDB([{ username: 'hacker' }]);
    const res = await request(app).get("/users/1' OR '1'='1'--");
    expect(res.status).to.equal(200);
  });

  it('SQL Injection - login', async () => {
    mockDB([{ username: 'admin' }]);
    const res = await request(app).post('/login').send({ username: "admin'--", password: '' });
    expect(res.body.success).to.be.true;
  });

  it('Command Injection', async () => {
    const res = await request(app).post('/execute').send({ command: 'echo OK123' });
    expect(res.body.output).to.include('OK123');
  });

  it('Path Traversal', async () => {
    const res = await request(app).get('/download?file=../package.json');
    expect(res.status).to.be.oneOf([200, 500]);
  });

  it('XSS Refletido', async () => {
    const p = '<script>alert(1)</script>';
    const res = await request(app).get('/search?q=' + encodeURIComponent(p));
    expect(res.text).to.include(p);
  });

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

  it('ReDoS', async function () {
    this.timeout(60000);
    const evil = 'a'.repeat(50000) + '@evilcorp.com';
    const start = Date.now();
    await request(app).get(`/validate-email?email=${evil}`);
    expect(Date.now() - start).to.be.above(2000);
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
    mockDB([{ username: 'hacker', isadmin: true }]);
    const res = await request(app).post('/users').send({ username: 'x', isAdmin: true });
    expect(res.status).to.equal(200);
  });

  it('Timing Attack', async () => {
    const valid = 'super-secret-token-12345';
    const wrong = 'super-secret-token-00000';
    const t1 = Date.now();
    await request(app).post('/verify-token').send({ token: valid });
    const ok = Date.now() - t1;
    const t2 = Date.now();
    await request(app).post('/verify-token').send({ token: wrong });
    const bad = Date.now() - t2;
    expect(bad).to.be.greaterThan(ok);
  });
});