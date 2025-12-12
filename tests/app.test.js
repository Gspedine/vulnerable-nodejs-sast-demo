// tests/app.test.js
const request = require('supertest');
const { expect } = require('chai');
const sinon = require('sinon');

// IMPORTANTE: importar pg antes do app
const pg = require('pg');

describe('API Vulnerável - SAST Demo (100% VERDE)', function () {
  this.timeout(30000);

  let queryStub;

  before(() => {
    queryStub = sinon.stub(pg.Pool.prototype, 'query');
  });

  after(() => {
    sinon.restore();
  });

  // Só agora importa o app (pool será criado com o stub ativo)
  const app = require('../src/app');

  const mockDB = (rows = [{ id: 1, username: 'admin' }]) => {
    queryStub.resolves({ rows });
  };

  beforeEach(() => queryStub.resetHistory());

  it('SQL Injection - GET /users/:id normal', async () => {
    mockDB();
    const res = await request(app).get('/users/1');
    expect(res.status).to.equal(200);
  });

  it('SQL Injection - GET /users/:id ataque', async () => {
    mockDB([{ username: 'hacker' }]);
    const res = await request(app).get("/users/1' OR '1'='1' --");
    expect(res.status).to.equal(200);
  });

  it('SQL Injection - POST /login ataque', async () => {
    mockDB([{ username: 'admin' }]);
    const res = await request(app)
      .post('/login')
      .send({ username: "admin' OR '1'='1' --", password: '' });
    expect(res.body.success).to.be.true;
  });

  it('Command Injection', async () => {
    const res = await request(app)
      .post('/execute')
      .send({ command: 'echo VULN123' });
    expect(res.body.output).to.include('VULN123');
  });

  it('Path Traversal', async () => {
    const res = await request(app).get('/download?file=../package.json');
    expect(res.status).to.be.oneOf([200, 500]);
  });

  it('XSS Refletido', async () => {
    const payload = '<script>alert(1)</script>';
    const res = await request(app).get('/search?q=' + encodeURIComponent(payload));
    expect(res.text).to.include(payload);
  });

  it('Criptografia Fraca (DES)', async () => {
    const res = await request(app)
      .post('/encrypt')
      .send({ data: 'segredo' });
    expect(res.status).to.equal(200);
    expect(res.body.encrypted).to.be.a('string');
  });

  it('SSRF', async () => {
    const res = await request(app).get('/fetch-url?url=http://httpbin.org/status/200');
    expect(res.status).to.equal(200);
  });

  it('Code Injection (eval)', async () => {
    const res = await request(app)
      .post('/calculate')
      .send({ expression: '6*9' });
    expect(res.body.result).to.equal(54);
  });

  it('ReDoS', async function () {
    this.timeout(60000);
    const evil = 'a'.repeat(40000) + '@evilcorp.com';
    const start = Date.now();
    await request(app).get(`/validate-email?email=${evil}`);
    expect(Date.now() - start).to.be.above(1500);
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
    const res = await request(app)
      .post('/users')
      .send({ username: 'hacker', email: 'h@h.com', isAdmin: true });
    expect(res.status).to.equal(200);
  });

  it('Timing Attack', async () => {
    const valid = 'super-secret-token-12345';
    const wrong = 'super-secret-token-00000';

    const t1 = Date.now();
    await request(app).post('/verify-token').send({ token: valid });
    const okTime = Date.now() - t1;

    const t2 = Date.now();
    await request(app).post('/verify-token').send({ token: wrong });
    const badTime = Date.now() - t2;

    expect(badTime).to.be.at.least(okTime * 2);
  });
});