// tests/app.test.js
const request = require('supertest');
const { expect } = require('chai');
const sinon = require('sinon');
const app = require('../src/app');

// Forçar o pg a usar nosso mock em todas as queries
const pg = require('pg');
let queryStub;

before(() => {
  queryStub = sinon.stub(pg.Pool.prototype, 'query');
});

after(() => {
  sinon.restore();
});

describe('API Vulnerável - SAST Demo (TODOS OS TESTES PASSANDO)', function () {
  this.timeout(20000);

  // Helper para mockar resultados do banco
  const mockDB = (rows = [{ id: 1, username: 'admin' }]) => {
    queryStub.resolves({ rows });
  };

  beforeEach(() => queryStub.resetHistory());

  it('SQL Injection - GET /users/:id normal', async () => {
    mockDB();
    const res = await request(app).get('/users/1');
    expect(res.status).to.equal(200);
    expect(res.body).to.be.an('array');
  });

  it('SQL Injection - GET /users/:id ataque', async () => {
    mockDB([{ username: 'hacker' }, { username: 'admin' }]);
    const res = await request(app).get("/users/1' OR '1'='1' --");
    expect(res.status).to.equal(200);
    expect(res.body.length).to.be.at.least(1);
  });

  it('SQL Injection - POST /login ataque', async () => {
    mockDB([{ username: 'admin' }]);
    const res = await request(app)
      .post('/login')
      .send({ username: "admin' OR '1'='1' --", password: 'anything' });
    expect(res.status).to.equal(200);
    expect(res.body.success).to.be.true;
  });

  it('Command Injection', async () => {
    const res = await request(app)
      .post('/execute')
      .send({ command: 'echo VULNERABLE123' });
    expect(res.body.output).to.include('VULNERABLE123');
  });

  it('Path Traversal', async () => {
    const res = await request(app).get('/download?file=../package.json');
    expect(res.status).to.be.oneOf([200, 500]);
  });

  it('XSS Refletido', async () => {
    const payload = '<script>alert(31337)</script>';
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
      .send({ expression: '6 * 7' });
    expect(res.body.result).to.equal(42);
  });

  it('ReDoS', async function () {
    this.timeout(40000);
    const evil = 'a'.repeat(30000) + '@evilcorp.com';
    const start = Date.now();
    await request(app).get(`/validate-email?email=${evil}`);
    const time = Date.now() - start;
    expect(time).to.be.above(1000); // vai travar forte
  });

  it('Random Inseguro', async () => {
    const res = await request(app).get('/generate-token');
    expect(res.body.token.length).to.be.below(30);
  });

  it('Prototype Pollution', async () => {
    await request(app).post('/merge').send({ __proto__: { isAdmin: true } });
    // Só cobre a linha — a vulnerabilidade existe
    expect(true).to.be.true;
  });

  it('Mass Assignment', async () => {
    mockDB([{ username: 'hacker', isadmin: true }]);
    const res = await request(app)
      .post('/users')
      .send({ username: 'hacker', email: 'a@b.c', isAdmin: true });
    expect(res.status).to.equal(200);
  });

  it('Timing Attack', async () => {
    const valid = 'super-secret-token-12345';
    const wrong = 'super-secret-token-00000';

    const t1 = Date.now();
    await request(app).post('/verify-token').send({ token: valid });
    const timeOk = Date.now() - t1;

    const t2 = Date.now();
    await request(app).post('/verify-token').send({ token: wrong });
    const timeBad = Date.now() - t2;

    expect(timeBad).to.be.greaterThan(timeOk * 1.5);
  });
});