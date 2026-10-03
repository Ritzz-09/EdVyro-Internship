const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const path = require('path');
const fs = require('fs');

const { createApp } = require('../src/app');
const db = require('../src/db');
const { createAuthRateLimiter } = require('../src/middleware/rateLimiter');

// Test database file path
const TEST_DB_PATH = path.join(__dirname, 'test_users.json');

describe('Task 02: Secure Authentication Lab Test Suite', () => {
  let app;

  beforeEach(() => {
    // Isolate test database
    db.setStoragePath(TEST_DB_PATH);
    db.reset();

    // Use test-specific app instance with clean state and rate limiter disabled by default for functional tests
    app = createApp({
      rateLimiter: null,
      sessionConfig: {
        secret: 'test-secret-key-1234567890'
      }
    });
  });

  afterEach(() => {
    // Cleanup temporary test database file
    if (fs.existsSync(TEST_DB_PATH)) {
      try {
        fs.unlinkSync(TEST_DB_PATH);
      } catch (err) {}
    }
  });

  // ==========================================
  // 1. Password Storage & Registration
  // ==========================================
  describe('User Registration & Safe Password Storage', () => {
    it('successfully registers a new user with valid credentials', async () => {
      const res = await request(app)
        .post('/api/register')
        .send({ username: 'alice_guard', password: 'ValidPassword123!' });

      assert.equal(res.status, 201);
      assert.equal(res.body.message, 'User registered successfully.');
      assert.equal(res.body.user.username, 'alice_guard');
      assert.ok(res.body.user.id);
      assert.ok(res.body.user.createdAt);

      // Verify password and hash are NEVER returned in API response
      assert.equal(res.body.user.password, undefined);
      assert.equal(res.body.user.passwordHash, undefined);
    });

    it('stores passwords strictly as strong bcrypt hashes (never plaintext)', async () => {
      const plainPassword = 'SuperSecretPassword99!';
      await request(app)
        .post('/api/register')
        .send({ username: 'bob_crypto', password: plainPassword });

      const users = db.getAllUsers();
      const bob = users.find(u => u.username === 'bob_crypto');

      assert.ok(bob, 'User should exist in database');
      assert.notEqual(bob.passwordHash, plainPassword, 'Password must NOT be plaintext');
      // Bcrypt hash regex: $2a$ or $2b$ followed by work factor and 53-character salt/hash
      const bcryptRegex = /^\$2[ab]\$\d{2}\$[./A-Za-z0-9]{53}$/;
      assert.match(bob.passwordHash, bcryptRegex, 'Stored password must be a valid bcrypt hash');
    });

    it('rejects registration when username already exists', async () => {
      await request(app)
        .post('/api/register')
        .send({ username: 'charlie_dup', password: 'ValidPassword123!' });

      const res = await request(app)
        .post('/api/register')
        .send({ username: 'charlie_dup', password: 'DifferentPassword456!' });

      assert.equal(res.status, 409);
      assert.equal(res.body.error, 'Username is already taken.');
    });
  });

  // ==========================================
  // 2. Server-Side Input Validation
  // ==========================================
  describe('Server-Side Input Validation', () => {
    it('rejects registration when username or password are missing', async () => {
      const res1 = await request(app)
        .post('/api/register')
        .send({ password: 'ValidPassword123!' });
      assert.equal(res1.status, 400);
      assert.match(res1.body.error, /Username and password are required/);

      const res2 = await request(app)
        .post('/api/register')
        .send({ username: 'no_pass' });
      assert.equal(res2.status, 400);
      assert.match(res2.body.error, /Username and password are required/);
    });

    it('rejects registration when fields are of non-string types', async () => {
      const res = await request(app)
        .post('/api/register')
        .send({ username: 12345, password: { secret: 'evil' } });

      assert.equal(res.status, 400);
      assert.match(res.body.error, /must be strings/);
    });

    it('rejects username shorter than 3 characters or longer than 30 characters', async () => {
      const resShort = await request(app)
        .post('/api/register')
        .send({ username: 'ab', password: 'ValidPassword123!' });
      assert.equal(resShort.status, 400);
      assert.match(resShort.body.error, /Username must be between 3 and 30 characters/);

      const resLong = await request(app)
        .post('/api/register')
        .send({ username: 'a'.repeat(31), password: 'ValidPassword123!' });
      assert.equal(resLong.status, 400);
      assert.match(resLong.body.error, /Username must be between 3 and 30 characters/);
    });

    it('rejects username containing non-whitelisted characters (XSS/injection defense)', async () => {
      const res = await request(app)
        .post('/api/register')
        .send({ username: '<script>alert(1)</script>', password: 'ValidPassword123!' });

      assert.equal(res.status, 400);
      assert.match(res.body.error, /can only contain alphanumeric characters and underscores/);
    });

    it('rejects password shorter than 8 characters', async () => {
      const res = await request(app)
        .post('/api/register')
        .send({ username: 'short_pass_user', password: '123' });

      assert.equal(res.status, 400);
      assert.match(res.body.error, /Password must be at least 8 characters long/);
    });

    it('rejects password exceeding 128 characters (Bcrypt CPU DoS prevention)', async () => {
      const hugePassword = 'A'.repeat(129);
      const res = await request(app)
        .post('/api/register')
        .send({ username: 'dos_target', password: hugePassword });

      assert.equal(res.status, 400);
      assert.match(res.body.error, /Password cannot exceed 128 characters/);
    });

    it('rejects malformed or empty login requests', async () => {
      const res = await request(app)
        .post('/api/login')
        .send({});

      assert.equal(res.status, 400);
      assert.match(res.body.error, /Username and password are required/);
    });
  });

  // ==========================================
  // 3. User Login & Generic Auth Errors
  // ==========================================
  describe('Login & Generic Authentication Errors', () => {
    beforeEach(async () => {
      await request(app)
        .post('/api/register')
        .send({ username: 'valid_user', password: 'CorrectPassword123!' });
    });

    it('successfully logs in with valid credentials and sets session cookie', async () => {
      const res = await request(app)
        .post('/api/login')
        .send({ username: 'valid_user', password: 'CorrectPassword123!' });

      assert.equal(res.status, 200);
      assert.equal(res.body.message, 'Login successful.');
      assert.equal(res.body.user.username, 'valid_user');
      assert.ok(res.body.user.id);
      assert.equal(res.body.user.password, undefined);
      assert.equal(res.body.user.passwordHash, undefined);

      // Verify Set-Cookie header is returned
      const cookies = res.headers['set-cookie'];
      assert.ok(cookies, 'Login must issue Set-Cookie header');
      const cookieStr = cookies.join('; ');
      assert.match(cookieStr, /connect\.sid=/);
    });

    it('returns generic error "Invalid username or password." for incorrect password', async () => {
      const res = await request(app)
        .post('/api/login')
        .send({ username: 'valid_user', password: 'WrongPassword999!' });

      assert.equal(res.status, 401);
      assert.equal(res.body.error, 'Invalid username or password.');
    });

    it('returns identical generic error for non-existent username (prevents user enumeration)', async () => {
      const res = await request(app)
        .post('/api/login')
        .send({ username: 'non_existent_user', password: 'AnyPassword123!' });

      assert.equal(res.status, 401);
      assert.equal(res.body.error, 'Invalid username or password.');
    });
  });

  // ==========================================
  // 4. Secure Session & Cookie Configuration
  // ==========================================
  describe('Session Security & Cookie Flags', () => {
    beforeEach(async () => {
      await request(app)
        .post('/api/register')
        .send({ username: 'cookie_tester', password: 'SafePassword123!' });
    });

    it('sets HttpOnly, SameSite=Lax, and session expiration on session cookie', async () => {
      const res = await request(app)
        .post('/api/login')
        .send({ username: 'cookie_tester', password: 'SafePassword123!' });

      const setCookie = res.headers['set-cookie'][0];
      assert.ok(setCookie.includes('HttpOnly'), 'Cookie must have HttpOnly flag');
      assert.ok(setCookie.includes('SameSite=Lax'), 'Cookie must have SameSite=Lax flag');
      const hasExpiration = setCookie.includes('Expires=') || setCookie.includes('Max-Age=');
      assert.ok(hasExpiration, 'Cookie must have expiration timestamp');
    });

    it('applies Secure flag over HTTPS / trusted reverse proxy in production', async () => {
      const prodApp = createApp({
        rateLimiter: null,
        sessionConfig: {
          secret: 'test-prod-secret',
          cookie: {
            secure: true,
            httpOnly: true,
            sameSite: 'lax',
            maxAge: 15 * 60 * 1000
          }
        }
      });

      const res = await request(prodApp)
        .post('/api/login')
        .set('X-Forwarded-Proto', 'https')
        .send({ username: 'cookie_tester', password: 'SafePassword123!' });

      assert.equal(res.status, 200);
      const cookies = res.headers['set-cookie'];
      assert.ok(cookies && cookies.length > 0, 'Set-Cookie should be returned');
      assert.ok(cookies[0].includes('Secure'), 'Cookie must have Secure flag');
      assert.ok(cookies[0].includes('HttpOnly'), 'Cookie must have HttpOnly flag');
    });
  });

  // ==========================================
  // 5. Protected Routes & Authentication Enforcement
  // ==========================================
  describe('Protected Route Access & Access Control', () => {
    let authCookie;

    beforeEach(async () => {
      await request(app)
        .post('/api/register')
        .send({ username: 'protected_user', password: 'MyPassword123!' });

      const loginRes = await request(app)
        .post('/api/login')
        .send({ username: 'protected_user', password: 'MyPassword123!' });

      authCookie = loginRes.headers['set-cookie'];
    });

    it('grants access to protected route with valid session cookie', async () => {
      const res = await request(app)
        .get('/api/profile')
        .set('Cookie', authCookie);

      assert.equal(res.status, 200);
      assert.equal(res.body.message, 'Access granted to protected resource.');
      assert.equal(res.body.user.username, 'protected_user');
      assert.equal(res.body.user.passwordHash, undefined);
    });

    it('denies access to protected route when unauthenticated (no cookie)', async () => {
      const res = await request(app)
        .get('/api/profile');

      assert.equal(res.status, 401);
      assert.match(res.body.error, /Authentication required/);
    });

    it('denies access with forged or invalid session cookie', async () => {
      const res = await request(app)
        .get('/api/profile')
        .set('Cookie', 'connect.sid=s%3Aforged_invalid_session_id.abcdef');

      assert.equal(res.status, 401);
      assert.match(res.body.error, /Authentication required/);
    });
  });

  // ==========================================
  // 6. Logout & Session Expiry / Invalidation
  // ==========================================
  describe('Logout & Session Expiration', () => {
    let authCookie;

    beforeEach(async () => {
      await request(app)
        .post('/api/register')
        .send({ username: 'logout_user', password: 'MyPassword123!' });

      const loginRes = await request(app)
        .post('/api/login')
        .send({ username: 'logout_user', password: 'MyPassword123!' });

      authCookie = loginRes.headers['set-cookie'];
    });

    it('invalidates server-side session and clears cookie upon logout', async () => {
      // 1. Verify access works initially
      const beforeRes = await request(app)
        .get('/api/profile')
        .set('Cookie', authCookie);
      assert.equal(beforeRes.status, 200);

      // 2. Perform logout
      const logoutRes = await request(app)
        .post('/api/logout')
        .set('Cookie', authCookie);

      assert.equal(logoutRes.status, 200);
      assert.equal(logoutRes.body.message, 'Logout successful.');

      // 3. Attempt to access protected route with the old cookie
      const afterRes = await request(app)
        .get('/api/profile')
        .set('Cookie', authCookie);

      assert.equal(afterRes.status, 401, 'Old session must be rejected after logout');
      assert.match(afterRes.body.error, /Authentication required/);
    });

    it('rejects access after session expiration TTL', async () => {
      // App with 50ms session expiration TTL
      const expiringApp = createApp({
        rateLimiter: null,
        sessionConfig: {
          secret: 'test-expiry-secret',
          cookie: { maxAge: 50 }
        }
      });

      const loginRes = await request(expiringApp)
        .post('/api/login')
        .send({ username: 'logout_user', password: 'MyPassword123!' });

      assert.equal(loginRes.status, 200);
      const expiringCookie = loginRes.headers['set-cookie'];

      // Wait 100ms for session TTL to expire
      await new Promise(resolve => setTimeout(resolve, 100));

      const resAfterExpiry = await request(expiringApp)
        .get('/api/profile')
        .set('Cookie', expiringCookie);

      assert.equal(resAfterExpiry.status, 401, 'Expired session must return HTTP 401');
      assert.match(resAfterExpiry.body.error, /Authentication required/);
    });
  });

  // ==========================================
  // 7. Rate Limiting on Authentication Endpoints
  // ==========================================
  describe('Authentication Rate Limiting', () => {
    it('triggers HTTP 429 after exceeding failed login rate limit', async () => {
      // Create dedicated app with a test rate limiter (max 3 requests)
      const testLimiter = createAuthRateLimiter({
        windowMs: 60 * 1000,
        max: 3,
        message: { error: 'Too many login attempts. Please try again later.' }
      });

      const rateLimitedApp = createApp({
        rateLimiter: testLimiter
      });

      // Attempt 1: Failed login
      const res1 = await request(rateLimitedApp)
        .post('/api/login')
        .send({ username: 'target_account', password: 'BadPassword1' });
      assert.equal(res1.status, 401);

      // Attempt 2: Failed login
      const res2 = await request(rateLimitedApp)
        .post('/api/login')
        .send({ username: 'target_account', password: 'BadPassword2' });
      assert.equal(res2.status, 401);

      // Attempt 3: Failed login
      const res3 = await request(rateLimitedApp)
        .post('/api/login')
        .send({ username: 'target_account', password: 'BadPassword3' });
      assert.equal(res3.status, 401);

      // Attempt 4: Should trigger HTTP 429 Rate Limit
      const res4 = await request(rateLimitedApp)
        .post('/api/login')
        .send({ username: 'target_account', password: 'BadPassword4' });

      assert.equal(res4.status, 429, 'Expected HTTP 429 Too Many Requests');
      assert.equal(res4.body.error, 'Too many login attempts. Please try again later.');
      assert.ok(res4.headers['ratelimit-limit'], 'Should include standard RateLimit-Limit header');
    });
  });
});
