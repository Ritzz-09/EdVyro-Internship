const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');
const db = require('./db');
const { validateRegistrationInput, validateLoginInput } = require('./validation');
const { createAuthRateLimiter, defaultAuthLimiter } = require('./middleware/rateLimiter');

// Constant dummy hash used for non-existent user lookups to mitigate timing attacks
const DUMMY_HASH = '$2a$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ012345';
const BCRYPT_SALT_ROUNDS = 10;
const GENERIC_AUTH_ERROR = 'Invalid username or password.';

/**
 * Express application factory.
 * @param {Object} [options]
 * @param {Function} [options.rateLimiter] Custom rate limiter middleware
 * @param {Object} [options.sessionConfig] Custom session options
 * @returns {express.Application}
 */
function createApp(options = {}) {
  const app = express();

  // Trust first proxy for secure cookie handling when behind reverse proxies (e.g. Nginx, Cloudflare)
  app.set('trust proxy', 1);

  // Basic security headers
  app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    next();
  });

  // Parse JSON payloads (limit to 10kb to avoid payload flood DoS)
  app.use(express.json({ limit: '10kb' }));
  app.use(express.urlencoded({ extended: false, limit: '10kb' }));

  // Configure Secure Server-Side Sessions
  const isProduction = process.env.NODE_ENV === 'production';
  const sessionSecret = process.env.SESSION_SECRET || 'local-auth-lab-secret-key-do-not-use-in-prod';

  app.use(session({
    name: 'connect.sid',
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true, // Prevents client-side scripts from reading cookie (XSS mitigation)
      sameSite: 'lax', // Protects against Cross-Site Request Forgery (CSRF)
      secure: isProduction, // Set to true only in production (requires HTTPS); allows local HTTP testing
      maxAge: 15 * 60 * 1000 // 15-minute session expiration
    },
    ...options.sessionConfig
  }));

  // Serve static UI assets
  app.use(express.static(path.join(__dirname, '..', 'public')));

  // Use provided or default rate limiter
  const loginLimiter = options.rateLimiter !== undefined ? options.rateLimiter : defaultAuthLimiter;

  /**
   * Authentication Middleware
   * Verifies that the incoming request has a valid, active session.
   */
  function requireAuth(req, res, next) {
    if (!req.session || !req.session.userId) {
      return res.status(401).json({
        error: 'Authentication required. Please log in.'
      });
    }
    next();
  }

  // ==========================================
  // Public Routes
  // ==========================================

  /**
   * POST /api/register
   * Registers a new user with server-side validation and salted password hashing.
   */
  app.post('/api/register', async (req, res) => {
    try {
      // 1. Server-side input validation
      const validation = validateRegistrationInput(req.body);
      if (!validation.valid) {
        return res.status(400).json({ error: validation.error });
      }

      const { username, password } = req.body;
      const normalizedUsername = username.trim();

      // 2. Check for username collision
      const existingUser = db.findUserByUsername(normalizedUsername);
      if (existingUser) {
        return res.status(409).json({ error: 'Username is already taken.' });
      }

      // 3. Salt and hash password (never store plaintext)
      const passwordHash = await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);

      // 4. Persist to database
      const newUser = db.createUser({
        username: normalizedUsername,
        passwordHash
      });

      // 5. Return sanitized response (never return password or passwordHash)
      return res.status(201).json({
        message: 'User registered successfully.',
        user: {
          id: newUser.id,
          username: newUser.username,
          createdAt: newUser.createdAt
        }
      });
    } catch (err) {
      return res.status(500).json({ error: 'Internal server error during registration.' });
    }
  });

  /**
   * POST /api/login
   * Authenticates user, protected by rate limiting and generic error responses.
   */
  const loginMiddleware = loginLimiter ? [loginLimiter] : [];
  app.post('/api/login', ...loginMiddleware, async (req, res, next) => {
    try {
      // 1. Validate payload structure
      const validation = validateLoginInput(req.body);
      if (!validation.valid) {
        return res.status(400).json({ error: validation.error });
      }

      const { username, password } = req.body;
      const normalizedUsername = username.trim();

      // 2. Lookup user in database
      const user = db.findUserByUsername(normalizedUsername);

      // If user is not found, compare against dummy hash to mitigate timing attacks
      if (!user) {
        await bcrypt.compare(password, DUMMY_HASH);
        return res.status(401).json({ error: GENERIC_AUTH_ERROR });
      }

      // 3. Constant-time password verification
      const passwordMatch = await bcrypt.compare(password, user.passwordHash);
      if (!passwordMatch) {
        return res.status(401).json({ error: GENERIC_AUTH_ERROR });
      }

      // 4. Regenerate session to prevent session fixation attacks
      req.session.regenerate((err) => {
        if (err) {
          return next(err);
        }

        // Establish authenticated session state
        req.session.userId = user.id;
        req.session.username = user.username;

        // 5. Return safe user data
        return res.status(200).json({
          message: 'Login successful.',
          user: {
            id: user.id,
            username: user.username
          }
        });
      });
    } catch (err) {
      return res.status(500).json({ error: 'Internal server error during login.' });
    }
  });

  /**
   * POST /api/logout
   * Destroys current session and clears the session cookie.
   */
  app.post('/api/logout', (req, res) => {
    if (!req.session) {
      return res.status(200).json({ message: 'No active session.' });
    }

    req.session.destroy((err) => {
      if (err) {
        return res.status(500).json({ error: 'Failed to destroy session.' });
      }

      res.clearCookie('connect.sid', { path: '/' });
      return res.status(200).json({ message: 'Logout successful.' });
    });
  });

  /**
   * GET /api/session-status
   * Safe status check for current session state.
   */
  app.get('/api/session-status', (req, res) => {
    if (req.session && req.session.userId) {
      return res.status(200).json({
        authenticated: true,
        user: {
          id: req.session.userId,
          username: req.session.username
        }
      });
    }
    return res.status(200).json({ authenticated: false });
  });

  // ==========================================
  // Protected Routes
  // ==========================================

  /**
   * GET /api/profile
   * Protected route requiring authenticated session.
   */
  app.get('/api/profile', requireAuth, (req, res) => {
    const user = db.findUserById(req.session.userId);
    if (!user) {
      // Session exists but user was removed
      req.session.destroy(() => {});
      return res.status(401).json({ error: 'Authentication required. Please log in.' });
    }

    // Return safe user information (never return passwordHash)
    return res.status(200).json({
      message: 'Access granted to protected resource.',
      user: {
        id: user.id,
        username: user.username,
        createdAt: user.createdAt
      }
    });
  });

  // 404 handler for unknown API routes
  app.use('/api', (req, res) => {
    res.status(404).json({ error: 'API endpoint not found.' });
  });

  return app;
}

const defaultApp = createApp();

module.exports = {
  createApp,
  app: defaultApp
};
