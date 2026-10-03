const rateLimit = require('express-rate-limit');

/**
 * Creates a rate limiter middleware for authentication routes.
 * 
 * Protects against brute-force password guessing and credential stuffing
 * by tracking attempts by client IP address and returning HTTP 429 when exceeded.
 * 
 * @param {Object} options Override default configuration
 * @returns {Function} Express middleware
 */
function createAuthRateLimiter(options = {}) {
  return rateLimit({
    windowMs: options.windowMs || 15 * 60 * 1000, // 15 minutes default
    max: options.max || 5, // Limit each IP to 5 requests per window
    standardHeaders: true, // Return standard `RateLimit-*` headers
    legacyHeaders: false, // Disable the `X-RateLimit-*` headers
    statusCode: 429,
    message: {
      error: 'Too many login attempts. Please try again later.'
    },
    // Allows custom handlers if passed
    ...options
  });
}

// Default export with production/default thresholds
const defaultAuthLimiter = createAuthRateLimiter();

module.exports = {
  createAuthRateLimiter,
  defaultAuthLimiter
};
