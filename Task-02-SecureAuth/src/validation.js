/**
 * Server-Side Input Validation Module
 * 
 * Enforces strict input validation on the server before processing credentials.
 * Client-side validation can be bypassed, so server-side validation is mandatory
 * to protect against injection, malformed payloads, and Denial of Service (DoS).
 */

const USERNAME_REGEX = /^[a-zA-Z0-9_]+$/;
const MIN_USERNAME_LENGTH = 3;
const MAX_USERNAME_LENGTH = 30;
const MIN_PASSWORD_LENGTH = 8;
const MAX_PASSWORD_LENGTH = 128; // Prevents bcrypt CPU-exhaustion DoS attacks

/**
 * Validates registration input payload.
 * @param {any} body 
 * @returns {{ valid: boolean, error?: string }}
 */
function validateRegistrationInput(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return { valid: false, error: 'Request body must be a valid JSON object.' };
  }

  const { username, password } = body;

  // Required field checks
  if (username === undefined || username === null || password === undefined || password === null) {
    return { valid: false, error: 'Username and password are required.' };
  }

  // Type checks
  if (typeof username !== 'string' || typeof password !== 'string') {
    return { valid: false, error: 'Username and password must be strings.' };
  }

  const trimmedUsername = username.trim();

  // Username length checks
  if (trimmedUsername.length < MIN_USERNAME_LENGTH || trimmedUsername.length > MAX_USERNAME_LENGTH) {
    return {
      valid: false,
      error: `Username must be between ${MIN_USERNAME_LENGTH} and ${MAX_USERNAME_LENGTH} characters.`
    };
  }

  // Username character whitelist check (alphanumeric and underscore)
  if (!USERNAME_REGEX.test(trimmedUsername)) {
    return {
      valid: false,
      error: 'Username can only contain alphanumeric characters and underscores.'
    };
  }

  // Password length checks
  if (password.length < MIN_PASSWORD_LENGTH) {
    return {
      valid: false,
      error: `Password must be at least ${MIN_PASSWORD_LENGTH} characters long.`
    };
  }

  if (password.length > MAX_PASSWORD_LENGTH) {
    return {
      valid: false,
      error: `Password cannot exceed ${MAX_PASSWORD_LENGTH} characters.`
    };
  }

  return { valid: true };
}

/**
 * Validates login input structure and types.
 * @param {any} body 
 * @returns {{ valid: boolean, error?: string }}
 */
function validateLoginInput(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return { valid: false, error: 'Request body must be a valid JSON object.' };
  }

  const { username, password } = body;

  if (username === undefined || username === null || password === undefined || password === null) {
    return { valid: false, error: 'Username and password are required.' };
  }

  if (typeof username !== 'string' || typeof password !== 'string') {
    return { valid: false, error: 'Username and password must be strings.' };
  }

  const trimmedUsername = username.trim();
  if (trimmedUsername.length === 0 || password.length === 0) {
    return { valid: false, error: 'Username and password cannot be empty.' };
  }

  // Guard against massive payload DoS attempts on login
  if (trimmedUsername.length > MAX_USERNAME_LENGTH || password.length > MAX_PASSWORD_LENGTH) {
    return { valid: false, error: 'Input exceeds allowable length limits.' };
  }

  return { valid: true };
}

module.exports = {
  validateRegistrationInput,
  validateLoginInput,
  MIN_USERNAME_LENGTH,
  MAX_USERNAME_LENGTH,
  MIN_PASSWORD_LENGTH,
  MAX_PASSWORD_LENGTH
};
