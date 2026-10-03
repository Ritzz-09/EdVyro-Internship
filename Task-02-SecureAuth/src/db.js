const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Default database storage path
let dbFilePath = path.join(__dirname, '..', 'data', 'users.json');

/**
 * Ensures the database directory and file exist.
 */
function init(customPath) {
  if (customPath) {
    dbFilePath = customPath;
  }
  const dir = path.dirname(dbFilePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  if (!fs.existsSync(dbFilePath)) {
    fs.writeFileSync(dbFilePath, JSON.stringify([], null, 2), 'utf8');
  }
}

/**
 * Reads all user records from the local storage.
 * @returns {Array<Object>}
 */
function getAllUsers() {
  init();
  try {
    const raw = fs.readFileSync(dbFilePath, 'utf8');
    return JSON.parse(raw || '[]');
  } catch (err) {
    return [];
  }
}

/**
 * Finds a user by their username (case-insensitive comparison).
 * @param {string} username
 * @returns {Object|null}
 */
function findUserByUsername(username) {
  if (!username || typeof username !== 'string') return null;
  const users = getAllUsers();
  const target = username.trim().toLowerCase();
  return users.find(u => u.username.toLowerCase() === target) || null;
}

/**
 * Finds a user by their unique ID.
 * @param {string} id
 * @returns {Object|null}
 */
function findUserById(id) {
  if (!id || typeof id !== 'string') return null;
  const users = getAllUsers();
  return users.find(u => u.id === id) || null;
}

/**
 * Creates and persists a new user record.
 * @param {Object} params
 * @param {string} params.username
 * @param {string} params.passwordHash
 * @returns {Object} Newly created user (with passwordHash intact for DB storage)
 */
function createUser({ username, passwordHash }) {
  init();
  const users = getAllUsers();
  const newUser = {
    id: crypto.randomUUID(),
    username: username.trim(),
    passwordHash,
    createdAt: new Date().toISOString()
  };

  users.push(newUser);

  // Write atomically using temporary file to avoid corruption
  const tempPath = `${dbFilePath}.${Date.now()}.tmp`;
  fs.writeFileSync(tempPath, JSON.stringify(users, null, 2), 'utf8');
  fs.renameSync(tempPath, dbFilePath);

  return newUser;
}

/**
 * Resets the database to empty (primarily used for test suite isolation).
 */
function reset() {
  init();
  fs.writeFileSync(dbFilePath, JSON.stringify([], null, 2), 'utf8');
}

/**
 * Overrides the storage path (useful for testing).
 * @param {string} newPath
 */
function setStoragePath(newPath) {
  dbFilePath = newPath;
  init();
}

module.exports = {
  init,
  getAllUsers,
  findUserByUsername,
  findUserById,
  createUser,
  reset,
  setStoragePath
};
