const { app } = require('./app');
const db = require('./db');

const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '127.0.0.1';

// Ensure the local database file is initialized
db.init();

app.listen(PORT, HOST, () => {
  console.log('====================================================');
  console.log('🛡️  Secure Authentication Lab (Task 02)');
  console.log('====================================================');
  console.log(`🌐 Server running locally at: http://${HOST}:${PORT}`);
  console.log(`🔒 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log('🛡️  Active Defenses:');
  console.log('   - Salted Bcrypt Password Hashing (Work Factor 10)');
  console.log('   - Server-Side Regex & Length Input Validation');
  console.log('   - HttpOnly + SameSite=Lax Session Cookies');
  console.log('   - Generic Authentication Failure Messages');
  console.log('   - Sliding Rate Limiting on /api/login');
  console.log('====================================================');
});
