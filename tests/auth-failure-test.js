/**
 * Simulates repeated authentication failures
 * Triggers auth-failure-based abuse detection
 */

const TARGET_URL = 'http://localhost:3000/api/auth/login';

async function failedLogin(attempt) {
  const res = await fetch(TARGET_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: 'nonexistent_user',
      password: 'wrong_password'
    })
  });

  console.log(`Attempt ${attempt}: ${res.status}`);
  return res.status;
}

async function runAuthFailures() {
  console.log('Starting auth failure test');

  for (let i = 1; i <= 10; i++) {
    await failedLogin(i);
    await new Promise(r => setTimeout(r, 300)); // small delay
  }

  console.log('Auth failure test completed');
}

runAuthFailures();
