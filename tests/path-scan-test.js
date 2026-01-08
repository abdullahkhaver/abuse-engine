/**
 * Simulates scanning sensitive paths
 */

const BASE_URL = 'http://localhost:3000';
const PATHS = [
  '/admin',
  '/admin/login',
  '/api/users',
  '/api/users/1',
  '/api/auth',
  '/api/auth/reset'
];

async function scanPaths() {
  console.log('Starting sensitive path scan');

  for (const path of PATHS) {
    const res = await fetch(BASE_URL + path);
    console.log(`${path}: ${res.status}`);
    await new Promise(r => setTimeout(r, 200));
  }

  console.log('Path scan completed');
}

scanPaths();
