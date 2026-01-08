const http = require('http');

const TARGET = {
  hostname: 'localhost',
  port: 3000,
};

function sendRequest(path, method = 'GET', body = null) {
  return new Promise((resolve) => {
    const options = {
      ...TARGET,
      path,
      method,
      headers: {
        'Content-Type': 'application/json',
      },
    };

    const req = http.request(options, (res) => {
      res.on('data', () => {});
      res.on('end', () => {
        resolve(res.statusCode);
      });
    });

    req.on('error', () => resolve(null));

    if (body) {
      req.write(JSON.stringify(body));
    }

    req.end();
  });
}

async function floodEndpoint(path, count) {
  console.log(`\n[TEST] Flooding ${path} (${count} requests)`);
  for (let i = 0; i < count; i++) {
    const status = await sendRequest(path);
    console.log(`Request ${i + 1}: ${status}`);
  }
}

async function authFailures(count) {
  console.log(`\n[TEST] Triggering auth failures (${count} attempts)`);
  for (let i = 0; i < count; i++) {
    const status = await sendRequest(
      '/api/auth/login',
      'POST',
      { username: 'attacker', password: 'wrong' }
    );
    console.log(`Login attempt ${i + 1}: ${status}`);
  }
}

async function scanSensitivePaths() {
  const paths = ['/admin', '/api/users', '/api/auth', '/admin/login'];
  console.log('\n[TEST] Scanning sensitive paths');
  for (const path of paths) {
    const status = await sendRequest(path);
    console.log(`Scan ${path}: ${status}`);
  }
}

async function run() {
  console.log('=== Abuse Engine Test Started ===');

  await floodEndpoint('/api/data', 30);
  await authFailures(8);
  await scanSensitivePaths();
  await floodEndpoint('/api/data', 50);

  console.log('\n=== Test Completed ===');
}

run();
