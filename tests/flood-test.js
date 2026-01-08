/**
 * Rapid request generator
 * Simulates high request volume from a single client
 */

const TARGET_URL = 'http://localhost:3000/api/data';
const REQUESTS = 200;
const CONCURRENCY = 10;

async function sendRequest() {
  try {
    const res = await fetch(TARGET_URL);
    return res.status;
  } catch (err) {
    return 'ERR';
  }
}

async function runFlood() {
  console.log(`Starting flood test: ${REQUESTS} requests`);

  let completed = 0;

  const workers = Array.from({ length: CONCURRENCY }, async () => {
    while (completed < REQUESTS) {
      completed++;
      const status = await sendRequest();
      console.log(`Request ${completed}: ${status}`);
    }
  });

  await Promise.all(workers);
  console.log('Flood test completed');
}

runFlood();
