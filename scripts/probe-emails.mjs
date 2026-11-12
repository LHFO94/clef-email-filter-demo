import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const project = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const defaults = [
  'signup@example.com',
  'alice@example.com',
  'john.smith@example.org',
  'jane.doe+signup@example.net',
  'support@example.org',
  'bob@example.net',
  'register@example.com',
  '75hgf8b@example.org',
  'jane8smith@example.net',
  'a8f3c9d1e7b2@example.com',
  'user@invalid',
  'not-an-email',
];

function required(name) {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`Set ${name} in the environment.`);
  return value;
}

async function main() {
  const args = process.argv.slice(2);
  if (args.includes('--help') || args.includes('-h')) {
    console.log('Usage: npm run test:emails -- [email ...]');
    console.log('Without arguments, tests 12 sample addresses against the private diagnostic origin.');
    return;
  }
  const endpoint = new URL('/AccountV2/ConfirmEmail', required('DEMO_BASE_URL')).href;
  const emails = args.length ? args : defaults;
  const headers = {
    'CF-Access-Client-Id': required('CF_ACCESS_CLIENT_ID'),
    'CF-Access-Client-Secret': required('CF_ACCESS_CLIENT_SECRET'),
    'Content-Type': 'application/json',
  };
  console.log(`POST ${endpoint}\nSynthetic test origin only: no accounts or emails are created.\n`);
  const requests = [];
  for (const email of emails) {
    const started = performance.now();
    const entry = { email, http: null, ray: null, totalMs: null, error: null };
    const body = JSON.stringify({ email });
    try {
      const response = await fetch(endpoint, {
        method: 'POST', headers, body, redirect: 'manual', signal: AbortSignal.timeout(130_000),
      });
      entry.http = response.status;
      const ray = response.headers.get('cf-ray')?.split('-')[0];
      if (ray && /^[a-f0-9]+$/.test(ray)) entry.ray = ray;
      if (response.status !== 201) {
        entry.error = response.status === 302 || response.status === 403
          ? 'Access denied; check service credentials' : `HTTP ${response.status}`;
      } else {
        const origin = await response.json();
        const hash = createHash('sha256').update(body).digest('hex');
        if (response.headers.get('x-test-origin') !== 'clef-signup-test-origin' ||
            origin.request?.method !== 'POST' || origin.request?.path !== '/AccountV2/ConfirmEmail' ||
            origin.request?.bodySha256 !== hash) {
          entry.error = 'Origin request fidelity check failed';
        }
      }
    } catch (error) {
      entry.error = error.name === 'TimeoutError' ? 'Request timed out' : error.message;
    }
    entry.totalMs = Math.round(performance.now() - started);
    requests.push(entry);
  }

  const rays = [...new Set(requests.flatMap(item => item.ray ? [item.ray] : []))];
  let records = [];
  if (rays.length) {
    // Ray IDs above contain only hex characters; email input never enters SQL.
    const sql = `SELECT ray_id, status, verdict, confidence, probabilities_json, inference_ms, error_code
      FROM classifications WHERE ray_id IN (${rays.map(ray => `'${ray}'`).join(',')})`;
    try {
      const output = execFileSync(resolve(project, 'node_modules/.bin/wrangler'), [
        'd1', 'execute', 'clef-signup-classifications', '--remote', '--command', sql, '--json',
      ], { cwd: project, encoding: 'utf8', timeout: 60_000, env: { ...process.env, WRANGLER_SEND_METRICS: 'false' } });
      records = JSON.parse(output).flatMap(item => item.results ?? []);
    } catch {
      console.error('Could not read D1 results. Check Wrangler authentication for your configured account.');
      process.exitCode = 1;
    }
  }
  const byRay = new Map(records.map(record => [record.ray_id, record]));
  const percent = value => typeof value === 'number' ? `${(value * 100).toFixed(1)}%` : '-';
  console.table(requests.map(request => {
    const record = byRay.get(request.ray);
    const probabilities = record?.probabilities_json ? JSON.parse(record.probabilities_json) : {};
    const error = request.error || record?.error_code || (!record ? 'D1 record missing' :
      record.status === 'pending' ? 'Classification still pending' : null);
    if (request.error || !record || !['classified', 'skipped'].includes(record.status)) process.exitCode = 1;
    return {
      Email: request.email,
      HTTP: request.http ?? '-',
      Result: record?.verdict ?? record?.status ?? 'error',
      Confidence: percent(record?.confidence),
      'Legitimate %': percent(probabilities.likely_legitimate),
      'Suspicious %': percent(probabilities.suspicious),
      'Unknown %': percent(probabilities.insufficient_evidence),
      'AI ms': record?.inference_ms ?? '-',
      'Total ms': request.totalMs,
      Error: error ?? '',
    };
  }));
  console.log('Advisory model outputs, not verified fraud labels. Results appear in this terminal; no report file is written.');
}

main().catch(error => {
  console.error(error.message);
  process.exitCode = 1;
});
