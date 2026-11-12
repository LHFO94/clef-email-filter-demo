import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const project = resolve(dirname(fileURLToPath(import.meta.url)), '..');
function required(name) {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`Set ${name} in the environment.`);
  return value;
}
const base = new URL(required('DEMO_BASE_URL')).origin;
const accessTeamDomain = required('ACCESS_TEAM_DOMAIN');
const accessHeaders = {
  'CF-Access-Client-Id': required('CF_ACCESS_CLIENT_ID'),
  'CF-Access-Client-Secret': required('CF_ACCESS_CLIENT_SECRET'),
};
const cases = [
  { path: '/signup', method: 'POST', type: 'application/json', body: '{"email":"signup@example.com","password":"synthetic-secret"}', expected: 'classified' },
  { path: '/register', method: 'POST', type: 'application/x-www-form-urlencoded', body: 'email=register%40example.org&password=synthetic-secret', expected: 'classified' },
  { path: '/AccountV2/ConfirmEmail', method: 'POST', type: 'application/json', body: '{"account":{"email":"confirm@example.net"},"password":"synthetic-secret"}', expected: 'classified' },
  { path: '/probe', method: 'PUT', type: 'text/javascript', body: '{"email":"probe@example.com"}', expected: 'classified' },
  { path: '/signup', method: 'POST', type: 'application/json', body: '{"email":', expected: 'skipped', reason: 'invalid_json' },
  { path: '/signup', method: 'POST', type: 'application/json', body: '{"email":"user@invalid"}', expected: 'skipped', reason: 'email_not_found' },
  { path: '/register', method: 'POST', type: 'text/plain', body: 'alice@example.com', expected: 'skipped', reason: 'unsupported_content_type' },
  { path: '/signup', method: 'POST', type: 'application/json', body: 'x'.repeat(16385), expected: 'rejected' },
];
const startedAt = new Date().toISOString();
const marker = randomUUID();
const requests = [];
for (const [index, item] of cases.entries()) {
  const started = performance.now();
  const response = await fetch(`${base}${item.path}?smoke=${marker}-${index}`, {
    method: item.method,
    headers: {
      ...accessHeaders,
      'Content-Type': item.type,
      'X-Proxy-Smoke': marker,
      Authorization: 'Bearer synthetic-proxy-test',
      Cookie: 'session=synthetic-proxy-test',
      'X-Clef-Status': 'classified',
      'X-Clef-Verdict': 'client-supplied',
      'X-Clef-Confidence': '1',
      'X-Clef-Request-Id': 'client-supplied',
    },
    body: item.body,
    redirect: 'manual',
    signal: AbortSignal.timeout(30_000),
  });
  const elapsedMs = Math.round(performance.now() - started);
  const body = await response.json();
  assert.equal(response.status, item.expected === 'rejected' ? 413 : 201, `${item.path}: unexpected HTTP status`);
  if (item.expected !== 'rejected') {
    assert.equal(response.headers.get('x-test-origin'), 'clef-signup-test-origin');
    assert.equal(body.request.bodySha256, createHash('sha256').update(item.body).digest('hex'));
    assert.equal(body.request.method, item.method);
    assert.equal(body.request.query, `?smoke=${marker}-${index}`);
    assert.equal(body.request.contentType, item.type);
    assert.equal(body.request.probeHeader, marker);
    assert.equal(body.request.authorizationPresent, true);
    assert.equal(body.request.cookiePresent, true);
  }
  const rayId = response.headers.get('cf-ray').split('-')[0];
  assert.match(rayId, /^[a-f0-9]+$/);
  requests.push({ path: item.path, expected: item.expected, reason: item.reason, status: response.status, rayId, elapsedMs,
    receivedClef: item.expected === 'rejected' ? null : body.clef });
}
const anonymous = await fetch(`${base}/signup`, {
  method: 'POST', headers: { 'Content-Type': 'application/json' },
  body: '{"email":"anonymous@example.com"}', redirect: 'manual',
});
assert.equal(anonymous.status, 302);
assert.equal(new URL(anonymous.headers.get('location')).hostname, accessTeamDomain);
console.table(requests.map(({ path, status, elapsedMs, rayId }) => ({ path, status, elapsedMs, rayId })));

const rays = requests.map(r => `'${r.rayId}'`).join(',');
const sql = `SELECT * FROM classifications WHERE ray_id IN (${rays}) ORDER BY created_at`;
const wrangler = resolve(project, 'node_modules/.bin/wrangler');
const output = execFileSync(wrangler, [
  'd1', 'execute', 'clef-signup-classifications', '--remote', '--command', sql, '--json',
], { cwd: project, encoding: 'utf8', timeout: 60_000, env: { ...process.env, WRANGLER_SEND_METRICS: 'false' } });
const rows = JSON.parse(output).flatMap(item => item.results ?? []);
const report = { startedAt, finishedAt: new Date().toISOString(), requests, anonymousStatus: anonymous.status, rows };
await mkdir(resolve(project, 'results'), { recursive: true });
await writeFile(resolve(project, 'results/live-smoke.json'), JSON.stringify(report, null, 2) + '\n');
assert.equal(rows.length, 7, 'Every accepted request must have exactly one D1 record');
for (const request of requests.filter(item => item.expected !== 'rejected')) {
  const row = rows.find(item => item.ray_id === request.rayId);
  assert.equal(row?.status, request.expected, `${request.path}: ${row?.error_code ?? 'record missing or pending'}`);
  assert.deepEqual(request.receivedClef, {
    status: row.status,
    verdict: row.verdict,
    probabilities: row.probabilities_json ? JSON.parse(row.probabilities_json) : null,
    confidence: row.confidence,
    requestId: row.id,
    model: row.model,
    policyVersion: row.policy_version,
    errorCode: row.error_code,
  }, `${request.path}: backend received predictions must match the committed result, not client-supplied headers`);
  if (request.expected === 'classified') {
    assert.equal(row.model, '@cf/cloudflare/clef');
    assert.equal(row.email_hmac.length, 64);
    assert.ok(['likely_legitimate', 'suspicious', 'insufficient_evidence'].includes(row.verdict));
  } else {
    assert.equal(row.error_code, request.reason);
  }
}
console.table(rows.map(({ path, status, verdict, confidence, inference_ms, error_code }) => ({
  path, status, verdict, confidence, inference_ms, error_code,
})));
console.log('Verified real Clef results, D1 commits, backend prediction receipt, original request fidelity, and private Access.');
console.log('Report: results/live-smoke.json');
