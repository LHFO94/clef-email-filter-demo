import assert from 'node:assert/strict';
import test from 'node:test';
import { emailHmac, extractEmail, MAX_BODY_BYTES, readBody } from '../src/email.js';
import { parseDecision } from '../src/policy.js';

const encode = value => new TextEncoder().encode(value);

test('finds the first valid email in nested JSON and ignores credential fields', () => {
  const body = JSON.stringify({
    password: 'secret@not-input.example',
    account: { username: 'user@invalid', details: [{ email: 'bob@mytempmail.com' }] },
    email: 'later@example.com',
  });
  assert.deepEqual(extractEmail(encode(body), 'application/json; charset=utf-8'), {
    email: 'bob@mytempmail.com', reason: null,
  });
});

test('decodes form values without treating password or query data as email', () => {
  const body = 'password=secret%40example.com&email=bad%40invalid&email=alice%2Boffer%40example.com';
  assert.deepEqual(extractEmail(encode(body), 'application/x-www-form-urlencoded'), {
    email: 'alice+offer@example.com', reason: null,
  });
});

test('malformed JSON and missing usable email remain distinct skipped outcomes', () => {
  assert.equal(extractEmail(encode('{"email":'), 'application/json').reason, 'invalid_json');
  assert.equal(extractEmail(encode('{"email":"user@invalid"}'), 'application/json').reason, 'email_not_found');
  assert.equal(extractEmail(encode('alice@example.com'), 'text/plain').reason, 'unsupported_content_type');
});

test('body limit applies to actual streamed bytes, including absent content-length', async () => {
  const atLimit = new Uint8Array(MAX_BODY_BYTES);
  const accepted = await readBody(new Request('https://example.com/signup', { method: 'POST', body: atLimit }));
  assert.deepEqual(accepted, atLimit);
  const stream = new ReadableStream({
    start(controller) {
      controller.enqueue(atLimit);
      controller.enqueue(new Uint8Array([1]));
      controller.close();
    },
  });
  assert.equal(await readBody(new Request('https://example.com/signup', {
    method: 'POST', body: stream, duplex: 'half',
  })), null);
});

test('identity HMAC is stable after normalization but isolated by key', async () => {
  const first = await emailHmac(' Bob@Example.com ', 'first-secret');
  assert.equal(first, await emailHmac('bob@example.com', 'first-secret'));
  assert.notEqual(first, await emailHmac('bob@example.com', 'second-secret'));
});

test('rejects untrustworthy probability distributions and inconsistent chosen class', () => {
  const response = {
    answers: { email_risk: {
      type: 'choice', choice: 'suspicious', confidence: 0.7,
      probabilities: { likely_legitimate: 0.1, suspicious: 0.8, insufficient_evidence: 0.1 },
    } },
  };
  assert.equal(parseDecision(response).verdict, 'suspicious');
  response.answers.email_risk.probabilities.suspicious = 0.2;
  assert.throws(() => parseDecision(response), /invalid_model_output/);
  response.answers.email_risk.probabilities.likely_legitimate = 0.7;
  assert.throws(() => parseDecision(response), /invalid_model_output/);
});
