import { emailHmac, extractEmail, MAX_BODY_BYTES, readBody } from './email.js';
import { MODEL, parseDecision, POLICY_VERSION, QUESTIONS } from './policy.js';

export const SIGNUP_PATHS = new Set(['/signup', '/register', '/AccountV2/ConfirmEmail', '/probe']);
const INFERENCE_TIMEOUT_MS = 120_000;
const unavailable = (recordId = null) => ({
  response: Response.json(
    { error: 'Classification record unavailable. The request was not forwarded.' },
    { status: 503, headers: { 'Cache-Control': 'no-store' } },
  ),
  recordId,
});

async function forward(request, result = null) {
  const headers = new Headers(request.headers);
  // Client-supplied predictions and demo markers are never origin evidence.
  for (const name of [...headers.keys()]) {
    if (name.toLowerCase().startsWith('x-clef-')) headers.delete(name);
  }
  if (result) {
    headers.set('X-Clef-Status', result.status);
    headers.set('X-Clef-Request-Id', result.id);
    headers.set('X-Clef-Model', MODEL);
    headers.set('X-Clef-Policy-Version', POLICY_VERSION);
    if (result.decision) {
      headers.set('X-Clef-Verdict', result.decision.verdict);
      headers.set('X-Clef-Probabilities', JSON.stringify(result.decision.probabilities));
      headers.set('X-Clef-Confidence', String(result.decision.confidence));
    }
    if (result.errorCode) headers.set('X-Clef-Error', result.errorCode);
  }
  const originRequest = new Request(request, { headers });
  try {
    return await fetch(originRequest);
  } catch {
    // Never retry signup POSTs: the origin may already have processed the request.
    return Response.json({ error: 'Origin unavailable.' }, {
      status: 502, headers: { 'Cache-Control': 'no-store' },
    });
  }
}

async function complete(env, id, { status, errorCode = null, decision = null, inferenceMs = null }) {
  const update = await env.DB.prepare(`
    UPDATE classifications SET completed_at = ?, status = ?, verdict = ?,
      probabilities_json = ?, confidence = ?, inference_ms = ?, input_tokens = ?,
      output_tokens = ?, action = 'forward', error_code = ?
    WHERE id = ? AND status = 'pending'
  `).bind(new Date().toISOString(), status, decision?.verdict ?? null,
    decision ? JSON.stringify(decision.probabilities) : null,
    decision?.confidence ?? null, inferenceMs, decision?.inputTokens ?? null,
    decision?.outputTokens ?? null, errorCode, id).run();
  if (!update.success || update.meta.changes !== 1) throw new Error('classification_commit_failed');
}

async function classify(env, id, email) {
  const started = performance.now();
  const signal = AbortSignal.timeout(INFERENCE_TIMEOUT_MS);
  let decision;
  let errorCode;
  try {
    const result = await env.AI.run(MODEL, {
      model: 'clef', state: { email }, questions: QUESTIONS,
    }, { signal });
    try {
      decision = parseDecision(result);
    } catch {
      errorCode = 'invalid_model_output';
    }
  } catch {
    errorCode = signal.aborted ? 'inference_timeout' : 'inference_failed';
  }
  const result = {
    status: decision ? 'classified' : 'error', decision, errorCode,
    inferenceMs: Math.round(performance.now() - started),
  };
  await complete(env, id, result);
  return result;
}

export async function proxySignup(request, env) {
  const url = new URL(request.url);
  if (!SIGNUP_PATHS.has(url.pathname) || !['POST', 'PUT'].includes(request.method)) {
    return { response: await forward(request), recordId: null };
  }
  if (!env.EMAIL_HMAC_KEY) return unavailable();

  let bytes;
  try {
    bytes = await readBody(request);
  } catch {
    return {
      response: Response.json({ error: 'Could not read request body.' }, { status: 400 }),
      recordId: null,
    };
  }
  if (bytes === null) {
    return {
      response: Response.json({ error: `Signup body exceeds ${MAX_BODY_BYTES} bytes.` }, {
        status: 413, headers: { 'Cache-Control': 'no-store' },
      }),
      recordId: null,
    };
  }
  const originRequest = new Request(request, { body: bytes });
  const contentType = request.headers.get('content-type') ?? '';
  const { email, reason } = extractEmail(bytes, contentType);
  const id = crypto.randomUUID();
  let recordId = null;
  let result;
  try {
    const hash = email ? await emailHmac(email, env.EMAIL_HMAC_KEY) : null;
    const insert = await env.DB.prepare(`
      INSERT INTO classifications
        (id, ray_id, created_at, path, method, content_type, email_hmac,
         model, policy_version, status, action)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', 'pending')
    `).bind(id, request.headers.get('cf-ray'), new Date().toISOString(), url.pathname,
      request.method, contentType, hash, MODEL, POLICY_VERSION).run();
    if (!insert.success) return unavailable();
    recordId = id;
    if (email) {
      result = await classify(env, id, email);
    } else {
      result = { status: 'skipped', errorCode: reason };
      await complete(env, id, result);
    }
  } catch {
    return unavailable(recordId);
  }
  // Log-only: preserve body, query, method and response; replace only Clef request headers.
  return { response: await forward(originRequest, { ...result, id }), recordId };
}
