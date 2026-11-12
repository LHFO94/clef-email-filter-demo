const PATHS = new Set(['/signup', '/register', '/AccountV2/ConfirmEmail', '/probe']);

const VERDICTS = ['likely_legitimate', 'suspicious', 'insufficient_evidence'];

function receivedClef(headers) {
  let probabilities = null;
  try {
    const parsed = JSON.parse(headers.get('X-Clef-Probabilities'));
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed) &&
        Object.keys(parsed).length === VERDICTS.length &&
        VERDICTS.every(key => Number.isFinite(parsed[key]) && parsed[key] >= 0 && parsed[key] <= 1)) {
      probabilities = Object.fromEntries(VERDICTS.map(key => [key, parsed[key]]));
    }
  } catch {
    // Missing or malformed predictions are evidence of absence, not a fallback verdict.
  }
  const rawConfidence = headers.get('X-Clef-Confidence');
  const confidence = rawConfidence?.trim() ? Number(rawConfidence) : NaN;
  return {
    status: headers.get('X-Clef-Status'),
    verdict: headers.get('X-Clef-Verdict'),
    probabilities,
    confidence: Number.isFinite(confidence) && confidence >= 0 && confidence <= 1 ? confidence : null,
    requestId: headers.get('X-Clef-Request-Id'),
    model: headers.get('X-Clef-Model'),
    policyVersion: headers.get('X-Clef-Policy-Version'),
    errorCode: headers.get('X-Clef-Error'),
  };
}

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const headers = { 'Cache-Control': 'no-store', 'X-Test-Origin': 'clef-signup-test-origin' };
    if (request.method === 'GET' && url.pathname === '/') {
      return Response.json({
        purpose: 'Private test origin for the Clef signup proxy. No real accounts or emails.',
        paths: [...PATHS],
        methods: ['POST', 'PUT'],
      }, { headers });
    }
    if (!PATHS.has(url.pathname)) return Response.json({ error: 'Not found' }, { status: 404, headers });
    if (!['POST', 'PUT'].includes(request.method)) {
      return new Response(null, { status: 405, headers: { ...headers, Allow: 'POST, PUT' } });
    }
    const bytes = await request.arrayBuffer();
    const digest = await crypto.subtle.digest('SHA-256', bytes);
    return Response.json({
      accepted: true,
      accountsCreated: 0,
      clef: receivedClef(request.headers),
      request: {
        path: url.pathname,
        query: url.search,
        method: request.method,
        contentType: request.headers.get('content-type'),
        bodyBytes: bytes.byteLength,
        bodySha256: Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, '0')).join(''),
        probeHeader: request.headers.get('x-proxy-smoke'),
        authorizationPresent: request.headers.has('authorization'),
        cookiePresent: request.headers.has('cookie'),
      },
    }, { status: 201, headers });
  },
};
