import { demoTest, secureResponse } from './demo.js';
import { proxySignup, SIGNUP_PATHS } from './proxy.js';

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === '/AccountV2/ConfirmEmail' && request.method === 'POST' &&
        request.headers.get('X-Clef-Demo') === '1') {
      return secureResponse(await demoTest(request, env));
    }
    // Preserve every method and the untouched origin response on existing signup paths.
    if (SIGNUP_PATHS.has(url.pathname)) {
      return (await proxySignup(request, env)).response;
    }
    if (url.pathname === '/api' || url.pathname.startsWith('/api/')) {
      return secureResponse(Response.json({ error: 'Not found.' }, { status: 404 }));
    }
    if (request.method === 'GET' || request.method === 'HEAD') {
      try {
        return secureResponse(await env.ASSETS.fetch(request));
      } catch {
        return secureResponse(Response.json({ error: 'Frontend assets unavailable.' }, { status: 503 }));
      }
    }
    // Non-asset bypass traffic retains the original proxy forwarding behavior.
    return (await proxySignup(request, env)).response;
  },
};
