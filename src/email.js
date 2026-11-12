export const MAX_BODY_BYTES = 16 * 1024;
const EMAIL_KEYS = new Set(['email', 'emailaddress', 'email_address', 'username']);
const EMAIL_PATTERN = /^[^\s@]+@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;

function validEmail(value) {
  if (typeof value !== 'string') return null;
  const email = value.trim();
  return email.length <= 254 && EMAIL_PATTERN.test(email) ? email : null;
}

function firstEmail(value) {
  if (!value || typeof value !== 'object') return null;
  // Iterative depth-first traversal also handles deeply nested, bounded JSON.
  const stack = [Object.entries(value)[Symbol.iterator]()];
  while (stack.length) {
    const next = stack.at(-1).next();
    if (next.done) {
      stack.pop();
      continue;
    }
    const [key, item] = next.value;
    if (EMAIL_KEYS.has(key.toLowerCase())) {
      const email = validEmail(item);
      if (email) return email;
    }
    if (item && typeof item === 'object') {
      stack.push(Object.entries(item)[Symbol.iterator]());
    }
  }
  return null;
}

export function extractEmail(bytes, contentType) {
  const type = contentType.split(';', 1)[0].trim().toLowerCase();
  const text = new TextDecoder().decode(bytes);
  if (type === 'application/json' || type === 'text/javascript') {
    let value;
    try {
      value = JSON.parse(text);
    } catch {
      return { email: null, reason: 'invalid_json' };
    }
    const email = firstEmail(value);
    return { email, reason: email ? null : 'email_not_found' };
  }
  if (type === 'application/x-www-form-urlencoded') {
    for (const [key, value] of new URLSearchParams(text)) {
      if (!EMAIL_KEYS.has(key.toLowerCase())) continue;
      const email = validEmail(value);
      if (email) return { email, reason: null };
    }
    return { email: null, reason: 'email_not_found' };
  }
  return { email: null, reason: 'unsupported_content_type' };
}

export async function readBody(request) {
  if (!request.body) return new Uint8Array();
  const reader = request.body.getReader();
  const chunks = [];
  let length = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > MAX_BODY_BYTES) {
        await reader.cancel();
        return null;
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

export async function emailHmac(email, secret) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
  );
  const digest = await crypto.subtle.sign('HMAC', key, encoder.encode(email.trim().toLowerCase()));
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('');
}
