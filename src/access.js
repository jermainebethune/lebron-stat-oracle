/**
 * Who is allowed to spend a Neuron.
 *
 * Before this existed, /api/ask was open to anyone who knew the URL. At ~35.5
 * Neurons per question against a 10,000/day allowance, a trivial loop could
 * exhaust the daily budget in minutes and take the app down until 00:00 UTC.
 *
 * Two ways in, deliberately:
 *
 *   1. A Turnstile token — what the web page sends. Invisible to real users,
 *      expensive for scripts.
 *   2. An API key header — so the thing can still be driven programmatically,
 *      by us for testing and by anyone we choose to hand a key to.
 *
 * Checked BEFORE any inference runs, because the whole point is not spending
 * the budget on unauthorized callers.
 */

const VERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';

export const DENIED = {
  NO_PROOF: 'Send a Turnstile token or an x-api-key header.',
  BAD_TOKEN: 'That Turnstile token was not accepted.',
  BAD_KEY: 'That API key is not valid.',
};

/**
 * Constant-time-ish string compare. Not a defence against a determined
 * attacker over the network (jitter swamps the signal), but it costs nothing
 * and avoids the habit of leaking length/prefix through early return.
 */
function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function verifyTurnstile(token, secret, ip) {
  const form = new FormData();
  form.append('secret', secret);
  form.append('response', token);
  if (ip) form.append('remoteip', ip);

  const res = await fetch(VERIFY_URL, { method: 'POST', body: form });
  if (!res.ok) return false;
  const data = await res.json();
  return data.success === true;
}

/**
 * Returns { ok: true, via } or { ok: false, reason }.
 *
 * Fails closed: if a secret isn't configured, that path simply isn't available
 * rather than silently allowing everything through.
 */
export async function authorize(request, body, env) {
  const key = request.headers.get('x-api-key');
  if (key) {
    if (env.API_KEY && safeEqual(key, env.API_KEY)) return { ok: true, via: 'api-key' };
    return { ok: false, reason: DENIED.BAD_KEY };
  }

  const token = body?.turnstileToken;
  if (token) {
    if (!env.TURNSTILE_SECRET) return { ok: false, reason: DENIED.BAD_TOKEN };
    const ip = request.headers.get('cf-connecting-ip');
    const good = await verifyTurnstile(token, env.TURNSTILE_SECRET, ip);
    return good ? { ok: true, via: 'turnstile' } : { ok: false, reason: DENIED.BAD_TOKEN };
  }

  return { ok: false, reason: DENIED.NO_PROOF };
}
