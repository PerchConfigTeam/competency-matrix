// Cloudflare Pages Function - admin password control
// POST /set-password  { idToken, targetUid, newPassword }
// Verifies the caller is a signed-in admin, then overwrites the target
// user's password using a Google service account. No old password needed.

const ITK = 'https://identitytoolkit.googleapis.com/v1';

function json(body, status) {
  return new Response(JSON.stringify(body), {
    status: status || 200,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }
  });
}

function b64url(bytes) {
  let s = '';
  const b = new Uint8Array(bytes);
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function pemToArrayBuffer(pem) {
  const body = pem
    .replace(/-----BEGIN PRIVATE KEY-----/, '')
    .replace(/-----END PRIVATE KEY-----/, '')
    .replace(/\s/g, '');
  const raw = atob(body);
  const buf = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) buf[i] = raw.charCodeAt(i);
  return buf.buffer;
}

async function getAccessToken(sa) {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'RS256', typ: 'JWT' };
  const claim = {
    iss: sa.client_email,
    scope: 'https://www.googleapis.com/auth/cloud-platform',
    aud: 'https://oauth2.googleapis.com/token',
    iat: now,
    exp: now + 3600
  };
  const enc = new TextEncoder();
  const unsigned = b64url(enc.encode(JSON.stringify(header))) + '.' + b64url(enc.encode(JSON.stringify(claim)));
  const key = await crypto.subtle.importKey(
    'pkcs8',
    pemToArrayBuffer(sa.private_key),
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, enc.encode(unsigned));
  const jwt = unsigned + '.' + b64url(sig);

  const res = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=' + encodeURIComponent(jwt)
  });
  const data = await res.json();
  if (!res.ok || !data.access_token) throw new Error('Google token exchange failed.');
  return data.access_token;
}

async function verifyCaller(idToken, apiKey) {
  const res = await fetch(ITK + '/accounts:lookup?key=' + apiKey, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ idToken: idToken })
  });
  const data = await res.json();
  if (!res.ok || !data.users || !data.users.length) return null;
  return { uid: data.users[0].localId, email: data.users[0].email };
}

async function isAdmin(projectId, uid, accessToken) {
  const url = 'https://firestore.googleapis.com/v1/projects/' + projectId +
    '/databases/(default)/documents/users/' + encodeURIComponent(uid);
  const res = await fetch(url, { headers: { Authorization: 'Bearer ' + accessToken } });
  if (!res.ok) return false;
  const doc = await res.json();
  const role = doc && doc.fields && doc.fields.role && doc.fields.role.stringValue;
  return role === 'admin';
}

export async function onRequestPost(context) {
  const env = context.env;
  try {
    if (!env.FIREBASE_SERVICE_ACCOUNT || !env.FIREBASE_API_KEY) {
      return json({ error: 'Server not configured. Check FIREBASE_SERVICE_ACCOUNT and FIREBASE_API_KEY in Cloudflare.' }, 500);
    }

    let body;
    try { body = await context.request.json(); }
    catch (e) { return json({ error: 'Bad request body.' }, 400); }

    const idToken = body.idToken;
    const targetUid = body.targetUid;
    const newPassword = body.newPassword;

    if (!idToken || !targetUid || !newPassword) return json({ error: 'Missing idToken, targetUid or newPassword.' }, 400);
    if (String(newPassword).length < 6) return json({ error: 'Password must be at least 6 characters.' }, 400);

    const sa = JSON.parse(env.FIREBASE_SERVICE_ACCOUNT);
    const projectId = sa.project_id;

    const caller = await verifyCaller(idToken, env.FIREBASE_API_KEY);
    if (!caller) return json({ error: 'Your session has expired. Log out and back in.' }, 401);

    const accessToken = await getAccessToken(sa);

    if (!(await isAdmin(projectId, caller.uid, accessToken))) {
      return json({ error: 'Admins only.' }, 403);
    }

    const res = await fetch(ITK + '/projects/' + projectId + '/accounts:update', {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + accessToken, 'Content-Type': 'application/json' },
      body: JSON.stringify({ localId: targetUid, password: String(newPassword) })
    });
    const out = await res.json();
    if (!res.ok) {
      const msg = (out && out.error && out.error.message) || 'Update failed.';
      return json({ error: msg }, 400);
    }

    return json({ ok: true, email: out.email || null, changedBy: caller.email });
  } catch (e) {
    return json({ error: e.message || 'Unexpected server error.' }, 500);
  }
}

export async function onRequestOptions() {
  return new Response(null, { status: 204, headers: { Allow: 'POST, OPTIONS' } });
}
