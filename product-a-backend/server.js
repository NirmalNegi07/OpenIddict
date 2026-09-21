require('dotenv').config();

const crypto = require('crypto');
const express = require('express');
const session = require('express-session');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const { renderPage, escapeHtml } = require('./layout');

const app = express();

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, sameSite: 'lax' }, // secure:false because this is local plain-HTTP
  })
);

const jwks = jwksClient({ jwksUri: process.env.LIGHTHOUSE_JWKS_URI });

function getSigningKey(header, callback) {
  jwks.getSigningKey(header.kid, (err, key) => {
    if (err) return callback(err);
    callback(null, key.getPublicKey());
  });
}

// Verifies the "stamp" -- the access token Lighthouse issued -- against Lighthouse's
// published JWKS, so Product A never has to trust a token just because it has one.
function verifyAccessToken(token) {
  return new Promise((resolve, reject) => {
    jwt.verify(
      token,
      getSigningKey,
      {
        issuer: `${process.env.LIGHTHOUSE_ISSUER}/`,
        audience: 'product_a_api',
        algorithms: ['RS256'],
      },
      (err, decoded) => {
        if (err) return reject(err);
        resolve(decoded);
      }
    );
  });
}

function base64url(buffer) {
  return buffer.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// Centralized auth check: verifies the access token's signature/issuer/audience/expiry on
// every single request to a protected route (not just once at login), and attaches the
// decoded claims to req.tokenClaims so route handlers don't each re-verify separately.
async function requireAuth(req, res, next) {
  if (!req.session.accessToken) {
    return res.redirect('/login');
  }
  try {
    req.tokenClaims = await verifyAccessToken(req.session.accessToken);
    next();
  } catch (err) {
    logStep(req, `ERROR verifying access token on ${req.path}`, { message: err.message });
    req.session.accessToken = null;
    req.session.user = null;
    return res.redirect('/login');
  }
}

// --- Flow log: records each step of the OAuth exchange with real (truncated) values so the
// UI can show what's actually happening under the hood, not just "logged in / not logged in".
function truncate(value, length = 36) {
  if (!value) return value;
  const str = String(value);
  return str.length > length ? `${str.slice(0, length)}…` : str;
}

function logStep(req, title, data) {
  if (!req.session.flowLog) req.session.flowLog = [];
  req.session.flowLog.push({
    time: new Date().toISOString(),
    title,
    data: data || {},
  });
  // Keep it bounded -- this is a demo log, not an audit trail.
  if (req.session.flowLog.length > 30) req.session.flowLog.shift();
}

app.get('/', (req, res) => {
  const user = req.session.user;

  const body = user
    ? `
      <div class="hero">
        <h1>Welcome back</h1>
        <p>You're signed in as <b>${escapeHtml(user.email || user.sub)}</b>, verified against Lighthouse.</p>
        <a href="/dashboard" class="btn btn-primary">Go to dashboard</a>
      </div>
    `
    : `
      <div class="hero">
        <h1>Product A</h1>
        <p>This app doesn't handle its own logins &mdash; every sign-in happens at Lighthouse,
           the central identity provider, using OAuth2 Authorization Code + PKCE.</p>
        <a href="/login" class="btn btn-primary">Login with Lighthouse</a>
      </div>
      <div class="card">
        <h2>What happens when you click that</h2>
        <p class="card-sub">A quick preview of the flow this experiment demonstrates</p>
        <table class="kv">
          <tr><td class="k">1. Redirect</td><td class="v">Browser is sent to Lighthouse's /connect/authorize</td></tr>
          <tr><td class="k">2. Login</td><td class="v">You authenticate directly with Lighthouse, never with Product A</td></tr>
          <tr><td class="k">3. Stamp</td><td class="v">Lighthouse redirects back with a single-use authorization code</td></tr>
          <tr><td class="k">4. Exchange</td><td class="v">Product A's server trades that code for tokens, server-to-server</td></tr>
          <tr><td class="k">5. Verify</td><td class="v">Product A checks the token's signature against Lighthouse's public key</td></tr>
        </table>
      </div>
    `;

  res.send(renderPage({ title: 'Home', active: null, user, body }));
});

// Step 1: send the user to Lighthouse's authorization endpoint (Authorization Code + PKCE).
app.get('/login', (req, res) => {
  req.session.flowLog = []; // fresh log for each login attempt

  const codeVerifier = base64url(crypto.randomBytes(32));
  const codeChallenge = base64url(crypto.createHash('sha256').update(codeVerifier).digest());
  const state = base64url(crypto.randomBytes(16));

  req.session.codeVerifier = codeVerifier;
  req.session.state = state;

  const params = new URLSearchParams({
    client_id: process.env.CLIENT_ID,
    response_type: 'code',
    redirect_uri: process.env.REDIRECT_URI,
    scope: process.env.SCOPES,
    state,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
  });

  logStep(req, '1. Redirecting browser to Lighthouse /connect/authorize', {
    client_id: process.env.CLIENT_ID,
    redirect_uri: process.env.REDIRECT_URI,
    scope: process.env.SCOPES,
    state,
    code_verifier: `${truncate(codeVerifier)}  (kept server-side only, never sent yet)`,
    code_challenge: truncate(codeChallenge),
  });

  res.redirect(`${process.env.LIGHTHOUSE_AUTHORIZE_URL}?${params.toString()}`);
});

// Step 2: Lighthouse redirects back here with an authorization code (the "stamp").
// Product A exchanges it for tokens, then verifies the access token itself.
app.get('/auth/callback', async (req, res) => {
  const { code, state, error, error_description: errorDescription } = req.query;

  if (error) {
    logStep(req, '2. Lighthouse returned an error instead of a code', { error, errorDescription });
    return res.status(400).send(`Login failed: ${error} - ${errorDescription || ''}`);
  }

  logStep(req, '2. Received the "stamp" (authorization code) from Lighthouse', {
    code: truncate(code),
    state,
    state_matches_what_we_sent: state === req.session.state,
  });

  if (!state || state !== req.session.state) {
    return res.status(400).send('Invalid or missing state parameter.');
  }

  const codeVerifier = req.session.codeVerifier;
  delete req.session.state;
  delete req.session.codeVerifier;

  try {
    logStep(req, '3. Exchanging the stamp for tokens (server-to-server, browser not involved)', {
      request_to: process.env.LIGHTHOUSE_TOKEN_URL,
      code: truncate(code),
      code_verifier: truncate(codeVerifier),
      client_id: process.env.CLIENT_ID,
      client_secret: '••• (sent, not shown)',
    });

    const tokenResponse = await axios.post(
      process.env.LIGHTHOUSE_TOKEN_URL,
      new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: process.env.REDIRECT_URI,
        client_id: process.env.CLIENT_ID,
        client_secret: process.env.CLIENT_SECRET,
        code_verifier: codeVerifier,
      }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );

    const { access_token: accessToken, refresh_token: refreshToken, expires_in: expiresIn } = tokenResponse.data;

    logStep(req, '4. Lighthouse returned tokens', {
      access_token: truncate(accessToken, 60),
      refresh_token: truncate(refreshToken, 40),
      expires_in: `${expiresIn}s`,
    });

    const claims = await verifyAccessToken(accessToken);

    logStep(req, '5. Verified access token signature against Lighthouse JWKS (no network call to Lighthouse)', {
      sub: claims.sub,
      email: claims.email,
      aud: claims.aud,
      scope: claims.scope,
      exp: new Date(claims.exp * 1000).toISOString(),
    });

    req.session.accessToken = accessToken;
    req.session.refreshToken = refreshToken;
    req.session.tokenIssuedAt = Date.now();
    req.session.user = claims;

    res.redirect('/dashboard');
  } catch (err) {
    logStep(req, 'ERROR during token exchange/verification', {
      message: err.response?.data ? JSON.stringify(err.response.data) : err.message,
    });
    console.error('Token exchange or verification failed:', err.response?.data || err.message);
    res.status(500).send('Login failed during token exchange/verification. Check server logs.');
  }
});

// Post-login home: a richer landing spot than the public "/", with quick stats and links to
// the pages that show the mechanics (Profile, Session, Flow Log).
app.get('/dashboard', requireAuth, (req, res) => {
  const claims = req.tokenClaims;
  const expiresInMin = Math.max(0, Math.round((claims.exp * 1000 - Date.now()) / 60000));
  const scopeCount = (claims.scope || '').split(' ').filter(Boolean).length;

  logStep(req, 'Re-verified access token for /dashboard request', { sub: claims.sub, aud: claims.aud });

  const body = `
    <div class="tiles">
      <div class="tile">
        <div class="label">Signed in as</div>
        <div class="value mono">${escapeHtml(claims.email || claims.sub)}</div>
      </div>
      <div class="tile">
        <div class="label">Access token expires in</div>
        <div class="value">${expiresInMin} min</div>
      </div>
      <div class="tile">
        <div class="label">Scopes granted</div>
        <div class="value">${scopeCount}</div>
      </div>
      <div class="tile">
        <div class="label">Refresh token</div>
        <div class="value">${req.session.refreshToken ? 'Present' : 'None'}</div>
      </div>
    </div>

    <div class="card">
      <h2>Explore what's actually happening</h2>
      <p class="card-sub">Every page here reflects real, live data from this session &mdash; nothing mocked</p>
      <div class="quick-links">
        <a href="/profile" class="btn btn-ghost">View verified claims</a>
        <a href="/session" class="btn btn-ghost">Inspect token/session details</a>
        <a href="/logs" class="btn btn-ghost">Replay the login flow log</a>
      </div>
    </div>
  `;

  res.send(renderPage({ title: 'Dashboard', active: 'dashboard', user: req.session.user, body }));
});

// Protected route: shows the token's claims in a readable form, plus the raw decoded JWT.
// Re-verifies the token on every request via requireAuth -- this is not read from a cache.
app.get('/profile', requireAuth, (req, res) => {
  const claims = req.tokenClaims;

  logStep(req, 'Re-verified access token for /profile request', { sub: claims.sub, aud: claims.aud });

  const knownRows = [
    ['sub', claims.sub],
    ['email', claims.email],
    ['name', claims.name],
    ['preferred_username', claims.preferred_username],
    ['client_id', claims.client_id],
    ['iss', claims.iss],
    ['aud', claims.aud],
  ]
    .filter(([, v]) => v !== undefined)
    .map(([k, v]) => `<tr><td class="k">${escapeHtml(k)}</td><td class="v">${escapeHtml(v)}</td></tr>`)
    .join('');

  const body = `
    <div class="card">
      <h2>Verified identity claims</h2>
      <p class="card-sub">Decoded from the access token, signature-checked against Lighthouse's JWKS on this request</p>
      <table class="kv">${knownRows}</table>

      <details class="raw">
        <summary>Show full raw claim set (JSON)</summary>
        <pre>${escapeHtml(JSON.stringify(claims, null, 2))}</pre>
      </details>
    </div>
  `;

  res.send(renderPage({ title: 'Profile', active: 'profile', user: req.session.user, body }));
});

// Protected route: token/session mechanics -- issuance, expiry, scopes, refresh token
// presence. A companion to /profile that's about the token itself, not the user's identity.
app.get('/session', requireAuth, (req, res) => {
  const claims = req.tokenClaims;
  const now = Date.now();
  const expiresAt = claims.exp * 1000;
  const issuedAt = claims.iat * 1000;
  const minutesLeft = Math.max(0, Math.round((expiresAt - now) / 60000));
  const scopes = (claims.scope || '').split(' ').filter(Boolean);

  logStep(req, 'Re-verified access token for /session request', { sub: claims.sub, aud: claims.aud });

  const scopeTags = scopes.map((s) => `<span class="scope-tag">${escapeHtml(s)}</span>`).join('');

  const body = `
    <div class="card">
      <h2>Token lifecycle</h2>
      <p class="card-sub">Times decoded straight from the token's own iat/exp claims</p>
      <table class="kv">
        <tr><td class="k">Issued at</td><td class="v">${new Date(issuedAt).toLocaleString()}</td></tr>
        <tr><td class="k">Expires at</td><td class="v">${new Date(expiresAt).toLocaleString()}</td></tr>
        <tr><td class="k">Time remaining</td><td class="v">
          <span class="badge ${minutesLeft > 5 ? 'badge-success' : 'badge-danger'}">${minutesLeft} min left</span>
        </td></tr>
        <tr><td class="k">Refresh token</td><td class="v">
          <span class="badge ${req.session.refreshToken ? 'badge-success' : 'badge-neutral'}">
            ${req.session.refreshToken ? 'present in session' : 'not issued'}
          </span>
        </td></tr>
      </table>
    </div>

    <div class="card">
      <h2>Granted scopes</h2>
      <p class="card-sub">What Lighthouse allowed this token to claim access to</p>
      <div class="scope-tags">${scopeTags}</div>
    </div>

    <div class="card">
      <h2>How this page got verified</h2>
      <p class="card-sub">No shortcuts &mdash; same check every protected route runs</p>
      <table class="kv">
        <tr><td class="k">Verification method</td><td class="v">RS256 signature check against Lighthouse's JWKS</td></tr>
        <tr><td class="k">Network call to Lighthouse?</td><td class="v">No (public key cached after first fetch)</td></tr>
        <tr><td class="k">Database call?</td><td class="v">No</td></tr>
      </table>
    </div>
  `;

  res.send(renderPage({ title: 'Session', active: 'session', user: req.session.user, body }));
});

// Renders the step-by-step log of what actually happened during the OAuth exchange, with
// real (truncated) values, so you can see the flow instead of just trusting it worked.
app.get('/logs', (req, res) => {
  const entries = req.session.flowLog || [];

  const rows = entries.length
    ? entries
        .map(
          (entry, i) => `
        <div class="flow-entry">
          <div class="flow-entry-head">
            <span class="step-num">${i + 1}</span>
            <span class="title">${escapeHtml(entry.title)}</span>
            <span class="time">${new Date(entry.time).toLocaleTimeString()}</span>
          </div>
          <table class="kv">
            ${Object.entries(entry.data)
              .map(([k, v]) => `<tr><td class="k">${escapeHtml(k)}</td><td class="v">${escapeHtml(String(v))}</td></tr>`)
              .join('')}
          </table>
        </div>`
        )
        .join('')
    : '<div class="empty-state">No flow recorded yet. <a href="/login">Login with Lighthouse</a> to generate one.</div>';

  const body = `
    <div class="card">
      <h2>OAuth flow log</h2>
      <p class="card-sub">This session's login exchange, step by step, with real (truncated) values</p>
    </div>
    ${rows}
  `;

  res.send(renderPage({ title: 'Flow Log', active: 'logs', user: req.session.user, body }));
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

const port = process.env.PORT || 4000;
app.listen(port, () => {
  console.log(`Product A backend listening on http://localhost:${port}`);
});
