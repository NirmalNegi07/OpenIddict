require('dotenv').config();

const crypto = require('crypto');
const express = require('express');
const session = require('express-session');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

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

function requireAuth(req, res, next) {
  if (!req.session.accessToken) {
    return res.redirect('/login');
  }
  next();
}

app.get('/', (req, res) => {
  if (req.session.user) {
    res.send(`
      <h1>Product A</h1>
      <p>Signed in as <b>${req.session.user.email || req.session.user.sub}</b> (via Lighthouse).</p>
      <p><a href="/profile">View verified token claims</a> · <a href="/logout">Logout</a></p>
    `);
  } else {
    res.send(`
      <h1>Product A</h1>
      <p><a href="/login">Login with Lighthouse</a></p>
    `);
  }
});

// Step 1: send the user to Lighthouse's authorization endpoint (Authorization Code + PKCE).
app.get('/login', (req, res) => {
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

  res.redirect(`${process.env.LIGHTHOUSE_AUTHORIZE_URL}?${params.toString()}`);
});

// Step 2: Lighthouse redirects back here with an authorization code (the "stamp").
// Product A exchanges it for tokens, then verifies the access token itself.
app.get('/auth/callback', async (req, res) => {
  const { code, state, error, error_description: errorDescription } = req.query;

  if (error) {
    return res.status(400).send(`Login failed: ${error} - ${errorDescription || ''}`);
  }

  if (!state || state !== req.session.state) {
    return res.status(400).send('Invalid or missing state parameter.');
  }

  const codeVerifier = req.session.codeVerifier;
  delete req.session.state;
  delete req.session.codeVerifier;

  try {
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

    const { access_token: accessToken, refresh_token: refreshToken } = tokenResponse.data;
    const claims = await verifyAccessToken(accessToken);

    req.session.accessToken = accessToken;
    req.session.refreshToken = refreshToken;
    req.session.user = claims;

    res.redirect('/');
  } catch (err) {
    console.error('Token exchange or verification failed:', err.response?.data || err.message);
    res.status(500).send('Login failed during token exchange/verification. Check server logs.');
  }
});

// Protected route: re-verifies the stored access token against Lighthouse's JWKS on every
// request, rather than trusting the session blindly.
app.get('/profile', requireAuth, async (req, res) => {
  try {
    const claims = await verifyAccessToken(req.session.accessToken);
    res.type('text/plain').send(JSON.stringify(claims, null, 2));
  } catch (err) {
    res.status(401).send(`Access token is no longer valid: ${err.message}`);
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

const port = process.env.PORT || 4000;
app.listen(port, () => {
  console.log(`Product A backend listening on http://localhost:${port}`);
});
