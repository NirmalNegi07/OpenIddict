# OpenIddict experiment: Lighthouse (IDP) + Product A (client)

A minimal end-to-end OAuth2/OIDC setup to see how OpenIddict works.

## Architecture

- **Lighthouse** (`Lighthouse/`) — ASP.NET Core 8 + OpenIddict + ASP.NET Identity, backed by
  MySQL. Acts as the central IDP: hosts the login page, the `/connect/authorize` and
  `/connect/token` endpoints, and the JWKS used to verify tokens it issues.
- **Product A backend** (`product-a-backend/`) — Express app acting as a confidential OAuth
  client (holds a client secret) and as the resource server that verifies tokens.

Flow: user hits Product A → redirected to Lighthouse to log in → Lighthouse redirects back
with an authorization code (the "stamp") → Product A exchanges the code for an access token
at Lighthouse's token endpoint → Product A verifies that access token itself against
Lighthouse's JWKS (signature, issuer, audience) before trusting it. This is the standard
OAuth2 Authorization Code flow with PKCE.

## Running it

**Lighthouse** (needs MySQL running locally; connection string is in `appsettings.json`):
```
cd Lighthouse
dotnet run --launch-profile http   # http://localhost:5094
```
On first run it auto-migrates the DB and seeds:
- OAuth client `product-a-backend` / secret `product-a-dev-secret-change-me`
- Scope `product_a_api` (this is what ends up as the token's `aud` claim)
- Test user `test@lighthouse.local` / `Passw0rd!`

**Product A backend**:
```
cd product-a-backend
npm install
node server.js   # http://localhost:4000
```

Then open http://localhost:4000 in a browser, click "Login with Lighthouse", sign in with
the test account, and you'll land back on Product A logged in. `/profile` shows the verified
JWT claims.

## Things simplified for this experiment (fix before this goes anywhere near production)

- **Ephemeral signing/encryption keys** (`AddEphemeralSigningKey`/`AddEphemeralEncryptionKey`
  in `Lighthouse/Program.cs`): regenerated on every Lighthouse restart, so any tokens issued
  before a restart stop validating. Swap for a persisted X509 certificate.
- **Plain HTTP, transport security disabled** (`DisableTransportSecurityRequirement()`): done
  so Product A doesn't need to trust a local dev HTTPS cert. Never do this outside localhost.
- **No consent screen**: Product A is treated as a single trusted first-party client, so
  `AuthorizationController.Authorize()` skips straight to issuing a code after login.
- **Secrets in `appsettings.json` / `.env` in plain text** — fine for a laptop experiment,
  not for anything shared.
- **MySQL column lengths trimmed** on `OpenIddictAuthorizations`/`OpenIddictTokens`
  (`Lighthouse/Data/LighthouseDbContext.cs`) because MySQL's InnoDB caps a composite index key
  at 3072 bytes and OpenIddict's utf8mb4 defaults blow past that.

## Useful endpoints

- `http://localhost:5094/.well-known/openid-configuration` — OIDC discovery document
- `http://localhost:5094/.well-known/jwks` — signing keys (what Product A verifies against)
