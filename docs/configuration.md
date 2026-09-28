# Configuration

Copy `.env.example` to `.env` and adjust. Config is validated at startup
(`src/config.ts`); missing required values fail fast.

| Variable                    | Default                              | Notes                                                                                                                                                                                                                             |
| --------------------------- | ------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `PORT`                      | `3000`                               | HTTP port                                                                                                                                                                                                                         |
| `LOG_LEVEL`                 | `debug`                              | `debug` enables pino-pretty output                                                                                                                                                                                                |
| `DB_HOST`                   | `localhost`                          | MySQL host                                                                                                                                                                                                                        |
| `DB_PORT`                   | `3306`                               | MySQL port (keep in sync with `MYSQL_PORT`)                                                                                                                                                                                       |
| `DB_USER`                   | —                                    | **required**; MySQL user                                                                                                                                                                                                          |
| `DB_PASS`                   | _(empty)_                            | MySQL password                                                                                                                                                                                                                    |
| `DB_NAME`                   | —                                    | **required**; MySQL database name                                                                                                                                                                                                 |
| `DB_SSL`                    | _(auto)_                             | `required` or `off`. Unset: `off` for `localhost`/`127.0.0.1`/`::1`, `required` for any other host. TLS always verifies the certificate chain and that it names `DB_HOST`, so with TLS on `DB_HOST` must be a hostname, not an IP |
| `DB_SSL_CA`                 | _(empty)_                            | CA certificate (PEM) to trust for the database, e.g. the AWS RDS bundle; empty uses the system trust store                                                                                                                        |
| `JWT_PRIVATE_KEY`           | —                                    | **required**; RS256 private key (PEM). `deno task keys:gen`                                                                                                                                                                       |
| `JWT_PUBLIC_KEY`            | —                                    | **required**; RS256 public key (PEM), published via JWKS                                                                                                                                                                          |
| `JWT_ISSUER`                | —                                    | **required**; `iss` claim + OIDC issuer URL                                                                                                                                                                                       |
| `JWT_PREVIOUS_PUBLIC_KEYS`  | `[]`                                 | retired signing public keys still honored during rotation                                                                                                                                                                         |
| `BOOTSTRAP_ADMIN_EMAIL`     | _(unset)_                            | optional; if set with password, `db:seed` creates a platform admin                                                                                                                                                                |
| `BOOTSTRAP_ADMIN_PASSWORD`  | _(unset)_                            | optional; bootstrap admin password; must pass the password rules (8+ chars, ≤72 bytes, not common); `change-me-please` is refused                                                                                                 |
| `ACCESS_TOKEN_TTL`          | `900`                                | access-token lifetime (seconds)                                                                                                                                                                                                   |
| `REFRESH_TOKEN_TTL`         | `2592000`                            | refresh-token lifetime (seconds)                                                                                                                                                                                                  |
| `REFRESH_TOKEN_REUSE_GRACE` | `30`                                 | seconds after a rotation during which replaying the old refresh token is refused without revoking the family (two tabs refreshing at once); `0` = every replay revokes it                                                         |
| `SSO_SESSION_TTL`           | `2592000`                            | SSO session lifetime (seconds)                                                                                                                                                                                                    |
| `AUTH_CODE_TTL`             | `60`                                 | authorization-code lifetime (seconds)                                                                                                                                                                                             |
| `EMAIL_VERIFICATION_TTL`    | `86400`                              | email-verification link lifetime (seconds)                                                                                                                                                                                        |
| `SMTP_HOST`                 | _(empty)_                            | the switch: set it to send over SMTP, leave empty for the log sender. `.env.example` sets `127.0.0.1` (Mailpit)                                                                                                                   |
| `SMTP_PORT`                 | `587`                                | `587` upgrades with STARTTLS, `465` needs `SMTP_SECURE=true`. `.env.example` sets `1025` (Mailpit)                                                                                                                                |
| `SMTP_USER`                 | _(empty)_                            | SMTP username; empty sends without auth (Mailpit needs none)                                                                                                                                                                      |
| `SMTP_PASS`                 | _(empty)_                            | SMTP password                                                                                                                                                                                                                     |
| `SMTP_SECURE`               | `false`                              | `true` for implicit TLS on connect (port 465)                                                                                                                                                                                     |
| `EMAIL_FROM`                | _(empty)_                            | sender address, e.g. `"tanod <no-reply@example.com>"`                                                                                                                                                                             |
| `EMAIL_LOG_LINKS`           | `false`                              | set `true` only in local dev; logs the verification link + address                                                                                                                                                                |
| `PRUNE_RETENTION`           | `2592000` (30d)                      | how long expired rows are kept before `db:prune` removes them; also the replay-detection window                                                                                                                                   |
| `ACCOUNT_PURGE_GRACE`       | `2592000` (30d)                      | how long a deleted account stays recoverable before `db:prune` erases it                                                                                                                                                          |
| `GOOGLE_CLIENT_ID`          | —                                    | Google OAuth client ID                                                                                                                                                                                                            |
| `GOOGLE_CLIENT_SECRET`      | —                                    | Google OAuth client secret                                                                                                                                                                                                        |
| `GOOGLE_REDIRECT_URI`       | `http://localhost:3000/oauth/google` | must equal the `/oauth/google` route                                                                                                                                                                                              |
| `GOOGLE_BIND_REDIRECT_URI`  | _(empty)_                            | `redirect_uri` for the server-auth-code exchange; empty sends none (native SDK). See [guest accounts](guest-accounts.md)                                                                                                          |
| `ALLOW_PASSWORD_GRANT`      | `false`                              | `true` accepts `grant_type=password` (RFC 9700 forbids it) and logs a warning at startup. Guests need it on; `.env.example` turns it on for local development                                                                     |
| `TOTP_ENCRYPTION_KEY`       | _(empty)_                            | seals TOTP secrets at rest (AES-256-GCM); `''` = no new setups; enrolled users are still asked for a code                                                                                                                         |
| `WEBAUTHN_RP_ID`            | _(empty)_                            | passkeys (WebAuthn) relying-party ID; `''` = passkeys off. Must equal the `JWT_ISSUER` host or a parent domain of it, or the server refuses to start                                                                              |
| `LOGIN_MAX_FAILURES`        | `10`                                 | consecutive failed passwords before an account stops accepting them                                                                                                                                                               |
| `LOGIN_LOCKOUT_MS`          | `900000` (15m)                       | how long that account refuses passwords; password reset stays available throughout                                                                                                                                                |
| `RATE_LIMIT_WINDOW_MS`      | `60000`                              | global limiter window                                                                                                                                                                                                             |
| `RATE_LIMIT_MAX`            | `100`                                | global limiter max requests/window                                                                                                                                                                                                |
| `GUEST_RATE_LIMIT`          | `10`                                 | per-IP max `POST /users/guest` creations per `RATE_LIMIT_WINDOW_MS`                                                                                                                                                               |
| `TRUST_PROXY`               | `0`                                  | number of trusted proxy hops; `0` ignores `X-Forwarded-For`                                                                                                                                                                       |

`TRUST_PROXY` must be the **exact** number of reverse proxies in front of this
service (`2` behind Cloudflare -> nginx, `0` when directly exposed). Proxies
append to `X-Forwarded-For`, so the client IP for rate limiting is read that
many entries from the right and everything to the left — which the caller can
forge — is ignored. Too low a count shares one rate-limit bucket between
clients; too high a count lets a caller pick its own bucket. Legacy
`true`/`false` still parse as `1`/`0`, and `true` logs a startup warning.

## Two-factor authentication (TOTP)

`TOTP_ENCRYPTION_KEY` seals every user's TOTP secret at rest (AES-256-GCM; a
TOTP secret cannot be hashed the way a password is — the server needs it back to
compute codes). Generate one with `openssl rand -base64 32`; it must decode to
exactly 32 bytes or the server fails to start. Leave it empty (`''`, the
default) and new two-factor setups are not offered — every `/users/me/totp*`
endpoint answers 404. Users who already enrolled are still asked for a code
(their recovery codes work), and an operator can reset them with
`DELETE /users/:id/totp`, which works with no key. Store it with the JWT keys:
it is as sensitive, and losing it has the same shape of consequence.

**Removing or changing this key while users have TOTP enabled fails closed.**
They are still asked for a code at sign-in (the account's `enabled_at` is
unaffected), but their authenticator app's codes no longer verify — the key that
sealed their secret is gone, so it cannot be opened. Their recovery codes still
work, since those are hashed, not sealed. An operator can get a locked-out user
back in with `DELETE /users/:id/totp` (see [API reference](api.md)), which
resets two-factor authentication so they can sign in with their password alone
and set it up again.

## Passkeys (WebAuthn)

`WEBAUTHN_RP_ID` is the relying-party ID: the domain a passkey is bound to.
Leave it empty (the default) and passkeys are off — the hosted login page shows
no passkey button or autofill, the offer page never appears, and the sign-in and
enrolment routes answer 404 `passkey_not_configured`. List and delete
(`GET`/`DELETE /users/me/passkeys/:id`) run `requireAuth` first, like every
other bearer-token route: a request with no valid access token gets 401
regardless of configuration, and only an authenticated one reaches the config
check and gets 404.

Set it to the `JWT_ISSUER` host itself, or a parent domain of it (e.g.
`JWT_ISSUER=https://auth.example.com` allows `auth.example.com` or
`example.com`); config loading throws on startup otherwise. The expected origin
for every ceremony is the issuer's origin, and there is no separate `rpName`
setting — the RP ID is used for both. WebAuthn requires https, with the usual
exception for `localhost`.

**Pick the final domain before turning this on: changing `WEBAUTHN_RP_ID` later
orphans every passkey already created under the old value** — a passkey is
cryptographically bound to the RP ID it was registered with, and there is no
migration for it. Users fall back to their password (or Google) and can enrol a
new passkey once the domain is fixed.

## Google OAuth

1. Create OAuth credentials in the Google Cloud Console.
2. Add `http://localhost:3000/oauth/google` as an authorized redirect URI.
3. Set `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, and `GOOGLE_REDIRECT_URI`.

With these set, the `/oauth/authorize` login page shows **Sign in with Google**.
Google login is part of the authorization code flow, not a separate way to get
tokens: the link carries the pending authorize request to `/oauth/google`, which
remembers it in a short-lived cookie and redirects to Google. On the way back
the user gets the same SSO session and `302` to `redirect_uri?code=…&state=…` as
after a password login, and the client exchanges the code as usual. The route
serves both legs, so its path must match `GOOGLE_REDIRECT_URI`.

A Google login is refused, back on the login page, when the Google email is
unverified or when a local account with that email has a password or an
unverified email (sign in with the password first). Cancelling at Google also
returns to the login page. Without `GOOGLE_CLIENT_ID` the button is hidden and
the route returns 404.

[← Back to README](../README.md)
