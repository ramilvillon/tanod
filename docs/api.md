# API reference

## Endpoints

| Method   | Path                                | Auth                               | Description                                                                                                                                  |
| -------- | ----------------------------------- | ---------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `GET`    | `/health`                           | —                                  | Liveness check                                                                                                                               |
| `POST`   | `/users`                            | —                                  | Register a user (no roles; roles are per-service, granted via the management API)                                                            |
| `POST`   | `/users/guest`                      | —                                  | Create a guest account for a `client_id` with `guestsEnabled`; returns a one-time username + password                                        |
| `POST`   | `/users/me/social-links`            | Bearer                             | Bind a Google account via a native-SDK server auth code                                                                                      |
| `GET`    | `/users/me`                         | Bearer                             | Current authenticated user                                                                                                                   |
| `GET`    | `/users`                            | Bearer + `users:list`              | List users                                                                                                                                   |
| `GET`    | `/users/:id`                        | Bearer, self or `users:read:any`   | Get a user                                                                                                                                   |
| `PATCH`  | `/users/:id`                        | Bearer, self or `users:update:any` | Update a user; a self-service `password` change requires `current_password`, and a self-service `email` change is held (202) until confirmed |
| `DELETE` | `/users/:id`                        | Bearer, self or `users:delete:any` | Delete a user                                                                                                                                |
| `POST`   | `/users/me/totp`                    | Bearer                             | Start two-factor (TOTP) setup; needs `current_password`; returns a new secret + `otpauth://` URI                                             |
| `POST`   | `/users/me/totp/confirm`            | Bearer                             | Confirm setup with a first code; turns two-factor on, returns 10 recovery codes (shown once)                                                 |
| `DELETE` | `/users/me/totp`                    | Bearer                             | Turn two-factor off; needs `code` or `recovery_code` as proof, throttled                                                                     |
| `DELETE` | `/users/:id/totp`                   | Bearer + `users:update:any`        | Reset a user's two-factor authentication (operator; lost device and codes)                                                                   |
| `GET`    | `/users/me/passkeys`                | Bearer                             | List your passkeys                                                                                                                           |
| `DELETE` | `/users/me/passkeys/:id`            | Bearer                             | Delete one of your passkeys                                                                                                                  |
| `GET`    | `/verify-email`                     | —                                  | Verify via emailed token                                                                                                                     |
| `POST`   | `/verify-email/resend`              | —                                  | Resend verification email (always 204)                                                                                                       |
| `POST`   | `/oauth/token`                      | —                                  | OAuth2 password, refresh, code, or client_credentials grant                                                                                  |
| `POST`   | `/oauth/revoke`                     | —                                  | Revoke a refresh token                                                                                                                       |
| `GET`    | `/oauth/google`                     | —                                  | Sign in with Google, linked from the authorize login page (redirect + return)                                                                |
| `GET`    | `/oauth/authorize`                  | —                                  | Start SSO; login form or 302 with `?code`                                                                                                    |
| `POST`   | `/oauth/authorize`                  | —                                  | Submit login; sets session, 302 with `?code` (or the code page, for a two-factor account)                                                    |
| `POST`   | `/oauth/authorize/totp`             | `auth_mfa` challenge cookie        | Submit a TOTP or recovery code to finish a two-factor sign-in; sets session, 302 with `?code`                                                |
| `POST`   | `/oauth/authorize/passkey/options`  | —                                  | Create a sign-in challenge for the hosted login page's passkey button/autofill                                                               |
| `POST`   | `/oauth/authorize/passkey`          | —                                  | Submit a passkey assertion to sign in; sets session, 302 with `?code`; skips the TOTP prompt                                                 |
| `GET`    | `/oauth/passkeys/dismiss`           | —                                  | "Not now" on the post-sign-in passkey offer; sets a 30-day dismiss cookie, then continues the authorize request                              |
| `POST`   | `/oauth/passkeys/register/options`  | SSO session cookie                 | Create an enrolment challenge for the passkey offer page                                                                                     |
| `POST`   | `/oauth/passkeys/register`          | SSO session cookie                 | Submit a passkey creation response; adds the passkey to the signed-in user                                                                   |
| `POST`   | `/oauth/logout`                     | session cookie                     | Revoke the SSO session                                                                                                                       |
| `GET`    | `/oauth/userinfo`                   | Bearer (user access token)         | OIDC UserInfo — identity claims for the token subject                                                                                        |
| `POST`   | `/oauth/userinfo`                   | Bearer (user access token)         | OIDC UserInfo — identity claims for the token subject                                                                                        |
| `GET`    | `/.well-known/jwks.json`            | —                                  | Public signing key (JWKS)                                                                                                                    |
| `GET`    | `/.well-known/openid-configuration` | —                                  | OIDC discovery document                                                                                                                      |
| `GET`    | `/openapi`                          | —                                  | OpenAPI 3 spec (JSON)                                                                                                                        |
| `GET`    | `/docs`                             | —                                  | Scalar API reference UI                                                                                                                      |

`POST /oauth/token` requires an `audience` (a service's `audience` string) on
the password and client_credentials grants; the returned access token carries
exactly the permissions that user has in that service. A request without it is
rejected with 400 `invalid_request`.

`/oauth/revoke` follows RFC 7009: the token goes in the **`token`** parameter
(`refresh_token` is still accepted), `token_type_hint` is accepted and ignored,
and success is **200** with an empty body — including for a token that is
unknown, already expired or already revoked, since the state the caller asked
for already holds.

Refresh tokens rotate: each use returns a new one and retires the old. Replaying
a retired token is treated as theft and revokes every refresh token the user
holds, except within `REFRESH_TOKEN_REUSE_GRACE` seconds (default 30) of its
rotation: then it is refused with `invalid_grant` and nothing else is revoked,
so two tabs refreshing at once do not sign the user out. The losing tab should
re-read the token the winning one stored.

`/oauth/token` and `/oauth/revoke` follow RFC 6749: they take
`application/x-www-form-urlencoded` bodies (what OAuth client libraries send),
and also accept JSON. A confidential client authenticates with HTTP Basic
(`client_secret_basic`, `Authorization: Basic base64(client_id:client_secret)`)
or with `client_id` + `client_secret` in the body (`client_secret_post`) — one
or the other, never both. That includes refreshing and revoking: a refresh token
issued to a confidential client can only be used or revoked with that same
client's credentials. Public clients send none. Their errors use the RFC's flat
shape rather than the envelope under [Errors](#errors), and token responses
carry `Cache-Control: no-store`.

Permission keys are defined per service, so the `users:*` permissions above
count only on a token minted for the reserved `platform` audience — the same key
granted inside a tenant service authorizes nothing on `/users`. Acting on your
own record (self) works with a token for any audience.

## The user representation

`GET /users`, `GET /users/:id`, `GET /users/me`, `POST /users` and
`PATCH /users/:id` all return the same shape:

```jsonc
{
  "id": "...",
  "email": "a@b.com", /* or null */
  "username": null, /* or "..." */
  "createdAt": "..."
}
```

Two fields changed with guest accounts, and a client parsing this strictly
should note both: **`email` is nullable** and **`username` was added**. Nothing
consumed the response before guests shipped, so no version of this document ever
described a non-nullable `email` — it is recorded here so the change is not
rediscovered as a bug.

The rule governing the two: **a username is assigned at creation and never
changes; an email can be filled in later.** Only `POST /users/guest` ever writes
a username, and no path assigns one to an existing row — so a non-null
`username` means the account was created as a guest, permanently. It does _not_
mean the account still lacks an address: a guest that binds Google has both.

|                            | `email`         | `username`  |
| -------------------------- | --------------- | ----------- |
| Registered                 | set at creation | always null |
| Guest, unbound             | null            | set         |
| Guest, after a Google bind | set             | set         |

### Login throttling

The global rate limiter is keyed on IP, which a password spray from many
addresses walks past: each address stays under the limit while one account takes
every guess. So tanod also counts **consecutive failed passwords per account**
(`LOGIN_MAX_FAILURES`, default 10). At the limit that account stops accepting
passwords for `LOGIN_LOCKOUT_MS` (default 15 minutes), the correct one included
— that is what makes it work. A successful login clears the count, so an account
in daily use never accumulates its way into a lockout.

A locked account answers exactly as it would for a wrong password. A distinct
error would be an enumeration oracle: failures are only counted for accounts
that exist, so "locked" would mean "this address is registered".

**Password reset still works while an account is locked**, which is the way back
in for someone locked out by another person's guessing.

**A two-factor (TOTP) account shares this same counter with wrong codes**, not a
separate one: a correct password alone does not clear it, only a login that
completes fully does — so entering the right password still leaves the account
locked if enough wrong TOTP codes came before or after it.

### Password rules

A password a person chooses — at registration, on a self-service change, or
through a reset — must be at least 8 characters, at most 72 bytes, and must not
appear in the bundled list of ~3,900 common passwords (matched
case-insensitively). Failures are 400 `weak_password` or 400
`password_too_long`.

The 72-byte ceiling is bcrypt's: past it the extra bytes are ignored, so two
long passwords sharing a prefix would authenticate each other. tanod refuses the
input rather than silently truncating it. Note the limit counts bytes, so one
emoji costs four.

A reset link is not consumed by a refused password: the rules are checked first,
so the user can submit a better one with the same link.

Any password change — a reset, a self-service change, or an operator setting one
with `PATCH /users/:id` — revokes every refresh token and session, deletes every
passkey, and invalidates every outstanding password-reset, email-change and
account-deletion link on the account. A link minted before the change (by
someone who had the mailbox or a stolen token) cannot be used after it.
Email-verification links are left alone.

Generated secrets — a guest account's password — skip these rules; they are
random, and a blocklist hit on one would be a false positive.

Addresses are matched **case-insensitively** — `casey@b.com` and `CASEY@b.com`
are the same account, so the second one cannot be registered and either spelling
signs in. They are stored as they were typed; mail always goes to the stored
spelling. The same rule decides whether an address is already taken on an email
change. An address longer than 255 characters is rejected with 400.

A guest's address is filled in by the bind (`POST /users/me/social-links`, which
adopts Google's address only when there is none — a user who already has one
keeps it), or by an operator holding `users:update:any`. The self-service
`PATCH` path cannot do it: the confirming link goes to the account's _current_
address, so an address-less account is refused with `account_has_no_email`, as
it is for self-service deletion.

Guest usernames are deliberately included on the operator-facing listings. They
are not a credential (the password is), and the routes already restrict who can
see them: `users:list` and `users:read:any` count only on the reserved
`platform` audience, so a tenant token reaches nothing but its own row. Removing
the field would leave an operator looking at a bare id with a null email and no
way to tell which account it is.

## Two-factor authentication (TOTP)

An account turns TOTP on through the API — there is no hosted settings page. It
is a property of the person, not of any one app: one flag covers every audience,
so turning it on while signed into app X means app Y asks for a code too on its
next hosted login. **Turning it on does not sign out sessions or refresh tokens
that already exist** — those keep working until they expire; only a hosted login
started afterwards is asked for a code.

All four routes require a Bearer token (`requireAuth`); a `client_credentials`
(service) token names no user and gets 404, as on `/users/me`. The three
`/users/me/totp*` routes also answer 404 `totp_not_configured` when
`TOTP_ENCRYPTION_KEY` is unset — two-factor setup is simply not offered. The
operator reset `DELETE /users/:id/totp` works with or without the key: it is the
way back in for users who enrolled before the key was removed.

| endpoint                      | body                                                    | success                                                                               | errors                                                                                                                                                                                                                                                                                                                                        |
| ----------------------------- | ------------------------------------------------------- | ------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `POST /users/me/totp`         | `{ current_password }` (omit for a Google-only account) | 200 `{ secret, otpauth_uri }`; creates or overwrites a pending (unconfirmed) setup    | 400 `current_password_required` · 401 `invalid_credentials` (wrong password), throttled with password changes — 429 after 5 per account · 403 `totp_guest_forbidden` (guest account) or `fresh_login_required` (Google-only account, token not from a sign-in in the last 5 minutes) · 404 `totp_not_configured` · 409 `totp_already_enabled` |
| `POST /users/me/totp/confirm` | `{ code }`                                              | 200 `{ recovery_codes: string[10] }`, shown once and never again; turns two-factor on | 400 `totp_invalid_code` · 404 `totp_not_pending` (or `totp_not_configured`) · 409 `totp_already_enabled`                                                                                                                                                                                                                                      |
| `DELETE /users/me/totp`       | exactly one of `{ code }` or `{ recovery_code }`        | 204; deletes the secret and every recovery code                                       | 400 neither or both sent · 401 `invalid_credentials` (wrong proof), throttled — 429 after 5 wrong proofs per account in the rate-limit window · 404 `totp_not_configured`                                                                                                                                                                     |
| `DELETE /users/:id/totp`      | —                                                       | 204; operator reset (idempotent)                                                      | 403 missing `users:update:any` on a platform-audience token                                                                                                                                                                                                                                                                                   |

**Google-only accounts** have no password to send. For them the proof is a
recent sign-in: send the user through `/oauth/authorize` with `prompt=login`
(which skips the SSO session and shows the sign-in page), exchange the code, and
call `POST /users/me/totp` with that new access token within 5 minutes. Tokens
from an authorization code carry `auth_time`; refreshed tokens do not, so they
never count as fresh.

A code is accepted once: right after confirming, wait for the next code before
signing in — the code used to confirm cannot also sign in.

`otpauth_uri` is
`otpauth://totp/<issuer host>:<email or username>?secret=…&issuer=<issuer host>&algorithm=SHA1&digits=6&period=30`
— draw it as a QR code client-side.

`DELETE /users/:id/totp` (the operator reset) needs `users:update:any` on a
**platform**-audience token; it is permission-only, not self-or-permission — a
user turning off their own two-factor goes through `DELETE /users/me/totp` and
presents proof instead. The permission gains no new power: its holder can
already change a user's email or trigger a password reset. It exists for someone
who lost both their device and their recovery codes; afterwards they sign in
with their password alone and set two-factor up again.

### Hosted flow

`GET`/`POST /oauth/authorize` are unchanged for an account without TOTP. For one
that has it on, the password form (or a Google sign-in) is followed by a code
page instead of a session: a signed **`auth_mfa`** challenge cookie (HttpOnly,
`SameSite=Lax`, path `/oauth`, 5-minute lifetime) records that the first factor
already succeeded, and the page carries the pending authorize request forward as
hidden fields.

`POST /oauth/authorize/totp` takes the same authorize parameters plus one `code`
field: six digits are read as a TOTP code, anything else as a recovery code. A
missing, expired, or otherwise invalid challenge cookie sends the user back to
the login page ("Your sign-in timed out. Please sign in again."). A wrong code
and a locked account render the **same** code-page message, so there is nothing
in the response to tell one from the other: "That code is not valid. Check your
authenticator app or use a recovery code. After too many attempts, sign-in
pauses for a while." A right code opens the session and continues exactly like a
password login: redirect to `redirect_uri` with `?code=…`.

An existing SSO session still skips the login form entirely on
`GET /oauth/authorize` — and so skips TOTP too — because it already passed the
check when it was created.

### The token endpoint

The password grant (`POST /oauth/token`) refuses a two-factor account outright.
Once the password checks out, it answers **400
`{"error":"mfa_required", "error_description":…}`** instead of a token pair — an
extension error code (RFC 6749 §5.2 allows them), distinct from `invalid_grant`
so a client library doesn't read it as "bad credentials, start over". It is
returned only after the password is correct, so it reveals nothing to someone
who does not already know it (the same reasoning as `email_not_verified`). A
client that sees `mfa_required` should send the user through the authorization
code flow (`GET /oauth/authorize`) instead, where the code page is available.
The refresh grant is unaffected: a refresh token proves a login that already
happened.

## Passkeys (WebAuthn)

A passkey is bound to tanod's own domain (the relying-party ID), so both
creating and using one has to run in a browser page tanod serves — this is not
an API-only feature the way TOTP is. Passkeys are off unless `WEBAUTHN_RP_ID` is
set (see [Configuration](configuration.md#passkeys-webauthn)); with it empty,
the login page shows no passkey UI, the sign-in and enrolment routes below
answer 404 `passkey_not_configured`, and the management routes (which require a
bearer token first) do too once authenticated — an unauthenticated call to them
still gets 401.

### Sign-in — the hosted login page

When passkeys are on, `GET /oauth/authorize`'s login page adds a **"Sign in with
a passkey"** button, hidden until an inline script confirms the browser supports
WebAuthn, and the email field gets `autocomplete="username webauthn"` so
supporting browsers also offer saved passkeys from the field's own autofill
dropdown (conditional UI). Both paths call
`POST /oauth/authorize/passkey/options` for a challenge, run
`navigator.credentials.get()`, then `POST /oauth/authorize/passkey` with the
assertion plus the pending authorize request. **A passkey sign-in counts as its
own factor and skips the TOTP prompt**; every other sign-in gate still applies
(account exists and is not soft-deleted, `REQUIRE_EMAIL_VERIFICATION`). On
success: session cookie, 302 to `redirect_uri?code=…`, exactly like a password
sign-in. Any failure — unknown credential, bad signature, an
expired/already-used challenge — is the single `passkey_invalid` (401); the page
re-renders with "That passkey couldn't be used." A script request (no
`text/html` in `Accept`) gets the JSON error instead.

`POST /oauth/authorize/passkey/options` has its own rate budget (30 per IP per
window, separate from the login limiter) since a passkey-aware page can call it
on every load for conditional UI, before anyone has typed anything;
`POST /oauth/authorize/passkey` shares the strict login limiter with the
password and TOTP routes.

### Enrolment — the offer page

Right after a **password, TOTP, or Google** sign-in (not after a passkey
sign-in) `finishHostedLogin` shows an offer page — "Sign in faster next time
with a passkey" — instead of redirecting straight away, unless the browser
already carries an `auth_passkey_offer=dismissed` cookie. **Not now**
(`GET /oauth/passkeys/dismiss`) sets that cookie for 30 days and continues.
**Create passkey** calls `POST /oauth/passkeys/register/options`, runs
`navigator.credentials.create()`, then `POST /oauth/passkeys/register`; either
way the browser is sent on to `GET /oauth/authorize` with the same params
(`prompt` removed), which reuses the session that was just created and issues
the code — enrolling never issues a code by itself.

An app that wants an explicit **"Add passkey"** entry point (rather than waiting
for the next sign-in) sends the user through the ordinary authorize URL with
`prompt=login&passkey=add` added: `prompt=login` forces the sign-in page even
with an active SSO session (its ordinary OIDC meaning — it does nothing to the
offer by itself); `passkey=add` is what makes the offer appear afterwards
regardless of a dismiss cookie. Both are stripped from the continue/dismiss
links so they do not linger past the one sign-in they were meant for. The offer
is still skipped for an account already at the passkey limit.

The two register routes require the SSO session cookie plus CSRF, and the
session's sign-in must be **under 5 minutes old** (403 `fresh_login_required`
otherwise — the same step-up window as TOTP enrolment). Refused at 20 passkeys
per account (409 `passkey_limit_reached`); a duplicate credential is 409
`passkey_already_registered`.

### Management

| endpoint                        | success                                                     | errors                     |
| ------------------------------- | ----------------------------------------------------------- | -------------------------- |
| `GET /users/me/passkeys`        | 200 `[{ id, created_at, last_used_at, backed_up, aaguid }]` | 404 not configured         |
| `DELETE /users/me/passkeys/:id` | 204                                                         | 404 not theirs / not found |

Bearer token; a `client_credentials` (service) token names no user and gets 404,
like `/users/me`. The public key is never returned. `aaguid` identifies the
authenticator model (iCloud Keychain, Google Password Manager, a hardware key…)
from the public community AAGUID list — tanod ships no name map, so mapping it
to a display name is left to the caller. Delete needs only the bearer token: a
stolen token can remove a passkey, but that only removes a convenience — the
password or Google sign-in it was created after still works. A password reset or
a self-service password change deletes every passkey on the account: both are
what someone reaches for because they believe the account is compromised, and a
passkey enrolled under the old credentials must not outlive them.

### Errors

- `passkey_not_configured` — 404, `WEBAUTHN_RP_ID` is unset
- `passkey_invalid` — 401, covers every sign-in verification failure
- `passkey_limit_reached` — 409, 20 passkeys already on the account
- `passkey_already_registered` — 409, duplicate credential
- `passkey_not_found` — 404, delete of a passkey that isn't yours or doesn't
  exist
- `fresh_login_required` — 403, the session's sign-in is more than 5 minutes old

### Native apps

tanod has no native WebAuthn integration (no associated-domains setup). A native
app gets passkeys the same way it gets any other hosted sign-in: run
`GET /oauth/authorize` inside `ASWebAuthenticationSession` (iOS) or a Custom Tab
(Android) rather than an embedded webview — both support passkeys backed by the
OS credential manager, and the redirect back to the app carries the code exactly
as it does for a password or Google sign-in.

## Management API

These routes require a Bearer token minted for the reserved `platform` audience
(`requireAuth` + `requirePlatform`) plus the listed permission.

| Method   | Path                                       | Permission       | Description                                                  |
| -------- | ------------------------------------------ | ---------------- | ------------------------------------------------------------ |
| `POST`   | `/orgs`                                    | `orgs:write`     | Create an organization                                       |
| `GET`    | `/orgs`                                    | `orgs:read`      | List organizations                                           |
| `GET`    | `/orgs/:id`                                | `orgs:read`      | Get an organization                                          |
| `POST`   | `/orgs/:id/services`                       | `services:write` | Register a service (one-time secret)                         |
| `GET`    | `/orgs/:id/services`                       | `services:read`  | List an org's services                                       |
| `PATCH`  | `/services/:id`                            | `services:write` | Update a service's `name`, `redirectUris` or `guestsEnabled` |
| `POST`   | `/orgs/:id/members`                        | `members:write`  | Add a member                                                 |
| `DELETE` | `/orgs/:id/members/:userId`                | `members:write`  | Remove a member                                              |
| `POST`   | `/services/:id/roles`                      | `rbac:write`     | Create a role for a service                                  |
| `POST`   | `/services/:id/permissions`                | `rbac:write`     | Create a permission for a service                            |
| `POST`   | `/roles/:id/permissions`                   | `rbac:write`     | Grant a permission to a role                                 |
| `POST`   | `/users/:userId/roles`                     | `rbac:write`     | Assign a role to a user                                      |
| `POST`   | `/clients/:clientId/roles`                 | `rbac:write`     | Grant a role to a client (M2M principal)                     |
| `GET`    | `/services/:id/roles`                      | `rbac:read`      | List a service's roles, each with its permissions inlined    |
| `GET`    | `/services/:id/permissions`                | `rbac:read`      | List a service's permissions                                 |
| `GET`    | `/users/:userId/roles`                     | `rbac:read`      | List the roles a user holds                                  |
| `GET`    | `/clients/:clientId/roles`                 | `rbac:read`      | List the roles a client holds                                |
| `DELETE` | `/roles/:roleId/permissions/:permissionId` | `rbac:write`     | Revoke a permission from a role                              |
| `DELETE` | `/users/:userId/roles/:roleId`             | `rbac:write`     | Unassign a role from a user                                  |
| `DELETE` | `/clients/:clientId/roles/:roleId`         | `rbac:write`     | Unassign a role from a client                                |

Setting `BOOTSTRAP_ADMIN_EMAIL`/`BOOTSTRAP_ADMIN_PASSWORD` before
`deno task
db:seed` creates that user as a platform `admin`. Both are empty in
`.env.example`, so pick your own values; `db:seed` aborts if the password is
still the `change-me-please` placeholder older templates shipped. Get an admin
token with a password grant for `audience: "platform"`.

The password grant is on by default for compatibility, but RFC 9700 (the OAuth
2.0 Security BCP) says it MUST NOT be used: the client handles the user's
password, and there is no page on which to add MFA or consent. New clients
should use the authorization code flow with PKCE. It is off by default:
`/oauth/token` refuses it with `unsupported_grant_type` and discovery omits it
unless `ALLOW_PASSWORD_GRANT=true`.

Example password-grant flow (`username` accepts a registered user's email or a
guest's generated username):

```bash
# obtain a token pair (form-encoded, as RFC 6749 specifies; JSON also works)
curl -X POST localhost:3000/oauth/token \
  -d grant_type=password -d username=a@b.com -d password=pw123456 \
  -d audience=platform

# call a protected route
curl localhost:3000/users/me -H "authorization: Bearer <access_token>"
```

### Revoking

The three `DELETE`s are idempotent: they answer 204 whether or not the grant was
there, because the state the caller asked for — that grant does not exist —
holds either way. The `GET`s 404 an unknown service id, which is a wrong id
rather than an empty answer.

**A revoke only affects tokens minted afterwards.** Permissions are read at
issuance and written into the access token's `scope`, so a token already in a
client's hands keeps what it was given until it expires (`ACCESS_TOKEN_TTL`, 15
minutes by default). Revoke the refresh token too if you need to cut access off
sooner.

Roles and permissions themselves cannot be deleted through the API — only
created, granted and revoked. Deleting a row that grants still reference needs a
cascade decision that has not been made.

Note `:id` on the service routes and `:clientId` on the client routes are the
service row's **UUID**, not its OAuth `client_id` string.

## Authorization Code + PKCE (SSO)

1. Client generates a `code_verifier` and
   `code_challenge = base64url(sha256(verifier))`.
2. Browser hits
   `GET /oauth/authorize?client_id=…&redirect_uri=…&code_challenge=…&code_challenge_method=S256&state=…`.
3. No session → login form (password, or Sign in with Google); on success the
   server sets an SSO session cookie and `302`s back to
   `redirect_uri?code=…&state=…`. An existing session skips the form.
4. Client exchanges the code:

```bash
curl -X POST localhost:3000/oauth/token \
  -d grant_type=authorization_code -d code=<code> -d redirect_uri=<uri> \
  -d code_verifier=<verifier> -d client_id=<client_id>
```

Confidential clients also send `client_secret`. Only PKCE `S256` is supported.

## OIDC

To get an `id_token`, include `openid` (plus any of `email`, `profile`) in the
authorization request scope:

```
GET /oauth/authorize?client_id=…&redirect_uri=…&scope=openid+email+profile
  &code_challenge=…&code_challenge_method=S256&state=…&nonce=<nonce>
```

`prompt=login` makes the user sign in again even when an SSO session exists
(other `prompt` values are ignored). Access tokens from the code exchange carry
the sign-in time as `auth_time`, as the `id_token` does.

The token exchange (`grant_type=authorization_code`) returns the usual access
token plus an `id_token` — a signed JWT whose `aud` is the `client_id`. The
`id_token` carries the claims for the granted scopes.

**UserInfo** — `/oauth/userinfo` accepts the user access token and returns the
same claims:

```bash
curl localhost:3000/oauth/userinfo \
  -H "authorization: Bearer <access_token>"
```

Profile claims (`name`, `given_name`, `family_name`, `picture`) are sourced from
the user's profile fields, which can be set via `PATCH /users/:id`.
`email_verified` reflects whether the user has clicked the verification link; it
is surfaced in both the id_token and the UserInfo response.

## Email verification

Registration triggers a verification email. With `SMTP_HOST` set it is sent over
SMTP (locally, to Mailpit); with it empty the log sender only records that a
mail was sent — the link embeds a live verification token and is never logged
unless you set `EMAIL_LOG_LINKS=true` in your `.env` for local development.
Clicking the link sets `email_verified: true`, which is surfaced in the OIDC
id_token and UserInfo endpoint. The resend endpoint
(`POST /verify-email/resend`) is anti-enumeration — it always returns 204
regardless of whether the address exists or is already verified. Changing a
user's email resets `email_verified` to false. An account created by Google
login starts verified: that path refuses an unverified Google email, so the
address is already proven and no link is sent. Verification is non-blocking: it
does not gate login.

## Key rotation

Generate a new pair (`deno task keys:gen`) → set it as
`JWT_PRIVATE_KEY`/`JWT_PUBLIC_KEY`, move the old public PEM into
`JWT_PREVIOUS_PUBLIC_KEYS` (JSON array) → deploy. Both keys appear in JWKS so
verifiers pick by `kid`; drop the retired public key after the access-token TTL
elapses.

## M2M (client_credentials)

```bash
curl -X POST localhost:3000/oauth/token -u '<cid>:<secret>' \
  -d grant_type=client_credentials -d audience=<target-audience>
```

## Errors

Every endpoint except the two token endpoints (below) uses one envelope:

```json
{ "error": { "code": "<machine_code>", "message": "..." } }
```

The HTTP status reflects the error class (400 / 401 / 403 / 404 / 409 / 429).
Every rate limiter answers 429 `rate_limited` with a `Retry-After` header.
`code` is a stable machine-readable identifier from the catalogue in
`src/lib/errors.ts` (e.g. `invalid_grant`, `user_not_found`, `email_taken`).
Clients should branch on `code`, not on the human-readable `message` — messages
may be revised without a version bump; codes are stable.

### Token endpoint errors (RFC 6749)

`POST /oauth/token` and `POST /oauth/revoke` answer in the flat shape RFC 6749
section 5.2 defines, because OAuth client libraries parse `error` as a string:

```json
{
  "error": "invalid_grant",
  "error_description": "refresh token reuse detected"
}
```

| `error`                  | status | when                                                                                                                                                 |
| ------------------------ | ------ | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| `invalid_request`        | 400    | a parameter is missing or malformed, or the body is neither form-encoded nor JSON                                                                    |
| `unsupported_grant_type` | 400    | `grant_type` is not `password`, `refresh_token`, `authorization_code` or `client_credentials`                                                        |
| `invalid_grant`          | 400    | wrong credentials; an unknown, expired, revoked or replayed refresh token or code; the user is not a member of the service's org                     |
| `invalid_target`         | 400    | the `audience` names no service (RFC 8707)                                                                                                           |
| `mfa_required`           | 400    | the password grant's credentials were correct, but the account has two-factor authentication on; sign in through the authorization code flow instead |
| `invalid_client`         | 401    | client authentication failed; carries `WWW-Authenticate: Basic` when the client used HTTP Basic                                                      |
| `rate_limited`           | 429    | too many requests from this address; `Retry-After` gives the seconds to wait (not an RFC 6749 code: the RFC defines none for rate limiting)          |

`error_description` carries the catalogue message, so the specific reason (for
example reuse detection) stays readable. Branch on `error`.

## Type-safe RPC client

`src/client.ts` exports an `hc<AppType>` client typed by the live route tree.
Import it from another Deno/TypeScript project to call the API with full
inference on paths, params, and response bodies.

[← Back to README](../README.md)
