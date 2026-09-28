import { assertEquals, assertStringIncludes, assertThrows } from '@std/assert'
import {
  insecureGoogleRedirectWarning,
  loadConfig,
  passwordGrantWarning,
  unverifiableEmailWarning,
} from '../../src/config.ts'

const base = {
  PORT: '3000',
  LOG_LEVEL: 'info',
  DB_HOST: 'localhost',
  DB_PORT: '3306',
  DB_USER: 'app',
  DB_PASS: 'app',
  DB_NAME: 'app',
  JWT_PRIVATE_KEY: 'pk',
  JWT_PUBLIC_KEY: 'pub',
  JWT_ISSUER: 'http://localhost:3000',
  ACCESS_TOKEN_TTL: '900',
  REFRESH_TOKEN_TTL: '2592000',
  GOOGLE_CLIENT_ID: 'gid',
  GOOGLE_CLIENT_SECRET: 'gsecret',
  GOOGLE_REDIRECT_URI: 'http://localhost:3000/oauth/google/callback',
  RATE_LIMIT_WINDOW_MS: '60000',
  RATE_LIMIT_MAX: '100',
}

Deno.test('loadConfig parses and coerces env', () => {
  const cfg = loadConfig(base)
  assertEquals(cfg.port, 3000)
  assertEquals(cfg.accessTokenTtl, 900)
  assertEquals(cfg.db, {
    host: 'localhost',
    port: 3306,
    user: 'app',
    password: 'app',
    name: 'app',
    ssl: false,
  })
})

Deno.test('loadConfig throws on missing DB_NAME', () => {
  const { DB_NAME: _omit, ...partial } = base
  assertThrows(() => loadConfig(partial), Error, 'DB_NAME')
})

Deno.test('loadConfig throws on missing required value', () => {
  const { JWT_PRIVATE_KEY: _omit, ...partial } = base
  assertThrows(() => loadConfig(partial), Error, 'JWT_PRIVATE_KEY')
})

Deno.test('loadConfig defaults SSO + auth-code TTLs', () => {
  const cfg = loadConfig({
    DB_USER: 'app',
    DB_NAME: 'app',
    JWT_PRIVATE_KEY: 'x',
    JWT_PUBLIC_KEY: 'y',
    JWT_ISSUER: 'http://t',
  })
  assertEquals(cfg.ssoSessionTtl, 2592000)
  assertEquals(cfg.authCodeTtl, 60)
})

Deno.test('loadConfig parses JWT_PREVIOUS_PUBLIC_KEYS (defaults to [])', () => {
  const base = {
    DB_USER: 'app',
    DB_NAME: 'app',
    JWT_PRIVATE_KEY: 'x',
    JWT_PUBLIC_KEY: 'y',
    JWT_ISSUER: 'http://t',
  }
  assertEquals(loadConfig(base).jwtPreviousPublicKeys, [])
  assertEquals(
    loadConfig({ ...base, JWT_PREVIOUS_PUBLIC_KEYS: '["pemA","pemB"]' })
      .jwtPreviousPublicKeys,
    ['pemA', 'pemB'],
  )
})

Deno.test('loadConfig parses TRUST_PROXY as a hop count', () => {
  assertEquals(loadConfig(base).trustProxyHops, 0)
  assertEquals(loadConfig({ ...base, TRUST_PROXY: '2' }).trustProxyHops, 2)
  // legacy booleans stay accepted
  assertEquals(loadConfig({ ...base, TRUST_PROXY: 'false' }).trustProxyHops, 0)
  assertEquals(loadConfig({ ...base, TRUST_PROXY: 'true' }).trustProxyHops, 1)
  assertThrows(
    () => loadConfig({ ...base, TRUST_PROXY: '-1' }),
    Error,
    'TRUST_PROXY',
  )
  assertThrows(
    () => loadConfig({ ...base, TRUST_PROXY: 'yes' }),
    Error,
    'TRUST_PROXY',
  )
})

Deno.test('loadConfig defaults EMAIL_VERIFICATION_TTL', () => {
  const cfg = loadConfig({
    DB_USER: 'app',
    DB_NAME: 'app',
    JWT_PRIVATE_KEY: 'x',
    JWT_PUBLIC_KEY: 'y',
    JWT_ISSUER: 'http://t',
  })
  assertEquals(cfg.emailVerificationTtl, 86400)
})

Deno.test('insecureGoogleRedirectWarning flags only plain-http non-localhost redirect URIs', () => {
  // Fine: https anywhere, and the two hosts browsers treat as trustworthy.
  for (
    const ok of [
      '',
      'https://auth.example.com/oauth/google',
      'http://localhost:3000/oauth/google',
      'http://127.0.0.1:3000/oauth/google',
    ]
  ) {
    assertEquals(insecureGoogleRedirectWarning(ok), null, ok)
  }

  // Broken: the browser drops the Secure state cookie, so every callback 401s.
  const warning = insecureGoogleRedirectWarning(
    'http://staging.internal/oauth/google',
  )
  assertStringIncludes(warning ?? '', 'staging.internal')
  assertStringIncludes(warning ?? '', '401')

  assertStringIncludes(
    insecureGoogleRedirectWarning('not-a-url') ?? '',
    'not a valid URL',
  )
})

// The default is the whole promise of making this configurable: an existing
// deployment that sets nothing must send exactly the request it sent before.
// Empty means the parameter is omitted entirely, which is not the same wire
// request as sending an empty one -- see exchangeGoogleAuthCode.
Deno.test('GOOGLE_BIND_REDIRECT_URI defaults to empty and is independent of the browser leg', () => {
  assertEquals(loadConfig(base).google.bindRedirectUri, '')
  // Setting the browser leg's URI must not set this one. Those two being
  // confused is the bug this endpoint originally shipped with.
  assertEquals(
    loadConfig({ ...base, GOOGLE_REDIRECT_URI: 'https://a.test/cb' })
      .google.bindRedirectUri,
    '',
  )
  assertEquals(
    loadConfig({ ...base, GOOGLE_BIND_REDIRECT_URI: 'postmessage' })
      .google.bindRedirectUri,
    'postmessage',
  )
})

Deno.test('REQUIRE_EMAIL_VERIFICATION is off unless set to true', () => {
  assertEquals(loadConfig(base).requireEmailVerification, false)
  assertEquals(
    loadConfig({ ...base, REQUIRE_EMAIL_VERIFICATION: 'true' })
      .requireEmailVerification,
    true,
  )
})

Deno.test('unverifiableEmailWarning fires only when the gate is on and no email can go out', () => {
  const w = (
    requireEmailVerification: boolean,
    smtpHost: string,
    emailLogLinks: boolean,
  ) =>
    unverifiableEmailWarning({
      requireEmailVerification,
      smtpHost,
      emailLogLinks,
    })
  assertEquals(w(false, '', false), null, 'gate off')
  assertEquals(w(true, 'smtp.example.test', false), null, 'SMTP configured')
  assertEquals(w(true, '', true), null, 'links logged for local development')
  assertStringIncludes(w(true, '', false) ?? '', 'REQUIRE_EMAIL_VERIFICATION')
})

Deno.test('ALLOW_PASSWORD_GRANT is off unless set to true, and warns while on', () => {
  assertEquals(loadConfig(base).allowPasswordGrant, false)
  assertEquals(
    loadConfig({ ...base, ALLOW_PASSWORD_GRANT: 'true' }).allowPasswordGrant,
    true,
  )
  assertStringIncludes(passwordGrantWarning(true) ?? '', 'RFC 9700')
  assertEquals(passwordGrantWarning(false), null)
})

Deno.test('TOTP_ENCRYPTION_KEY defaults to empty (TOTP off)', () => {
  assertEquals(loadConfig(base).totpEncryptionKey, '')
})

Deno.test('TOTP_ENCRYPTION_KEY accepts base64 of exactly 32 bytes', () => {
  const key = btoa(String.fromCharCode(...new Uint8Array(32).fill(3)))
  assertEquals(
    loadConfig({ ...base, TOTP_ENCRYPTION_KEY: key }).totpEncryptionKey,
    key,
  )
})

Deno.test('TOTP_ENCRYPTION_KEY refuses the wrong length and non-base64', () => {
  const short = btoa(String.fromCharCode(...new Uint8Array(16)))
  for (const bad of [short, 'not base64!!']) {
    assertThrows(
      () => loadConfig({ ...base, TOTP_ENCRYPTION_KEY: bad }),
      Error,
      'TOTP_ENCRYPTION_KEY',
    )
  }
})

Deno.test('WEBAUTHN_RP_ID unset leaves passkeys off', () => {
  assertEquals(loadConfig(base).webauthn, {
    rpId: '',
    origin: 'http://localhost:3000',
  })
})

Deno.test('WEBAUTHN_RP_ID may be the issuer host or a parent of it', () => {
  const issuer = { ...base, JWT_ISSUER: 'https://auth.example.com' }
  assertEquals(
    loadConfig({ ...issuer, WEBAUTHN_RP_ID: 'auth.example.com' }).webauthn,
    { rpId: 'auth.example.com', origin: 'https://auth.example.com' },
  )
  assertEquals(
    loadConfig({ ...issuer, WEBAUTHN_RP_ID: 'example.com' }).webauthn.rpId,
    'example.com',
  )
})

Deno.test('WEBAUTHN_RP_ID that is not the issuer host or a parent is refused', () => {
  const issuer = { ...base, JWT_ISSUER: 'https://auth.example.com' }
  for (const rpId of ['other.com', 'ample.com', 'evil.auth.example.com']) {
    assertThrows(
      () => loadConfig({ ...issuer, WEBAUTHN_RP_ID: rpId }),
      Error,
      'WEBAUTHN_RP_ID',
    )
  }
})

// The DB connection carries password hashes and the DB login: plaintext only
// where there is no network in between, and TLS always verifies the server.
const verified = { rejectUnauthorized: true, verifyIdentity: true } as const

Deno.test('DB TLS is off by default for loopback hosts only', () => {
  for (const DB_HOST of ['localhost', '127.0.0.1', '::1']) {
    assertEquals(loadConfig({ ...base, DB_HOST }).db.ssl, false)
  }
  assertEquals(
    loadConfig({ ...base, DB_HOST: 'db.internal' }).db.ssl,
    verified,
    'a remote host must default to verified TLS',
  )
})

Deno.test('DB_SSL overrides the default, and an empty value means unset', () => {
  assertEquals(loadConfig({ ...base, DB_SSL: 'required' }).db.ssl, verified)
  assertEquals(
    loadConfig({ ...base, DB_HOST: 'db.internal', DB_SSL: 'off' }).db.ssl,
    false,
  )
  assertEquals(
    loadConfig({ ...base, DB_HOST: 'db.internal', DB_SSL: '' }).db.ssl,
    verified,
  )
  assertThrows(() => loadConfig({ ...base, DB_SSL: 'yes' }), Error, 'DB_SSL')
})

Deno.test('DB_SSL_CA is passed through for a private CA', () => {
  assertEquals(
    loadConfig({ ...base, DB_HOST: 'db.internal', DB_SSL_CA: 'PEM' }).db.ssl,
    { ca: 'PEM', ...verified },
  )
})

// mysql2 never checks a certificate against an IP, so TLS to one would verify
// the CA but not whose server answered.
Deno.test('DB TLS to an IP address is refused', () => {
  assertThrows(
    () => loadConfig({ ...base, DB_HOST: '10.0.0.5' }),
    Error,
    'not an IP address',
  )
  assertThrows(
    () => loadConfig({ ...base, DB_HOST: '127.0.0.1', DB_SSL: 'required' }),
    Error,
    'not an IP address',
  )
  assertEquals(
    loadConfig({ ...base, DB_HOST: '10.0.0.5', DB_SSL: 'off' }).db.ssl,
    false,
  )
})
