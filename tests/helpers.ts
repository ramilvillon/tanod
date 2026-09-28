import type { Deps } from '../src/deps.ts'
import { testDb } from './mysql-mode.ts'
import { createDrizzleUserRepository } from '../src/modules/users/users.repository.drizzle.ts'
import { createDrizzleRefreshTokenRepository } from '../src/modules/auth/token.repository.drizzle.ts'
import { createDrizzleSocialAccountRepository } from '../src/modules/auth/social.repository.drizzle.ts'
import { createDrizzleOrgRepository } from '../src/modules/orgs/orgs.repository.drizzle.ts'
import { createDrizzleRbacRepository } from '../src/modules/rbac/rbac.repository.drizzle.ts'
import { createDrizzleSessionRepository } from '../src/modules/auth/session.repository.drizzle.ts'
import { createDrizzleAuthCodeRepository } from '../src/modules/auth/authcode.repository.drizzle.ts'
import { createDrizzleVerificationTokenRepository } from '../src/modules/verification/verification.repository.drizzle.ts'
import type { UserRepository } from '../src/modules/users/users.repository.ts'
import { createApp } from '../src/app.ts'
import { PLATFORM_PERMISSIONS as CATALOGUE_PERMISSIONS } from '../src/db/rbac-constants.ts'
import { loadConfig } from '../src/config.ts'
import { createInMemoryUserRepository } from '../src/modules/users/users.repository.ts'
import { createInMemoryRefreshTokenRepository } from '../src/modules/auth/token.repository.ts'
import { createInMemoryOrgRepository } from '../src/modules/orgs/orgs.repository.ts'
import { createInMemoryRbacRepository } from '../src/modules/rbac/rbac.repository.ts'
import { createInMemorySessionRepository } from '../src/modules/auth/session.repository.ts'
import { createInMemoryAuthCodeRepository } from '../src/modules/auth/authcode.repository.ts'
import { createInMemoryVerificationTokenRepository } from '../src/modules/verification/verification.repository.ts'
import { createInMemoryTotpRepository } from '../src/modules/mfa/totp.repository.ts'
import { createDrizzleTotpRepository } from '../src/modules/mfa/totp.repository.drizzle.ts'
import { createTotpService } from '../src/modules/mfa/totp.service.ts'
import { createInMemoryPasskeyRepository } from '../src/modules/passkeys/passkey.repository.ts'
import { createDrizzlePasskeyRepository } from '../src/modules/passkeys/passkey.repository.drizzle.ts'
import { createPasskeyService } from '../src/modules/passkeys/passkey.service.ts'
import { currentStep, fromBase32, hotp } from '../src/lib/totp.ts'
import { createVerificationService } from '../src/modules/verification/verification.service.ts'
import { createUserService } from '../src/modules/users/users.service.ts'
import { createAuthService } from '../src/modules/auth/auth.service.ts'
import { createAdminService } from '../src/modules/admin/admin.service.ts'
import { createMemoryRateLimitStore } from '../src/lib/rate-limit-store.ts'
import {
  createInMemorySocialAccountRepository,
  type SocialAccountRepository,
} from '../src/modules/auth/social.repository.ts'
import type { TokenPurpose } from '../src/modules/verification/verification.repository.ts'
import type { OrgRepository } from '../src/modules/orgs/orgs.repository.ts'
import type { RbacRepository } from '../src/modules/rbac/rbac.repository.ts'
import { generateRsaKeyPairPem, loadKeyRing } from '../src/lib/keys.ts'
import { signAccessToken } from '../src/lib/jwt.ts'
import type { Logger } from '../src/lib/logger.ts'

const { privateKeyPem, publicKeyPem } = await generateRsaKeyPairPem()
export const keySet = await loadKeyRing(privateKeyPem, publicKeyPem, [])

// A fixed key: tests that need TOTP off override it with ''.
export const TEST_TOTP_KEY = btoa(
  String.fromCharCode(...new Uint8Array(32).fill(7)),
)

// A stand-in for pino's Logger -- these tests never assert on log output,
// they just need something with an `.error` method to satisfy
// exchangeGoogleAuthCode's signature.
const testLogger = { error: () => {} } as unknown as Logger

const testEnv = {
  DB_USER: 'app',
  DB_PASS: 'app',
  DB_NAME: 'app',
  JWT_PRIVATE_KEY: privateKeyPem,
  JWT_PUBLIC_KEY: publicKeyPem,
  JWT_ISSUER: 'http://test.local',
  LOG_LEVEL: 'silent',
  TOTP_ENCRYPTION_KEY: TEST_TOTP_KEY,
  // Off by default in the app; most suites sign in through it (and guests
  // need it), so tests opt in. The default itself is pinned in config.test.ts.
  ALLOW_PASSWORD_GRANT: 'true',
}

export type TestContext = {
  deps: Deps
  userRepo: ReturnType<typeof createInMemoryUserRepository>
  tokenRepo: ReturnType<typeof createInMemoryRefreshTokenRepository>
  sessionRepo: ReturnType<typeof createInMemorySessionRepository>
  authCodeRepo: ReturnType<typeof createInMemoryAuthCodeRepository>
  verificationRepo: ReturnType<typeof createInMemoryVerificationTokenRepository>
  socialRepo: SocialAccountRepository
  orgRepo: ReturnType<typeof createInMemoryOrgRepository>
  rbacRepo: ReturnType<typeof createInMemoryRbacRepository>
  totpRepo: ReturnType<typeof createInMemoryTotpRepository>
  passkeyRepo: ReturnType<typeof createInMemoryPasskeyRepository>
  sentEmails: { to: string; purpose: TokenPurpose; link: string }[]
}

export function makeTestDeps(
  envOverrides: Record<string, string> = {},
): TestContext {
  const config = loadConfig({ ...testEnv, ...envOverrides })
  const userRepo = testDb
    ? createDrizzleUserRepository(testDb)
    : createInMemoryUserRepository()
  const tokenRepo = testDb
    ? createDrizzleRefreshTokenRepository(testDb)
    : createInMemoryRefreshTokenRepository()
  const orgRepo = testDb
    ? createDrizzleOrgRepository(testDb)
    : createInMemoryOrgRepository()
  const rbacRepo = testDb
    ? createDrizzleRbacRepository(testDb)
    : createInMemoryRbacRepository()
  const sessionRepo = testDb
    ? createDrizzleSessionRepository(testDb)
    : createInMemorySessionRepository()
  const authCodeRepo = testDb
    ? createDrizzleAuthCodeRepository(testDb)
    : createInMemoryAuthCodeRepository()
  const verificationRepo = testDb
    ? createDrizzleVerificationTokenRepository(testDb)
    : createInMemoryVerificationTokenRepository()
  const sentEmails: { to: string; purpose: TokenPurpose; link: string }[] = []
  const emailSender = {
    sendLink(to: string, purpose: TokenPurpose, link: string) {
      sentEmails.push({ to, purpose, link })
      return Promise.resolve()
    },
  }
  const socialRepo = testDb
    ? createDrizzleSocialAccountRepository(testDb)
    : createInMemorySocialAccountRepository()
  const totpRepo = testDb
    ? createDrizzleTotpRepository(testDb)
    : createInMemoryTotpRepository()
  const passkeyRepo = testDb
    ? createDrizzlePasskeyRepository(testDb)
    : createInMemoryPasskeyRepository()
  const verificationService = createVerificationService({
    verificationRepo,
    userRepo,
    tokenRepo,
    sessionRepo,
    passkeyRepo,
    emailSender,
    config,
  })
  const totpService = createTotpService({
    totpRepo,
    userRepo,
    issuer: config.issuer,
    encryptionKey: config.totpEncryptionKey,
  })
  const passkeyService = createPasskeyService({
    passkeyRepo,
    userRepo,
    rpId: config.webauthn.rpId,
    origin: config.webauthn.origin,
  })
  const deps: Deps = {
    config,
    keySet,
    rateStore: createMemoryRateLimitStore(),
    userService: createUserService({
      repo: userRepo,
      tokenRepo,
      sessionRepo,
      authCodeRepo,
      verificationRepo,
      socialRepo,
      orgRepo,
      totpRepo,
      passkeyRepo,
      allowPasswordGrant: config.allowPasswordGrant,
    }),
    authService: createAuthService({
      userRepo,
      tokenRepo,
      socialRepo,
      orgRepo,
      rbacRepo,
      config,
      keySet,
      sessionRepo,
      authCodeRepo,
      logger: testLogger,
      totp: totpService,
    }),
    adminService: createAdminService({ orgRepo, rbacRepo }),
    verificationService,
    totpService,
    passkeyService,
  }
  return {
    deps,
    userRepo,
    tokenRepo,
    sessionRepo,
    authCodeRepo,
    verificationRepo,
    socialRepo,
    orgRepo,
    rbacRepo,
    totpRepo,
    passkeyRepo,
    sentEmails,
  }
}

export function makeTestApp(envOverrides: Record<string, string> = {}) {
  const {
    deps,
    userRepo,
    socialRepo,
    orgRepo,
    rbacRepo,
    totpRepo,
    passkeyRepo,
    sentEmails,
  } = makeTestDeps(envOverrides)
  return {
    app: createApp(deps),
    userRepo,
    socialRepo,
    orgRepo,
    rbacRepo,
    totpRepo,
    passkeyRepo,
    totpService: deps.totpService,
    passkeyService: deps.passkeyService,
    userService: deps.userService,
    sentEmails,
  }
}

// Passkeys are off in tests unless asked for: turning them on changes every
// password login (the enrolment offer), which most tests do not expect.
export const PASSKEY_ENV = { WEBAUTHN_RP_ID: 'test.local' }

// Seeds a default org + service and adds userId as a member.
// Returns the audience string so callers can pass it to authHeader/passwordGrant.
// org.slug, service.client_id and service.audience are each UNIQUE, so every
// call gets a fresh suffix -- a test that seeds two services (e.g. two guests
// in one test) would otherwise collide on the shared literal: masked
// in-memory (first match wins / last write wins) but a real duplicate-key
// error against Drizzle/MySQL.
export async function seedDefaultService(
  orgRepo: OrgRepository,
  userId: string,
  audience = `test-service-${crypto.randomUUID()}`,
): Promise<string> {
  const now = new Date()
  const org = await orgRepo.createOrg({
    id: crypto.randomUUID(),
    slug: `test-${crypto.randomUUID()}`,
    name: 'Test Org',
    createdAt: now,
  })
  await orgRepo.createService({
    id: crypto.randomUUID(),
    orgId: org.id,
    clientId: `cid_test_${crypto.randomUUID()}`,
    clientSecretHash: null,
    name: 'Test Service',
    slug: 'test-service',
    audience,
    type: 'public',
    redirectUris: [],
    createdAt: now,
  })
  await orgRepo.addMember({
    id: crypto.randomUUID(),
    userId,
    orgId: org.id,
    createdAt: now,
  })
  return audience
}

// Grants permission keys to userId within the service behind `audience`
// (creates a role + permissions, grants and assigns them) so the user's access
// token for that audience carries them as scope.
export async function grantPermissions(
  orgRepo: OrgRepository,
  rbacRepo: RbacRepository,
  audience: string,
  userId: string,
  keys: string[],
): Promise<void> {
  const service = await orgRepo.findServiceByAudience(audience)
  if (!service) throw new Error(`no service for audience ${audience}`)
  const roleId = crypto.randomUUID()
  await rbacRepo.createRole({
    id: roleId,
    appServiceId: service.id,
    name: `role-${roleId}`,
  })
  for (const key of keys) {
    const permId = crypto.randomUUID()
    await rbacRepo.createPermission({
      id: permId,
      appServiceId: service.id,
      key,
    })
    await rbacRepo.grantPermissionToRole(roleId, permId)
  }
  await rbacRepo.assignRoleToUser(userId, roleId)
}

export async function authHeader(
  app: ReturnType<typeof createApp>,
  email: string,
  password: string,
  audience: string,
) {
  const res = await app.request('/oauth/token', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      grant_type: 'password',
      username: email,
      password,
      audience,
    }),
  })
  const body = await res.json()
  return {
    Authorization: `Bearer ${body.access_token}`,
    refresh: body.refresh_token as string,
  }
}

// Re-exported from the real catalogue, not copied: a second list drifted the
// moment a permission key was added to src.
export const PLATFORM_PERMISSIONS: string[] = [...CATALOGUE_PERMISSIONS]

// Mints a platform-scoped access token directly: the token's scope IS the authz
// for the management API, so no RBAC seeding is needed. The admin does need a
// user row -- requireAuth rejects a user token whose subject does not exist.
// Pass a narrower permission list to exercise the missing-permission (403) path.
export async function seedPlatformAdmin(
  userRepo: UserRepository,
  permissions: string[] = PLATFORM_PERMISSIONS,
): Promise<string> {
  const now = new Date()
  // Idempotent on purpose: a test that needs both a full admin and a narrowed
  // one calls this twice, and the two share the single fixed-id user row. The
  // in-memory Map would silently overwrite it; MySQL rejects the duplicate key.
  if (!(await userRepo.findById('admin-user'))) {
    await userRepo.create({
      id: 'admin-user',
      email: 'platform-admin@test.local',
      passwordHash: null,
      createdAt: now,
      updatedAt: now,
    })
  }
  return signAccessToken({
    sub: 'admin-user',
    issuer: 'http://test.local',
    privateKeyPem: keySet.privateKeyPem,
    kid: keySet.kid,
    ttlSeconds: 900,
    aud: 'platform',
    org: 'platform',
    scope: permissions.join(' '),
    clientId: 'platform',
    subType: 'user',
  })
}

// Posts the login form the way a browser does: fetch the page, carry its CSRF
// cookie, and submit the token it rendered. Non-browser callers have to do this
// too now — a bare POST to /oauth/authorize is refused (F21).
export async function submitLoginForm(
  app: ReturnType<typeof createApp>,
  fields: Record<string, string>,
): Promise<Response> {
  const { email, password, ...authorize } = fields
  const q = new URLSearchParams({ scope: '', state: '', ...authorize })
  const page = await app.request(`/oauth/authorize?${q}`)
  const cookie = page.headers.getSetCookie().map((c) => c.split(';')[0]).join(
    '; ',
  )
  // Submit what the page rendered, the way a browser does: posting `fields`
  // directly would hide a parameter the form forgot to carry.
  const hidden = hiddenFields(await page.text())
  return await app.request('/oauth/authorize', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie },
    body: new URLSearchParams({ ...hidden, email, password }).toString(),
    redirect: 'manual',
  })
}

// The hidden inputs a rendered server page carries, unescaped.
export function hiddenFields(html: string): Record<string, string> {
  return Object.fromEntries(
    [...html.matchAll(/<input type="hidden" name="([^"]*)" value="([^"]*)">/g)]
      .map(([, name, value]) => [name, unescapeHtml(value)]),
  )
}

// Submits the code page the way a browser does: the cookies it set (CSRF and
// the MFA challenge) and the hidden fields it rendered, plus the code.
export async function submitTotpForm(
  app: ReturnType<typeof createApp>,
  page: Response,
  code: string,
  cookieOverride?: string,
): Promise<Response> {
  const cookie = cookieOverride ??
    page.headers.getSetCookie().map((c) => c.split(';')[0]).join('; ')
  return await app.request('/oauth/authorize/totp', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie },
    body: new URLSearchParams({ ...hiddenFields(await page.text()), code })
      .toString(),
    redirect: 'manual',
  })
}

const unescapeHtml = (s: string) =>
  s.replace(
    /&(amp|lt|gt|quot|#39);/g,
    (_, e) =>
      ({ amp: '&', lt: '<', gt: '>', quot: '"', '#39': "'" })[e as string]!,
  )

export const GOOGLE_ENV = {
  GOOGLE_CLIENT_ID: 'test-client-id',
  GOOGLE_CLIENT_SECRET: 'test-client-secret',
  GOOGLE_REDIRECT_URI: 'http://localhost/oauth/google',
}
export const GOOGLE_TOKEN_ENDPOINT = 'https://oauth2.googleapis.com/token'

// A real JWT shape, because the bind flow decodes the id_token payload. It is
// NOT signature-verified: it arrives over TLS in the response to our own
// client-authenticated POST, so the channel is the proof. The header and
// signature are therefore deliberately junk.
export function idToken(claims: Record<string, unknown>): string {
  const b64 = (o: unknown) =>
    btoa(JSON.stringify(o)).replaceAll('+', '-').replaceAll('/', '_')
      .replaceAll('=', '')
  return `${b64({ alg: 'RS256' })}.${b64(claims)}.sig`
}

// Stubs Google's token endpoint. `calls` is the assertion surface: an
// untouched Google proves no code was redeemed. `bodies` captures what was
// actually POSTed, as URLSearchParams -- e.g. a wrong redirect_uri sent to
// real Google is a redirect_uri_mismatch that `calls` alone cannot see.
// The verbatim body real Google returned on 2026-09-20 when the token
// exchange omitted redirect_uri. Fixtured rather than invented, so the failure
// path is tested against Google's shape and not our guess at it.
export const GOOGLE_TOKEN_ERROR_BODY = JSON.stringify({
  error: 'invalid_request',
  error_description: 'Missing parameter: redirect_uri',
})

export function stubGoogleToken(
  claims: Record<string, unknown>,
  // Set to make Google REJECT the exchange instead of returning an id_token.
  // Without this there is no way to reach exchangeGoogleAuthCode's !res.ok
  // branch, which is where the only diagnosis of a real-world bind failure
  // gets written.
  failure?: { status: number; body: string },
) {
  const calls: string[] = []
  const bodies: URLSearchParams[] = []
  const real = globalThis.fetch
  globalThis.fetch = ((input: string | URL | Request, init?: RequestInit) => {
    const url = typeof input === 'string'
      ? input
      : input instanceof URL
      ? input.toString()
      : input.url
    calls.push(url)
    if (url.startsWith(GOOGLE_TOKEN_ENDPOINT)) {
      if (init?.body) {
        // The real fetch is never invoked, so init.body arrives exactly as
        // google.ts constructed it -- a URLSearchParams instance, not yet
        // serialized to a string.
        bodies.push(
          init.body instanceof URLSearchParams
            ? init.body
            : new URLSearchParams(init.body as string),
        )
      }
      return Promise.resolve(
        failure
          ? new Response(failure.body, {
            status: failure.status,
            headers: { 'content-type': 'application/json' },
          })
          : Response.json({ id_token: idToken(claims) }),
      )
    }
    throw new Error(`unexpected fetch to ${url}`)
  }) as typeof fetch
  return { calls, bodies, restore: () => globalThis.fetch = real }
}

// The code an authenticator app would show now (+offset steps). Replay
// protection makes a used step unusable: confirm with offset 0, then use +1
// for the next TOTP in the same test -- never -1 (a clock rollover between
// generating and verifying would push it out of the window).
export function totpCode(secretB32: string, offset = 0): Promise<string> {
  return hotp(fromBase32(secretB32), currentStep() + offset)
}
