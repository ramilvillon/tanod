import { assert, assertEquals, assertStringIncludes } from '@std/assert'
import {
  makeTestApp,
  PASSKEY_ENV,
  submitTotpForm,
  totpCode,
} from '../helpers.ts'
import { s256Challenge } from '../../src/lib/pkce.ts'
import { signAccessToken, verifyAccessToken } from '../../src/lib/jwt.ts'
import { keySet } from '../helpers.ts'

// Google login is a step of the authorize flow: the login page links to
// /oauth/google with the pending authorize request, and the return leg ends
// like a password login -- session cookie, then a code to the client's
// redirect_uri. These drive the real route, googleAuth middleware included,
// with global fetch standing in for Google.

const GOOGLE_ENV = {
  GOOGLE_CLIENT_ID: 'test-client-id',
  GOOGLE_CLIENT_SECRET: 'test-client-secret',
  GOOGLE_REDIRECT_URI: 'http://localhost/oauth/google',
}

const TOKEN_ENDPOINT = 'https://oauth2.googleapis.com/token'
const USERINFO_ENDPOINT = 'https://www.googleapis.com/oauth2/v2/userinfo'

// Replaces global fetch so the middleware's two calls to Google resolve without
// network. `calls` is the assertion surface: an untouched Google means the
// authorization code was never redeemed.
function stubGoogle(profile: Record<string, unknown>) {
  const calls: string[] = []
  const real = globalThis.fetch
  globalThis.fetch = ((input: string | URL | Request) => {
    const url = typeof input === 'string'
      ? input
      : input instanceof URL
      ? input.toString()
      : input.url
    calls.push(url)
    if (url.startsWith(TOKEN_ENDPOINT)) {
      return Promise.resolve(
        Response.json({
          access_token: 'google-access-token',
          expires_in: 3600,
          scope: 'openid email profile',
          token_type: 'Bearer',
          id_token: 'google-id-token',
        }),
      )
    }
    if (url.startsWith(USERINFO_ENDPOINT)) {
      return Promise.resolve(Response.json(profile))
    }
    throw new Error(`unexpected fetch to ${url}`)
  }) as typeof fetch
  return { calls, restore: () => globalThis.fetch = real }
}

// Everything the browser would send back on the next request.
const cookieHeader = (res: Response) =>
  res.headers.getSetCookie().map((c) => c.split(';')[0]).join('; ')

const VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
const REDIRECT = 'https://app.example/cb'

// A client, and a passwordless verified member whose address the Google
// profile below matches -- so the round trip links, signs in, and can redeem
// its code for a token.
async function seed(ctx: ReturnType<typeof makeTestApp>) {
  const now = new Date()
  const org = await ctx.orgRepo.createOrg({
    id: crypto.randomUUID(),
    slug: 'acme',
    name: 'Acme',
    createdAt: now,
  })
  await ctx.orgRepo.createService({
    id: crypto.randomUUID(),
    orgId: org.id,
    clientId: 'cid_app',
    clientSecretHash: null,
    name: 'App',
    slug: 'app',
    audience: 'acme-app',
    type: 'public',
    redirectUris: [REDIRECT],
    createdAt: now,
  })
  const user = await ctx.userRepo.create({
    id: crypto.randomUUID(),
    email: 'u@example.test',
    passwordHash: null,
    emailVerified: true,
    createdAt: now,
    updatedAt: now,
  })
  await ctx.orgRepo.addMember({
    id: crypto.randomUUID(),
    userId: user.id,
    orgId: org.id,
    createdAt: now,
  })
  return user
}

async function authorizeQuery(overrides: Record<string, string> = {}) {
  return new URLSearchParams({
    client_id: 'cid_app',
    redirect_uri: REDIRECT,
    scope: 'openid',
    state: 'app-state',
    nonce: 'n-1',
    code_challenge: await s256Challenge(VERIFIER),
    code_challenge_method: 'S256',
    ...overrides,
  })
}

const PROFILE = { id: 'g-1', email: 'u@example.test', verified_email: true }

// Starts a Google sign-in and returns the browser's cookies plus the state
// Google would echo back.
async function start(app: ReturnType<typeof makeTestApp>['app']) {
  const res = await app.request(`/oauth/google?${await authorizeQuery()}`)
  assertEquals(res.status, 302)
  const state = new URL(res.headers.get('location') ?? '').searchParams.get(
    'state',
  )
  assert(state)
  return { cookie: cookieHeader(res), state, res }
}

Deno.test('the login page links to Google with the authorize request, never the credentials', async () => {
  const ctx = makeTestApp(GOOGLE_ENV)
  await seed(ctx)
  const page = await ctx.app.request(
    `/oauth/authorize?${await authorizeQuery()}`,
  )
  const href = (await page.text()).match(/href="([^"]*)">Sign in with Google/)
    ?.[1]
  assert(href, 'the login page must offer Google when it is configured')
  const q = new URL(href.replaceAll('&amp;', '&'), 'http://x').searchParams
  assertEquals(q.get('client_id'), 'cid_app')
  assertEquals(q.get('redirect_uri'), REDIRECT)
  assertEquals(q.get('state'), 'app-state')
  assertEquals(q.get('nonce'), 'n-1')
  assertEquals(q.get('password'), null)
})

Deno.test('without Google configured there is no link and the route is 404', async () => {
  const ctx = makeTestApp()
  await seed(ctx)
  const page = await ctx.app.request(
    `/oauth/authorize?${await authorizeQuery()}`,
  )
  assert(!(await page.text()).includes('Sign in with Google'))
  const res = await ctx.app.request(`/oauth/google?${await authorizeQuery()}`)
  assertEquals(res.status, 404)
})

Deno.test('GET /oauth/google redirects to Google carrying a state that is also set as a cookie', async () => {
  const ctx = makeTestApp(GOOGLE_ENV)
  await seed(ctx)

  const { res, state } = await start(ctx.app)

  assertStringIncludes(
    res.headers.get('location') ?? '',
    'https://accounts.google.com/o/oauth2/v2/auth',
  )
  const stateCookie = res.headers.getSetCookie().find((c) =>
    c.startsWith('state=')
  )
  assert(stateCookie)
  assertStringIncludes(stateCookie, `state=${state}`)
  assertStringIncludes(stateCookie, 'HttpOnly')
  // `Secure` is the library's, not ours, and it is load-bearing in a direction
  // that bites: browsers drop a Secure cookie on a plain-http origin unless the
  // host is localhost, and then every callback 401s with no state cookie to
  // match. `insecureGoogleRedirectWarning` says so at startup; this pins the
  // attribute that makes the warning necessary, so a library change is visible
  // here rather than in production. Nothing server-side varies by scheme, so
  // the drop itself can only be observed in a real browser.
  assertStringIncludes(stateCookie, 'Secure')
})

Deno.test('an authorize request that fails validation never reaches Google', async () => {
  const ctx = makeTestApp(GOOGLE_ENV)
  await seed(ctx)
  const res = await ctx.app.request(
    `/oauth/google?${await authorizeQuery({
      redirect_uri: 'https://evil.example/cb',
    })}`,
  )
  assertEquals(res.status, 400)
  assertEquals(res.headers.get('location'), null)
})

Deno.test('signing in with Google returns a code to the client, and the code redeems for its audience', async () => {
  const ctx = makeTestApp(GOOGLE_ENV)
  const user = await seed(ctx)
  const { cookie, state } = await start(ctx.app)

  const google = stubGoogle(PROFILE)
  let res: Response
  try {
    res = await ctx.app.request(`/oauth/google?code=good-code&state=${state}`, {
      headers: { cookie },
    })
  } finally {
    google.restore()
  }

  assertEquals(res.status, 302)
  const location = new URL(res.headers.get('location') ?? '')
  assertEquals(location.origin + location.pathname, REDIRECT)
  assertEquals(location.searchParams.get('state'), 'app-state')
  const code = location.searchParams.get('code')
  assert(code)
  assert(
    res.headers.getSetCookie().some((c) => c.startsWith('auth_session=')),
    'the Google login must open an SSO session like a password login',
  )

  const token = await ctx.app.request('/oauth/token', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT,
      code_verifier: VERIFIER,
      client_id: 'cid_app',
    }),
  })
  assertEquals(token.status, 200)
  const pair = await token.json()
  const claims = await verifyAccessToken(pair.access_token, keySet.publicKeyPem)
  assertEquals(claims.aud, 'acme-app')
  assertEquals(claims.sub, user.id)
  assert(pair.id_token, 'openid was requested, so an id_token comes back')
  const idToken = JSON.parse(atob(pair.id_token.split('.')[1]))
  assertEquals(idToken.nonce, 'n-1')
})

Deno.test('cancelling at Google shows the login page again instead of looping back to Google', async () => {
  const ctx = makeTestApp(GOOGLE_ENV)
  await seed(ctx)
  const { cookie, state } = await start(ctx.app)

  const res = await ctx.app.request(
    `/oauth/google?error=access_denied&state=${state}`,
    { headers: { cookie } },
  )

  assertEquals(res.status, 401)
  assertEquals(res.headers.get('location'), null)
  assertStringIncludes(await res.text(), 'Google sign-in was cancelled')
})

Deno.test('a refused Google login shows the login page and signs nobody in', async () => {
  const ctx = makeTestApp(GOOGLE_ENV)
  await seed(ctx)
  const { cookie, state } = await start(ctx.app)

  const google = stubGoogle({ ...PROFILE, id: 'g-2', verified_email: false })
  let res: Response
  try {
    res = await ctx.app.request(`/oauth/google?code=good-code&state=${state}`, {
      headers: { cookie },
    })
  } finally {
    google.restore()
  }

  assertEquals(res.status, 403)
  assertEquals(res.headers.get('location'), null)
  assertStringIncludes(await res.text(), 'not verified')
  assert(
    !res.headers.getSetCookie().some((c) => c.startsWith('auth_session=')),
  )
})

Deno.test('a Google return with no sign-in in progress is refused', async () => {
  const ctx = makeTestApp(GOOGLE_ENV)
  await seed(ctx)
  const { cookie, state } = await start(ctx.app)
  // Keep the state cookie, lose the stored authorize request.
  const stateOnly = cookie.split('; ').filter((c) => c.startsWith('state='))
    .join('; ')

  const google = stubGoogle(PROFILE)
  try {
    const res = await ctx.app.request(
      `/oauth/google?code=good-code&state=${state}`,
      { headers: { cookie: stateOnly } },
    )
    assertEquals(res.status, 400)
    assertEquals((await res.json()).error.code, 'authorize_request_expired')
  } finally {
    google.restore()
  }
})

Deno.test('GET /oauth/google refuses a callback that carries no state at all', async () => {
  const { app, socialRepo } = makeTestApp(GOOGLE_ENV)
  // An attacker's own Google identity, attached to a code they hand to a victim.
  const google = stubGoogle({
    id: 'g-attacker',
    email: 'attacker@evil.test',
    verified_email: true,
  })

  try {
    // No state query param, and no state cookie: the victim's browser never
    // initiated a login. Comparing two absent values must not read as a match.
    const res = await app.request('/oauth/google?code=attacker-code')

    // This is the security property, and it is asserted first because it is the
    // one that actually distinguishes a rejected callback from an accepted one.
    // A redeemed code means the attacker's identity was already exchanged with
    // Google before anything downstream got a say.
    assertEquals(
      google.calls,
      [],
      'the authorization code must never reach Google',
    )
    assertEquals(
      res.status,
      401,
      'a callback with neither a state param nor a state cookie must be refused',
    )
    assertEquals(
      await socialRepo.findByProviderAccount('google', 'g-attacker'),
      null,
      'no social account may be linked from an unverified callback',
    )
  } finally {
    google.restore()
  }
})

Deno.test('GET /oauth/google refuses a callback whose state does not match the cookie', async () => {
  const ctx = makeTestApp(GOOGLE_ENV)
  await seed(ctx)
  const { cookie } = await start(ctx.app)
  const google = stubGoogle(PROFILE)

  try {
    const res = await ctx.app.request(
      '/oauth/google?code=some-code&state=not-the-minted-one',
      { headers: { cookie } },
    )

    assertEquals(res.status, 401)
    assertEquals(
      google.calls,
      [],
      'the authorization code must never reach Google',
    )
  } finally {
    google.restore()
  }
})

Deno.test('a Google sign-in of a TOTP user asks for the code before any session', async () => {
  const ctx = makeTestApp(GOOGLE_ENV)
  const user = await seed(ctx)
  // Enroll directly, as if just signed in: this user is passwordless, so a
  // fresh sign-in is its proof.
  const { secret } = await ctx.totpService.startSetup(user.id, {
    authTime: Math.floor(Date.now() / 1000),
  })
  await ctx.totpService.confirm(user.id, await totpCode(secret))
  const { cookie, state } = await start(ctx.app)

  const google = stubGoogle(PROFILE)
  let page: Response
  try {
    page = await ctx.app.request(
      `/oauth/google?code=good-code&state=${state}`,
      {
        headers: { cookie },
      },
    )
  } finally {
    google.restore()
  }
  assertEquals(page.status, 200)
  assert(
    !page.headers.getSetCookie().some((c) => c.startsWith('auth_session=')),
    'no session before the code',
  )
  const res = await submitTotpForm(ctx.app, page, await totpCode(secret, 1))
  assertEquals(res.status, 302)
  assertEquals(
    new URL(res.headers.get('location')!).searchParams.get('state'),
    'app-state',
  )
})

// A full Google sign-in through the authorize flow, redeemed for tokens.
async function googleSignIn(ctx: ReturnType<typeof makeTestApp>) {
  const { cookie, state } = await start(ctx.app)
  const google = stubGoogle(PROFILE)
  let res: Response
  try {
    res = await ctx.app.request(`/oauth/google?code=good-code&state=${state}`, {
      headers: { cookie },
    })
  } finally {
    google.restore()
  }
  assertEquals(res.status, 302)
  const code = new URL(res.headers.get('location')!).searchParams.get('code')
  const pair = await (await ctx.app.request('/oauth/token', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT,
      code_verifier: VERIFIER,
      client_id: 'cid_app',
    }),
  })).json()
  return { pair, session: cookieHeader(res) }
}

const startTotp = (
  app: ReturnType<typeof makeTestApp>['app'],
  accessToken: string,
) =>
  app.request('/users/me/totp', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'content-type': 'application/json',
    },
    body: '{}',
  })

Deno.test('a Google-only user enrols TOTP with a token from a fresh sign-in', async () => {
  const ctx = makeTestApp(GOOGLE_ENV)
  const user = await seed(ctx)
  const { pair } = await googleSignIn(ctx)
  const claims = await verifyAccessToken(pair.access_token, keySet.publicKeyPem)
  assert(typeof claims.auth_time === 'number')
  const res = await startTotp(ctx.app, pair.access_token)
  assertEquals(res.status, 200)
  const { secret } = await res.json()
  await ctx.totpService.confirm(user.id, await totpCode(secret))
  assert(await ctx.totpService.isEnabled(user.id))
})

Deno.test('a Google-only user with a stale or refreshed token must sign in again', async () => {
  const ctx = makeTestApp(GOOGLE_ENV)
  const user = await seed(ctx)
  const mint = (authTime?: Date) =>
    signAccessToken({
      sub: user.id,
      issuer: 'http://test.local',
      privateKeyPem: keySet.privateKeyPem,
      kid: keySet.kid,
      ttlSeconds: 900,
      aud: 'acme-app',
      org: 'acme',
      scope: '',
      clientId: 'cid_app',
      subType: 'user',
      authTime,
    })
  // Signed in ten minutes ago: a token stolen from that session must not
  // be able to enrol the thief's authenticator.
  const stale = await startTotp(
    ctx.app,
    await mint(new Date(Date.now() - 10 * 60 * 1000)),
  )
  assertEquals(stale.status, 403)
  assertEquals((await stale.json()).error.code, 'fresh_login_required')
  // A refreshed token carries no auth_time at all.
  assertEquals((await startTotp(ctx.app, await mint())).status, 403)
})

Deno.test('prompt=login shows the login page even with a live SSO session', async () => {
  const ctx = makeTestApp(GOOGLE_ENV)
  await seed(ctx)
  const { session } = await googleSignIn(ctx)
  const reuse = await ctx.app.request(
    `/oauth/authorize?${await authorizeQuery()}`,
    { headers: { cookie: session } },
  )
  assertEquals(reuse.status, 302)
  const forced = await ctx.app.request(
    `/oauth/authorize?${await authorizeQuery({ prompt: 'login' })}`,
    { headers: { cookie: session } },
  )
  assertEquals(forced.status, 200)
  assertStringIncludes(await forced.text(), '<form')
})

Deno.test('the Google link keeps prompt', async () => {
  const ctx = makeTestApp(GOOGLE_ENV)
  await seed(ctx)
  const page = await ctx.app.request(
    `/oauth/authorize?${await authorizeQuery({ prompt: 'login' })}`,
  )
  assertStringIncludes(await page.text(), 'prompt=login')
})

Deno.test('a Google sign-in is followed by the passkey offer when passkeys are on', async () => {
  const ctx = makeTestApp({ ...GOOGLE_ENV, ...PASSKEY_ENV })
  await seed(ctx)
  const { cookie, state } = await start(ctx.app)
  const google = stubGoogle(PROFILE)
  let res: Response
  try {
    res = await ctx.app.request(`/oauth/google?code=good-code&state=${state}`, {
      headers: { cookie },
    })
  } finally {
    google.restore()
  }
  assertEquals(res.status, 200)
  assertStringIncludes(await res.text(), 'Create passkey')
})
