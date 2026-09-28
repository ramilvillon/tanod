import { assert, assertEquals, assertStringIncludes } from '@std/assert'
import {
  authHeader,
  hiddenFields,
  makeTestApp,
  seedDefaultService,
  submitLoginForm,
  submitTotpForm,
  totpCode,
} from '../helpers.ts'
import { s256Challenge } from '../../src/lib/pkce.ts'

const PASSWORD = 'pw123456'

async function setup(env: Record<string, string> = {}) {
  const ctx = makeTestApp(env)
  const email = `l-${crypto.randomUUID()}@b.com`
  const user = await (await ctx.app.request('/users', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: PASSWORD }),
  })).json()
  const audience = await seedDefaultService(ctx.orgRepo, user.id)
  return { ...ctx, user, email, audience }
}

// Trap: once TOTP is on, authHeader can no longer mint a token for that user
// (the grant answers mfa_required). A test that needs the user's API token
// after enrolling must mint it BEFORE enroll.
// Enrolls through the API with a token obtained BEFORE TOTP was on.
async function enroll(ctx: Awaited<ReturnType<typeof setup>>) {
  const { Authorization } = await authHeader(
    ctx.app,
    ctx.email,
    PASSWORD,
    ctx.audience,
  )
  const headers = { Authorization, 'content-type': 'application/json' }
  const { secret } = await (await ctx.app.request('/users/me/totp', {
    method: 'POST',
    headers,
    body: JSON.stringify({ current_password: PASSWORD }),
  })).json()
  const { recovery_codes } =
    await (await ctx.app.request('/users/me/totp/confirm', {
      method: 'POST',
      headers,
      body: JSON.stringify({ code: await totpCode(secret) }),
    })).json()
  return {
    secret: secret as string,
    recovery_codes: recovery_codes as string[],
  }
}

function passwordGrant(
  ctx: Awaited<ReturnType<typeof setup>>,
  password: string,
) {
  return ctx.app.request('/oauth/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'password',
      username: ctx.email,
      password,
      audience: ctx.audience,
    }),
  })
}

Deno.test('password grant: a TOTP user with the right password gets mfa_required', async () => {
  const ctx = await setup()
  await enroll(ctx)
  const res = await passwordGrant(ctx, PASSWORD)
  assertEquals(res.status, 400)
  const body = await res.json()
  assertEquals(body.error, 'mfa_required')
  assertStringIncludes(body.error_description, 'authorization code flow')
})

Deno.test('password grant: a wrong password is still invalid_grant for a TOTP user', async () => {
  const ctx = await setup()
  await enroll(ctx)
  const res = await passwordGrant(ctx, 'wrong-password')
  assertEquals((await res.json()).error, 'invalid_grant')
})

const REDIRECT = 'https://app.example/cb'
const VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'

// setup() seeds a service with no redirect URIs; the hosted flow needs one.
async function hostedSetup(env: Record<string, string> = {}) {
  const ctx = await setup(env)
  const service = await ctx.orgRepo.findServiceByAudience(ctx.audience)
  const clientId = `cid_${crypto.randomUUID()}`
  await ctx.orgRepo.createService({
    id: crypto.randomUUID(),
    orgId: service!.orgId,
    clientId,
    clientSecretHash: null,
    name: 'Web',
    slug: 'web',
    audience: `web-${crypto.randomUUID()}`,
    type: 'public',
    redirectUris: [REDIRECT],
    createdAt: new Date(),
  })
  return { ...ctx, clientId }
}

async function loginFields(ctx: { clientId: string; email: string }) {
  return {
    client_id: ctx.clientId,
    redirect_uri: REDIRECT,
    state: 'st',
    code_challenge: await s256Challenge(VERIFIER),
    code_challenge_method: 'S256',
    email: ctx.email,
    password: PASSWORD,
  }
}

const cookieNames = (res: Response) =>
  res.headers.getSetCookie().map((c) => c.split('=')[0])

Deno.test('hosted login: a TOTP user gets the code page, not a session', async () => {
  const ctx = await hostedSetup()
  await enroll(ctx)
  const page = await submitLoginForm(ctx.app, await loginFields(ctx))
  assertEquals(page.status, 200)
  assert(
    !cookieNames(page).includes('auth_session'),
    'no session before the code',
  )
  assert(cookieNames(page).includes('auth_mfa'))
  const mfa = page.headers.getSetCookie().find((c) =>
    c.startsWith('auth_mfa=')
  )!
  assertStringIncludes(mfa, 'HttpOnly')
  assertStringIncludes(mfa, 'Path=/oauth')
  assertStringIncludes(await page.clone().text(), 'name="code"')
})

Deno.test('hosted login: the right code opens the session and redirects with a code', async () => {
  const ctx = await hostedSetup()
  const { secret } = await enroll(ctx)
  const page = await submitLoginForm(ctx.app, await loginFields(ctx))
  const res = await submitTotpForm(ctx.app, page, await totpCode(secret, 1))
  assertEquals(res.status, 302)
  const location = new URL(res.headers.get('location')!)
  assertEquals(location.origin + location.pathname, REDIRECT)
  assertEquals(location.searchParams.get('state'), 'st')
  assert(location.searchParams.get('code'))
  assert(cookieNames(res).includes('auth_session'))
  // The challenge is cleared once used.
  const cleared = res.headers.getSetCookie().find((c) =>
    c.startsWith('auth_mfa=')
  )
  assert(cleared && /Max-Age=0/i.test(cleared))
})

Deno.test('hosted login: a recovery code works in place of a TOTP code', async () => {
  const ctx = await hostedSetup()
  const { recovery_codes } = await enroll(ctx)
  const page = await submitLoginForm(ctx.app, await loginFields(ctx))
  const res = await submitTotpForm(ctx.app, page, recovery_codes[0])
  assertEquals(res.status, 302)
})

Deno.test('hosted login: a wrong code shows the code page again with 401', async () => {
  const ctx = await hostedSetup()
  await enroll(ctx)
  const page = await submitLoginForm(ctx.app, await loginFields(ctx))
  const res = await submitTotpForm(ctx.app, page, 'AAAA-AAAA-AAAA-AAAA')
  assertEquals(res.status, 401)
  const html = await res.text()
  assertStringIncludes(html, 'That code is not valid')
  assertStringIncludes(html, 'name="code"')
})

Deno.test('hosted login: a code used to sign in cannot be used again', async () => {
  const ctx = await hostedSetup()
  const { secret } = await enroll(ctx)
  const code = await totpCode(secret, 1)
  const first = await submitTotpForm(
    ctx.app,
    await submitLoginForm(ctx.app, await loginFields(ctx)),
    code,
  )
  assertEquals(first.status, 302)
  const again = await submitTotpForm(
    ctx.app,
    await submitLoginForm(ctx.app, await loginFields(ctx)),
    code,
  )
  assertEquals(again.status, 401)
})

Deno.test('hosted login: wrong codes count toward the account lockout', async () => {
  const ctx = await hostedSetup({
    LOGIN_MAX_FAILURES: '3',
    LOGIN_LOCKOUT_MS: '60000',
  })
  const { recovery_codes } = await enroll(ctx)
  const page = await submitLoginForm(ctx.app, await loginFields(ctx))
  const cookie = page.headers.getSetCookie().map((c) => c.split(';')[0]).join(
    '; ',
  )
  const html = await page.text()
  const post = (code: string) =>
    ctx.app.request('/oauth/authorize/totp', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', cookie },
      body: new URLSearchParams({ ...hiddenFields(html), code }).toString(),
      redirect: 'manual',
    })
  for (let i = 0; i < 3; i++) {
    assertEquals((await post('AAAA-AAAA-AAAA-AAAA')).status, 401)
  }
  // Locked: even a valid recovery code is refused now.
  assertEquals((await post(recovery_codes[0])).status, 401)
})

Deno.test('hosted login: no challenge cookie means sign in again', async () => {
  const ctx = await hostedSetup()
  const { secret } = await enroll(ctx)
  const page = await submitLoginForm(ctx.app, await loginFields(ctx))
  const csrfOnly = page.headers.getSetCookie()
    .filter((c) => c.startsWith('auth_csrf='))
    .map((c) => c.split(';')[0]).join('; ')
  const res = await submitTotpForm(
    ctx.app,
    page,
    await totpCode(secret, 1),
    csrfOnly,
  )
  assertEquals(res.status, 401)
  assertStringIncludes(await res.text(), 'Your sign-in timed out')
})

Deno.test('hosted login: an access token in the challenge cookie is refused', async () => {
  const ctx = await hostedSetup()
  const { Authorization } = await authHeader(
    ctx.app,
    ctx.email,
    PASSWORD,
    ctx.audience,
  )
  const { secret } = await enroll(ctx)
  const page = await submitLoginForm(ctx.app, await loginFields(ctx))
  const forged = page.headers.getSetCookie()
    .map((c) => c.split(';')[0])
    .map((c) =>
      c.startsWith('auth_mfa=') ? `auth_mfa=${Authorization.slice(7)}` : c
    )
    .join('; ')
  const res = await submitTotpForm(
    ctx.app,
    page,
    await totpCode(secret, 1),
    forged,
  )
  assertEquals(res.status, 401)
  // 401 alone would also fit a wrong code: this must be the challenge refusal.
  assertStringIncludes(await res.text(), 'Your sign-in timed out')
})

Deno.test('the MFA challenge is not an access token', async () => {
  const ctx = await hostedSetup()
  await enroll(ctx)
  const page = await submitLoginForm(ctx.app, await loginFields(ctx))
  const jwt = page.headers.getSetCookie()
    .find((c) => c.startsWith('auth_mfa='))!.split(';')[0].slice(
      'auth_mfa='.length,
    )
  const res = await ctx.app.request('/users/me', {
    headers: { Authorization: `Bearer ${jwt}` },
  })
  assertEquals(res.status, 401)
})

Deno.test('hosted login: a CSRF mismatch on the code page is refused', async () => {
  const ctx = await hostedSetup()
  const { secret } = await enroll(ctx)
  const page = await submitLoginForm(ctx.app, await loginFields(ctx))
  const noCsrf = page.headers.getSetCookie()
    .filter((c) => c.startsWith('auth_mfa='))
    .map((c) => c.split(';')[0]).join('; ')
  const res = await submitTotpForm(
    ctx.app,
    page,
    await totpCode(secret, 1),
    noCsrf,
  )
  assertEquals(res.status, 403)
})

Deno.test('hosted login: a user without TOTP is unaffected', async () => {
  const ctx = await hostedSetup()
  const res = await submitLoginForm(ctx.app, await loginFields(ctx))
  assertEquals(res.status, 302)
  assert(cookieNames(res).includes('auth_session'))
})

// A code page's cookies and fields, as reusable posts of one code each.
async function codePage(ctx: Awaited<ReturnType<typeof hostedSetup>>) {
  const page = await submitLoginForm(ctx.app, await loginFields(ctx))
  assertEquals(page.status, 200)
  const cookie = page.headers.getSetCookie().map((c) => c.split(';')[0]).join(
    '; ',
  )
  const html = await page.text()
  return (code: string) =>
    ctx.app.request('/oauth/authorize/totp', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', cookie },
      body: new URLSearchParams({ ...hiddenFields(html), code }).toString(),
      redirect: 'manual',
    })
}

const WRONG = 'AAAA-AAAA-AAAA-AAAA'
const LOCKOUT_ENV = { LOGIN_MAX_FAILURES: '3', LOGIN_LOCKOUT_MS: '60000' }

// The password alone must not end a run of failed codes: otherwise anyone
// holding it re-submits it every few guesses and guesses codes forever.
Deno.test('hosted login: a correct password does not reset the code-guess count', async () => {
  const ctx = await hostedSetup(LOCKOUT_ENV)
  const { recovery_codes } = await enroll(ctx)
  const first = await codePage(ctx)
  for (let i = 0; i < 2; i++) assertEquals((await first(WRONG)).status, 401)
  // The password again, on the form (a new challenge)...
  const second = await codePage(ctx)
  assertEquals((await second(WRONG)).status, 401)
  // ...that was the third failure: locked, so even a valid code is refused.
  const res = await second(recovery_codes[0])
  assertEquals(res.status, 401)
  assertStringIncludes(await res.text(), 'That code is not valid')
})

Deno.test('the login form carries prompt through to its POST', async () => {
  const ctx = await hostedSetup()
  const q = new URLSearchParams({
    client_id: ctx.clientId,
    redirect_uri: REDIRECT,
    scope: '',
    code_challenge: await s256Challenge(VERIFIER),
    code_challenge_method: 'S256',
    prompt: 'login',
  })
  const page = await ctx.app.request(`/oauth/authorize?${q}`)
  assertEquals(hiddenFields(await page.text()).prompt, 'login')
})

Deno.test('password grant: mfa_required does not reset the code-guess count', async () => {
  const ctx = await hostedSetup(LOCKOUT_ENV)
  const { recovery_codes } = await enroll(ctx)
  const post = await codePage(ctx)
  for (let i = 0; i < 2; i++) assertEquals((await post(WRONG)).status, 401)
  assertEquals(
    (await (await passwordGrant(ctx, PASSWORD)).json()).error,
    'mfa_required',
  )
  assertEquals((await post(WRONG)).status, 401)
  assertEquals((await post(recovery_codes[0])).status, 401)
})

Deno.test('hosted login: a lockout from wrong passwords also blocks the code page', async () => {
  const ctx = await hostedSetup(LOCKOUT_ENV)
  const { recovery_codes } = await enroll(ctx)
  const post = await codePage(ctx)
  for (let i = 0; i < 3; i++) {
    assertEquals(
      (await (await passwordGrant(ctx, 'wrong-password')).json()).error,
      'invalid_grant',
    )
  }
  assertEquals((await post(recovery_codes[0])).status, 401)
})
