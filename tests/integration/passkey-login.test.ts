import { assert, assertEquals, assertStringIncludes } from '@std/assert'
import {
  hiddenFields,
  makeTestApp,
  PASSKEY_ENV,
  seedDefaultService,
  totpCode,
} from '../helpers.ts'
import { s256Challenge } from '../../src/lib/pkce.ts'
import { createSoftAuthenticator } from '../soft-authenticator.ts'

const REDIRECT = 'https://app.example/cb'
const VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
const cookiesOf = (res: Response) =>
  res.headers.getSetCookie().map((c) => c.split(';')[0]).join('; ')

async function setup(env: Record<string, string> = PASSKEY_ENV) {
  const ctx = makeTestApp(env)
  const email = `k-${crypto.randomUUID()}@b.com`
  const user = await (await ctx.app.request('/users', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: 'pw123456' }),
  })).json()
  const audience = await seedDefaultService(ctx.orgRepo, user.id)
  const service = await ctx.orgRepo.findServiceByAudience(audience)
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
  const auth = await createSoftAuthenticator()
  if (ctx.passkeyService.enabled) {
    const options = await ctx.passkeyService.registrationOptions(
      user.id,
      new Date(),
    )
    await ctx.passkeyService.register(user.id, await auth.register(options))
  }
  return { ...ctx, user, email, clientId, auth }
}

async function authorizeQuery(ctx: { clientId: string }) {
  return new URLSearchParams({
    client_id: ctx.clientId,
    redirect_uri: REDIRECT,
    scope: '',
    state: 'st',
    code_challenge: await s256Challenge(VERIFIER),
    code_challenge_method: 'S256',
  })
}

// The page, its CSRF cookie, the options fetch, the ceremony, the form POST:
// what the login page's script does in a browser. `post` re-submits with any
// credential/fields, without spending another page load and options fetch.
// Rate-limit trap: GET /oauth/authorize, the options fetch and the POST all
// share one per-IP budget of 10 (every test request has the key 'unknown').
async function passkeySignIn(
  ctx: Awaited<ReturnType<typeof setup>>,
  fields: Record<string, string> = {},
) {
  const page = await ctx.app.request(
    `/oauth/authorize?${await authorizeQuery(ctx)}`,
  )
  const cookie = cookiesOf(page)
  const hidden = hiddenFields(await page.text())
  const options =
    await (await ctx.app.request('/oauth/authorize/passkey/options', {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ csrf_token: hidden.csrf_token }),
    })).json()
  const credential = JSON.stringify(await ctx.auth.authenticate(options))
  const post = (over: { credential?: string } = {}) =>
    ctx.app.request('/oauth/authorize/passkey', {
      method: 'POST',
      headers: {
        cookie,
        accept: 'text/html',
        'content-type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        ...hidden,
        ...fields,
        credential: over.credential ?? credential,
      }),
      redirect: 'manual',
    })
  return { res: await post(), post }
}

Deno.test('a passkey signs in: session cookie and a code for the client', async () => {
  const ctx = await setup()
  const { res } = await passkeySignIn(ctx)
  assertEquals(res.status, 302)
  const location = new URL(res.headers.get('location')!)
  assertEquals(location.origin + location.pathname, REDIRECT)
  assert(location.searchParams.get('code'))
  assert(res.headers.getSetCookie().some((c) => c.startsWith('auth_session=')))
})

Deno.test('a passkey sign-in skips the TOTP step', async () => {
  const ctx = await setup()
  const { secret } = await ctx.totpService.startSetup(ctx.user.id, {
    currentPassword: 'pw123456',
  })
  await ctx.totpService.confirm(ctx.user.id, await totpCode(secret))
  assertEquals((await passkeySignIn(ctx)).res.status, 302)
})

Deno.test('the same assertion cannot sign in twice', async () => {
  const ctx = await setup()
  const { res, post } = await passkeySignIn(ctx)
  assertEquals(res.status, 302)
  const again = await post()
  assertEquals(again.status, 401)
  assertStringIncludes(await again.text(), 'That passkey couldn&#39;t be used')
})

Deno.test('garbage in the credential field is a 401 page, not a 500', async () => {
  const ctx = await setup()
  // passkeySignIn's own first POST is a valid one; the garbage goes after it.
  const { res, post } = await passkeySignIn(ctx)
  assertEquals(res.status, 302)
  for (const credential of ['not json', '{}', '[]', '"x"', 'null']) {
    const r = await post({ credential })
    assertEquals(r.status, 401, credential)
    await r.body?.cancel()
  }
})

Deno.test('a garbage credential without an HTML Accept header is a JSON 401, not the login page', async () => {
  const ctx = await setup()
  const page = await ctx.app.request(
    `/oauth/authorize?${await authorizeQuery(ctx)}`,
  )
  const cookie = cookiesOf(page)
  const hidden = hiddenFields(await page.text())
  const res = await ctx.app.request('/oauth/authorize/passkey', {
    method: 'POST',
    headers: { cookie, 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ ...hidden, credential: 'not json' }),
  })
  assertEquals(res.status, 401)
  assertEquals((await res.json()).error.code, 'passkey_invalid')
})

Deno.test('a tampered redirect_uri is refused before any session', async () => {
  const ctx = await setup()
  const { res } = await passkeySignIn(ctx, {
    redirect_uri: 'https://evil.example/cb',
  })
  assertEquals(res.status, 400)
  assert(
    !res.headers.getSetCookie().some((c) => c.startsWith('auth_session=')),
  )
})

Deno.test('a passkey of a deleted account does not sign in', async () => {
  const ctx = await setup()
  // Soft-deleted: the passkey row survives the grace period, the account
  // must not sign in through it.
  await ctx.userService.remove(ctx.user.id)
  const { res } = await passkeySignIn(ctx)
  assertEquals(res.status, 401)
})

Deno.test('REQUIRE_EMAIL_VERIFICATION applies to a passkey sign-in', async () => {
  const ctx = await setup({
    ...PASSKEY_ENV,
    REQUIRE_EMAIL_VERIFICATION: 'true',
  })
  const { res } = await passkeySignIn(ctx)
  assertEquals(res.status, 403)
  assertStringIncludes(await res.text(), 'verify your email')
})

Deno.test('a CSRF token mismatch on the sign-in POST re-renders the login page', async () => {
  const ctx = await setup()
  const page = await ctx.app.request(
    `/oauth/authorize?${await authorizeQuery(ctx)}`,
  )
  const cookie = cookiesOf(page)
  const hidden = hiddenFields(await page.text())
  const res = await ctx.app.request('/oauth/authorize/passkey', {
    method: 'POST',
    headers: {
      cookie,
      accept: 'text/html',
      'content-type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      ...hidden,
      csrf_token: 'wrong-token',
      credential: '{}',
    }),
  })
  assertEquals(res.status, 403)
  assertStringIncludes(await res.text(), 'no longer valid')
})

Deno.test('every passkey route is 404 when passkeys are off, even the sign-in POST and register routes', async () => {
  const off = await setup({})
  const body = new URLSearchParams({ credential: '{}' })
  for (
    const path of [
      '/oauth/authorize/passkey',
      '/oauth/passkeys/register/options',
      '/oauth/passkeys/register',
    ]
  ) {
    const res = await off.app.request(path, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body,
    })
    assertEquals(res.status, 404, path)
  }
})

Deno.test('the options endpoint needs the CSRF token', async () => {
  const ctx = await setup()
  const res = await ctx.app.request('/oauth/authorize/passkey/options', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: '',
  })
  assertEquals(res.status, 403)
  assertEquals((await res.json()).error.code, 'csrf_token_invalid')
})

Deno.test('the options endpoint has its own rate budget, separate from login', async () => {
  const ctx = await setup()
  const page = await ctx.app.request(
    `/oauth/authorize?${await authorizeQuery(ctx)}`,
  )
  const cookie = cookiesOf(page)
  const hidden = hiddenFields(await page.text())
  // 10 requests here would exhaust a shared `login` budget of 10 on its own
  // (the page load above already spent one); each must still succeed.
  for (let i = 0; i < 10; i++) {
    const res = await ctx.app.request('/oauth/authorize/passkey/options', {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ csrf_token: hidden.csrf_token }),
    })
    assertEquals(res.status, 200, `request ${i}`)
  }
  // The login budget is untouched: another GET /oauth/authorize still works.
  const again = await ctx.app.request(
    `/oauth/authorize?${await authorizeQuery(ctx)}`,
  )
  assertEquals(again.status, 200)
})

Deno.test('the login page offers passkeys only when they are on', async () => {
  const on = await setup()
  const onPage =
    await (await on.app.request(`/oauth/authorize?${await authorizeQuery(on)}`))
      .text()
  assertStringIncludes(onPage, 'Sign in with a passkey')
  assertStringIncludes(onPage, 'autocomplete="username webauthn"')
  // Without JS the password form is untouched.
  assertStringIncludes(onPage, 'name="password"')

  const off = await setup({})
  const offPage = await (await off.app.request(
    `/oauth/authorize?${await authorizeQuery(off)}`,
  )).text()
  assertEquals(offPage.includes('passkey'), false)
  const res = await off.app.request('/oauth/authorize/passkey/options', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: '',
  })
  // 404 even without a CSRF token: off must look absent, not forbidden.
  assertEquals(res.status, 404)
})
