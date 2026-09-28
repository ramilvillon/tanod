import { assert, assertEquals, assertStringIncludes } from '@std/assert'
import {
  hiddenFields,
  makeTestApp,
  PASSKEY_ENV,
  seedDefaultService,
} from '../helpers.ts'
import { s256Challenge } from '../../src/lib/pkce.ts'
import { createSoftAuthenticator } from '../soft-authenticator.ts'
import { MAX_PASSKEYS } from '../../src/modules/passkeys/passkey.service.ts'
import { hashToken } from '../../src/lib/tokens.ts'

const REDIRECT = 'https://app.example/cb'
const VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
const cookiesOf = (res: Response) =>
  res.headers.getSetCookie().map((c) => c.split(';')[0]).join('; ')

// Unlike passkey-login.test.ts's setup, this one does NOT pre-register a
// passkey: every test here starts from a sign-in that has none yet, so the
// enrolment offer has something to offer.
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

async function passwordLogin(
  ctx: Awaited<ReturnType<typeof setup>>,
  extra: Record<string, string> = {},
  cookie = '',
) {
  const q = new URLSearchParams({
    ...Object.fromEntries(await authorizeQuery(ctx)),
    ...extra,
  })
  const page = await ctx.app.request(`/oauth/authorize?${q}`, {
    headers: { cookie },
  })
  const jar = [cookie, cookiesOf(page)].filter(Boolean).join('; ')
  const res = await ctx.app.request('/oauth/authorize', {
    method: 'POST',
    headers: {
      cookie: jar,
      'content-type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      ...hiddenFields(await page.text()),
      email: ctx.email,
      password: 'pw123456',
    }),
    redirect: 'manual',
  })
  return { res, jar: [jar, cookiesOf(res)].filter(Boolean).join('; ') }
}

const links = (html: string) =>
  [...html.matchAll(/href="([^"]*)"/g)].map(([, h]) =>
    h.replaceAll('&amp;', '&')
  )

Deno.test('after a password sign-in the offer page is shown instead of a redirect', async () => {
  const ctx = await setup()
  const { res } = await passwordLogin(ctx)
  assertEquals(res.status, 200)
  const html = await res.text()
  assertStringIncludes(html, 'Create passkey')
  assertStringIncludes(html, 'Not now')
  assert(res.headers.getSetCookie().some((c) => c.startsWith('auth_session=')))
})

Deno.test('Not now remembers the choice and continues to the app', async () => {
  const ctx = await setup()
  const { res, jar } = await passwordLogin(ctx)
  const dismiss = links(await res.text()).find((h) =>
    h.startsWith('/oauth/passkeys/dismiss')
  )!
  const d = await ctx.app.request(dismiss, {
    headers: { cookie: jar },
    redirect: 'manual',
  })
  assertEquals(d.status, 302)
  assert(
    d.headers.getSetCookie().some((c) =>
      c.startsWith('auth_passkey_offer=dismissed')
    ),
  )
  const next = await ctx.app.request(d.headers.get('location')!, {
    headers: { cookie: jar },
    redirect: 'manual',
  })
  assertEquals(next.status, 302)
  assert(new URL(next.headers.get('location')!).searchParams.get('code'))
  // Next sign-in in this browser: straight to the app.
  const again = await passwordLogin(ctx, {}, cookiesOf(d))
  assertEquals(again.res.status, 302)
})

Deno.test('prompt=login keeps only its OIDC meaning: it does not override Not now', async () => {
  const ctx = await setup()
  const { res } = await passwordLogin(
    ctx,
    { prompt: 'login' },
    'auth_passkey_offer=dismissed',
  )
  // The dismiss cookie still holds: straight through to the app, no offer.
  assertEquals(res.status, 302)
})

Deno.test('passkey=add shows the offer even after Not now, and its links drop prompt and passkey', async () => {
  const ctx = await setup()
  const { res } = await passwordLogin(
    ctx,
    { prompt: 'login', passkey: 'add' },
    'auth_passkey_offer=dismissed',
  )
  assertEquals(res.status, 200)
  const html = await res.text()
  assertStringIncludes(html, 'Create passkey')
  for (const href of links(html)) {
    const params = new URL(href, 'http://test.local').searchParams
    assertEquals(params.has('prompt'), false, href)
    assertEquals(params.has('passkey'), false, href)
  }
})

Deno.test('an account already at the passkey limit gets no offer', async () => {
  const ctx = await setup()
  for (let i = 0; i < MAX_PASSKEYS; i++) {
    await ctx.passkeyRepo.create({
      id: crypto.randomUUID(),
      userId: ctx.user.id,
      credentialId: `c${i}`,
      credentialIdHash: await hashToken(`c${i}`),
      publicKey: 'cGs',
      counter: 0,
      transports: [],
      aaguid: '00000000-0000-0000-0000-000000000000',
      backedUp: false,
      createdAt: new Date(),
      lastUsedAt: null,
    })
  }
  // passkey=add would otherwise force the offer past a dismiss cookie -- the
  // limit must still win.
  const { res } = await passwordLogin(ctx, { passkey: 'add' })
  assertEquals(res.status, 302)
})

Deno.test('Create registers the passkey, which then signs in without an offer', async () => {
  const ctx = await setup()
  const { res, jar } = await passwordLogin(ctx)
  const csrf = hiddenFields(await res.text()).csrf_token
  const post = (path: string, fields: Record<string, string>) =>
    ctx.app.request(path, {
      method: 'POST',
      headers: {
        cookie: jar,
        'content-type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({ csrf_token: csrf, ...fields }),
    })
  const options = await (await post('/oauth/passkeys/register/options', {}))
    .json()
  const done = await post('/oauth/passkeys/register', {
    credential: JSON.stringify(await ctx.auth.register(options)),
  })
  assertEquals(done.status, 204)
  assertEquals((await ctx.passkeyRepo.listForUser(ctx.user.id)).length, 1)
  assertEquals((await passkeySignIn(ctx)).res.status, 302)
})

Deno.test('register needs a session and the CSRF token', async () => {
  const ctx = await setup()
  const page = await ctx.app.request(
    `/oauth/authorize?${await authorizeQuery(ctx)}`,
  )
  const cookie = cookiesOf(page)
  const csrf = hiddenFields(await page.text()).csrf_token
  const noSession = await ctx.app.request('/oauth/passkeys/register/options', {
    method: 'POST',
    headers: { cookie, 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ csrf_token: csrf }),
  })
  assertEquals(noSession.status, 403)
  assertEquals((await noSession.json()).error.code, 'fresh_login_required')
  const { jar } = await passwordLogin(ctx)
  const noCsrf = await ctx.app.request('/oauth/passkeys/register/options', {
    method: 'POST',
    headers: {
      cookie: jar,
      'content-type': 'application/x-www-form-urlencoded',
    },
    body: '',
  })
  assertEquals(noCsrf.status, 403)
  assertEquals((await noCsrf.json()).error.code, 'csrf_token_invalid')
})

Deno.test('with passkeys off a password sign-in redirects as before', async () => {
  const ctx = await setup({})
  assertEquals((await passwordLogin(ctx)).res.status, 302)
})
