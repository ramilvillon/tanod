import { assert, assertEquals } from '@std/assert'
import { makeTestApp } from '../helpers.ts'
import { s256Challenge } from '../../src/lib/pkce.ts'

const VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
const REDIRECT = 'https://app.example/cb'

async function seed(ctx: ReturnType<typeof makeTestApp>) {
  await ctx.app.request('/users', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'mallory@evil.test', password: 'pw123456' }),
  })
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
  const user = await ctx.userRepo.findByEmail('mallory@evil.test')
  await ctx.orgRepo.addMember({
    id: crypto.randomUUID(),
    userId: user!.id,
    orgId: org.id,
    createdAt: now,
  })
}

const form = (challenge: string, extra: Record<string, string> = {}) =>
  new URLSearchParams({
    email: 'mallory@evil.test',
    password: 'pw123456',
    client_id: 'cid_app',
    redirect_uri: REDIRECT,
    scope: '',
    state: 'xyz',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    ...extra,
  }).toString()

const post = (
  ctx: ReturnType<typeof makeTestApp>,
  body: string,
  cookie?: string,
) =>
  ctx.app.request('/oauth/authorize', {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      ...(cookie ? { cookie } : {}),
    },
    body,
    redirect: 'manual',
  })

// Everything the browser would send back, and the token the form would carry.
const cookies = (res: Response) =>
  res.headers.getSetCookie().map((c) => c.split(';')[0]).join('; ')
const fieldOf = (html: string, name: string) =>
  html.match(new RegExp(`name="${name}" value="([^"]*)"`))?.[1]

Deno.test('a login POST with no CSRF token is refused', async () => {
  const ctx = makeTestApp()
  await seed(ctx)
  const challenge = await s256Challenge(VERIFIER)

  // Mallory's page auto-submits this from Dana's browser. The credentials are
  // valid -- they are Mallory's own -- so credentials alone cannot stop it.
  const res = await post(ctx, form(challenge))

  assertEquals(
    res.status,
    403,
    'a form post with no CSRF token must be refused',
  )
  assertEquals(
    res.headers.getSetCookie().some((c) => c.startsWith('auth_session=')),
    false,
    'no session may be established for the victim',
  )
})

const getLoginPage = (
  ctx: ReturnType<typeof makeTestApp>,
  challenge: string,
  cookie?: string,
) =>
  ctx.app.request(
    `/oauth/authorize?client_id=cid_app&redirect_uri=${
      encodeURIComponent(REDIRECT)
    }&scope=&state=xyz&code_challenge=${challenge}&code_challenge_method=S256`,
    { headers: cookie ? { cookie } : {} },
  )

Deno.test('the ordinary login flow still works: rendered token matches its cookie', async () => {
  const ctx = makeTestApp()
  await seed(ctx)
  const challenge = await s256Challenge(VERIFIER)

  const page = await getLoginPage(ctx, challenge)
  const token = fieldOf(await page.text(), 'csrf_token')
  assert(token, 'the form must carry a csrf_token')

  const res = await post(
    ctx,
    form(challenge, { csrf_token: token }),
    cookies(page),
  )
  assertEquals(res.status, 302)
  assert(new URL(res.headers.get('location')!).searchParams.get('code'))
})

Deno.test('a forged csrf_token that does not match the cookie is refused', async () => {
  const ctx = makeTestApp()
  await seed(ctx)
  const challenge = await s256Challenge(VERIFIER)
  const page = await getLoginPage(ctx, challenge)

  // Mallory can write the form field. She cannot write the cookie.
  const res = await post(
    ctx,
    form(challenge, { csrf_token: 'a-value-mallory-chose' }),
    cookies(page),
  )
  assertEquals(res.status, 403)
})

Deno.test('the token survives a wrong-password retry', async () => {
  const ctx = makeTestApp()
  await seed(ctx)
  const challenge = await s256Challenge(VERIFIER)
  const page = await getLoginPage(ctx, challenge)
  const cookie = cookies(page)
  const token = fieldOf(await page.text(), 'csrf_token')!

  // The failed attempt re-renders this very page. Minting a fresh token here
  // is what broke the previous attempt: the retry then failed as a CSRF error
  // instead of succeeding.
  const wrong = await post(
    ctx,
    form(challenge, { csrf_token: token, password: 'wrong-password' }),
    cookie,
  )
  assertEquals(wrong.status, 401)
  assertEquals(
    fieldOf(await wrong.text(), 'csrf_token'),
    token,
    'the retry form must carry the same token',
  )

  const retry = await post(ctx, form(challenge, { csrf_token: token }), cookie)
  assertEquals(retry.status, 302, 'the corrected retry must succeed')
})

Deno.test('a second tab does not invalidate the first', async () => {
  const ctx = makeTestApp()
  await seed(ctx)
  const challenge = await s256Challenge(VERIFIER)

  const tab1 = await getLoginPage(ctx, challenge)
  const cookie = cookies(tab1)
  const token1 = fieldOf(await tab1.text(), 'csrf_token')!
  // Second tab, same browser, so it carries the cookie the first one set.
  const tab2 = await getLoginPage(ctx, challenge, cookie)
  const token2 = fieldOf(await tab2.text(), 'csrf_token')!

  assertEquals(
    token2,
    token1,
    're-rendering must reuse the cookie, not re-mint',
  )
  // Submitting the older tab still works — the back button relies on this too.
  assertEquals(
    (await post(ctx, form(challenge, { csrf_token: token1 }), cookie)).status,
    302,
  )
})

Deno.test('a non-browser client gets a diagnosable JSON error, not the login page', async () => {
  const ctx = makeTestApp()
  await seed(ctx)
  const challenge = await s256Challenge(VERIFIER)

  const res = await ctx.app.request('/oauth/authorize', {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      accept: 'application/json',
    },
    body: form(challenge),
    redirect: 'manual',
  })

  assertEquals(res.status, 403)
  assert(
    res.headers.get('content-type')?.includes('application/json'),
    'a client that did not ask for HTML must not be handed a login page',
  )
  const body = await res.json()
  // A stable code, so a caller can tell a protocol mistake from bad credentials
  // instead of retrying a login that will never succeed.
  assertEquals(body.error.code, 'csrf_token_invalid')
  assert(
    body.error.message.includes('/oauth/authorize'),
    'the message must say how to obtain a token',
  )
})

Deno.test('a browser still gets the form back so the human can simply retry', async () => {
  const ctx = makeTestApp()
  await seed(ctx)
  const challenge = await s256Challenge(VERIFIER)

  const res = await ctx.app.request('/oauth/authorize', {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      accept: 'text/html,application/xhtml+xml',
    },
    body: form(challenge),
    redirect: 'manual',
  })

  assertEquals(res.status, 403)
  const html = await res.text()
  assert(html.includes('<form'), 'the human needs a working form, not JSON')
  assert(fieldOf(html, 'csrf_token'), 'and it must carry a usable token')
  assert(
    !html.includes('session expired'),
    'nothing expired: there was never a session, and saying so invites a pointless retry',
  )
})
