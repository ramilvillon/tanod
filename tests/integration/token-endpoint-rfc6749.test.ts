import { assert, assertEquals } from '@std/assert'
import { makeTestApp, submitLoginForm } from '../helpers.ts'
import { hashPassword } from '../../src/lib/password.ts'
import { s256Challenge } from '../../src/lib/pkce.ts'
import { hashToken } from '../../src/lib/tokens.ts'

// RFC 6749 on /oauth/token and /oauth/revoke: form-encoded requests (what every
// standard OAuth client library sends), flat {error, error_description}
// bodies with the RFC's codes, and no-store on token responses. JSON requests
// keep working and are covered by every other suite that calls these routes.

const PASSWORD = 'pw123456'
const SECRET = 's3cret'
const VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
const REDIRECT = 'https://app.example/cb'

type Ctx = ReturnType<typeof makeTestApp>
type Seeded = Awaited<ReturnType<typeof seed>>

// Random names throughout: under `make test-db` every test shares one MySQL
// database between truncates, so nothing here may collide on a UNIQUE.
async function seed(ctx: Ctx, { member = true } = {}) {
  const now = new Date()
  const id = crypto.randomUUID()
  const email = `u-${id}@example.test`
  const user = await ctx.userRepo.create({
    id,
    email,
    passwordHash: await hashPassword(PASSWORD),
    createdAt: now,
    updatedAt: now,
  })
  const org = await ctx.orgRepo.createOrg({
    id: crypto.randomUUID(),
    slug: `org-${id}`,
    name: 'Org',
    createdAt: now,
  })
  const clientId = `cid_pub_${id}`
  const audience = `aud-${id}`
  await ctx.orgRepo.createService({
    id: crypto.randomUUID(),
    orgId: org.id,
    clientId,
    clientSecretHash: null,
    name: 'App',
    slug: 'app',
    audience,
    type: 'public',
    redirectUris: [REDIRECT],
    createdAt: now,
  })
  const confidentialId = `cid_conf_${id}`
  await ctx.orgRepo.createService({
    id: crypto.randomUUID(),
    orgId: org.id,
    clientId: confidentialId,
    clientSecretHash: await hashToken(SECRET),
    name: 'Backend',
    slug: 'backend',
    audience: `conf-${id}`,
    type: 'confidential',
    redirectUris: [],
    createdAt: now,
  })
  if (member) {
    await ctx.orgRepo.addMember({
      id: crypto.randomUUID(),
      userId: user.id,
      orgId: org.id,
      createdAt: now,
    })
  }
  return { email, audience, clientId, confidentialId }
}

const form = (params: Record<string, string>) => ({
  method: 'POST',
  headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams(params).toString(),
})

const passwordGrant = (s: Seeded, overrides: Record<string, string> = {}) =>
  form({
    grant_type: 'password',
    username: s.email,
    password: PASSWORD,
    audience: s.audience,
    ...overrides,
  })

async function refreshTokenFor(ctx: Ctx, s: Seeded): Promise<string> {
  const res = await ctx.app.request('/oauth/token', passwordGrant(s))
  assertEquals(res.status, 200, 'setup: password grant must succeed')
  return (await res.json()).refresh_token
}

// ---- form-encoded requests succeed for every grant, and for revoke ---------

Deno.test('password grant accepts a form-encoded body', async () => {
  const ctx = makeTestApp()
  const s = await seed(ctx)
  const res = await ctx.app.request('/oauth/token', passwordGrant(s))
  assertEquals(res.status, 200)
  const pair = await res.json()
  assert(pair.access_token && pair.refresh_token)
  assertEquals(pair.token_type, 'Bearer')
})

Deno.test('refresh_token grant accepts a form-encoded body', async () => {
  const ctx = makeTestApp()
  const s = await seed(ctx)
  const refresh = await refreshTokenFor(ctx, s)
  const res = await ctx.app.request(
    '/oauth/token',
    form({ grant_type: 'refresh_token', refresh_token: refresh }),
  )
  assertEquals(res.status, 200)
  assert((await res.json()).access_token)
})

Deno.test('authorization_code grant accepts a form-encoded body', async () => {
  const ctx = makeTestApp()
  const s = await seed(ctx)
  const login = await submitLoginForm(ctx.app, {
    email: s.email,
    password: PASSWORD,
    client_id: s.clientId,
    redirect_uri: REDIRECT,
    scope: '',
    state: 'xyz',
    code_challenge: await s256Challenge(VERIFIER),
    code_challenge_method: 'S256',
  })
  assertEquals(login.status, 302, 'setup: login must issue a code')
  const code = new URL(login.headers.get('location')!).searchParams.get('code')!

  const res = await ctx.app.request(
    '/oauth/token',
    form({
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT,
      code_verifier: VERIFIER,
      client_id: s.clientId,
    }),
  )
  assertEquals(res.status, 200)
  assert((await res.json()).access_token)
})

Deno.test('client_credentials grant accepts a form-encoded body', async () => {
  const ctx = makeTestApp()
  const s = await seed(ctx)
  const res = await ctx.app.request(
    '/oauth/token',
    form({
      grant_type: 'client_credentials',
      client_id: s.confidentialId,
      client_secret: SECRET,
      audience: s.audience,
    }),
  )
  assertEquals(res.status, 200)
  assert((await res.json()).access_token)
})

Deno.test('revoke accepts a form-encoded body and the token stops working', async () => {
  const ctx = makeTestApp()
  const s = await seed(ctx)
  const refresh = await refreshTokenFor(ctx, s)

  const revoked = await ctx.app.request(
    '/oauth/revoke',
    form({ refresh_token: refresh }),
  )
  assertEquals(revoked.status, 200)

  const reuse = await ctx.app.request(
    '/oauth/token',
    form({ grant_type: 'refresh_token', refresh_token: refresh }),
  )
  assertEquals(reuse.status, 400, 'a revoked token must not mint anything')
})

// RFC 7009 section 2.1 names the parameter `token`, with an optional
// `token_type_hint`. this server only accepted `refresh_token`, so no standard client
// could revoke anything -- found by driving the API with openid-client.
Deno.test('revoke accepts the RFC 7009 `token` parameter', async () => {
  const ctx = makeTestApp()
  const s = await seed(ctx)
  const refresh = await refreshTokenFor(ctx, s)

  const revoked = await ctx.app.request(
    '/oauth/revoke',
    form({ token: refresh, token_type_hint: 'refresh_token' }),
  )
  assertEquals(revoked.status, 200)

  const reuse = await ctx.app.request(
    '/oauth/token',
    form({ grant_type: 'refresh_token', refresh_token: refresh }),
  )
  assertEquals(reuse.status, 400, 'a revoked token must not mint anything')
})

// An unknown token is "already not valid", which is the state the caller asked
// for. RFC 7009 section 2.2 requires a success response.
Deno.test('revoke of an unknown token is still a success', async () => {
  const ctx = makeTestApp()
  await seed(ctx)
  assertEquals(
    (await ctx.app.request('/oauth/revoke', form({ token: 'nope' }))).status,
    200,
  )
})

// ---- every failure is a flat RFC 6749 section 5.2 body -----------------------

type ErrorCase = {
  name: string
  status: number
  error: string
  request: (ctx: Ctx, s: Seeded) => Response | Promise<Response>
  seedOpts?: { member: boolean }
  path?: string
}

type Init = { method: string; headers: Record<string, string>; body: string }
const token = (ctx: Ctx, init: Init) => ctx.app.request('/oauth/token', init)

const ERROR_CASES: ErrorCase[] = [
  {
    name: 'a required parameter is missing',
    status: 400,
    error: 'invalid_request',
    request: (ctx) => token(ctx, form({ grant_type: 'refresh_token' })),
  },
  {
    name: 'grant_type is missing',
    status: 400,
    error: 'invalid_request',
    request: (ctx) => token(ctx, form({ refresh_token: 'x' })),
  },
  {
    name: 'the body is neither form nor JSON',
    status: 400,
    error: 'invalid_request',
    request: (ctx) =>
      token(ctx, {
        method: 'POST',
        headers: { 'content-type': 'text/plain' },
        body: 'grant_type=refresh_token&refresh_token=x',
      }),
  },
  {
    name: 'the JSON body does not parse',
    status: 400,
    error: 'invalid_request',
    request: (ctx) =>
      token(ctx, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: '{"grant_type":',
      }),
  },
  {
    name: 'grant_type is one this server does not implement',
    status: 400,
    error: 'unsupported_grant_type',
    request: (ctx) =>
      token(
        ctx,
        form({ grant_type: 'urn:ietf:params:oauth:grant-type:device_code' }),
      ),
  },
  {
    name: 'the password is wrong',
    status: 400,
    error: 'invalid_grant',
    request: (ctx, s) =>
      token(ctx, passwordGrant(s, { password: 'not-the-password' })),
  },
  {
    name: 'the user is not a member of the audience org',
    status: 400,
    error: 'invalid_grant',
    seedOpts: { member: false },
    request: (ctx, s) => token(ctx, passwordGrant(s)),
  },
  {
    name: 'the audience does not exist',
    status: 400,
    error: 'invalid_target',
    request: (ctx, s) =>
      token(ctx, passwordGrant(s, { audience: 'no-such-audience' })),
  },
  {
    name: 'the refresh token is unknown',
    status: 400,
    error: 'invalid_grant',
    request: (ctx) =>
      token(
        ctx,
        form({ grant_type: 'refresh_token', refresh_token: 'not-a-token' }),
      ),
  },
  {
    name: 'a rotated refresh token is replayed',
    status: 400,
    error: 'invalid_grant',
    request: async (ctx, s) => {
      const first = await refreshTokenFor(ctx, s)
      const rotated = await token(
        ctx,
        form({ grant_type: 'refresh_token', refresh_token: first }),
      )
      assertEquals(rotated.status, 200, 'setup: first rotation must succeed')
      return token(
        ctx,
        form({ grant_type: 'refresh_token', refresh_token: first }),
      )
    },
  },
  {
    name: 'the client secret is wrong',
    status: 401,
    error: 'invalid_client',
    request: (ctx, s) =>
      token(
        ctx,
        form({
          grant_type: 'client_credentials',
          client_id: s.confidentialId,
          client_secret: 'wrong',
          audience: s.audience,
        }),
      ),
  },
  {
    name: 'revoke is called without a token',
    status: 400,
    error: 'invalid_request',
    path: '/oauth/revoke',
    request: (ctx) => ctx.app.request('/oauth/revoke', form({})),
  },
]

for (const c of ERROR_CASES) {
  Deno.test(`${c.path ?? '/oauth/token'}: ${c.name} -> ${c.status} ${c.error}`, async () => {
    const ctx = makeTestApp()
    const s = await seed(ctx, c.seedOpts)
    const res = await c.request(ctx, s)
    const body = await res.json()

    assertEquals(res.status, c.status)
    assertEquals(body.error, c.error)
    // Exactly the RFC's two members: no nested {code, message} object, and no
    // validator dump describing the internal schema.
    assertEquals(Object.keys(body).sort(), ['error', 'error_description'])
    assertEquals(typeof body.error_description, 'string')
  })
}

// ---- RFC 6749 section 5.1: token responses must not be cached --------------

Deno.test('token responses are marked no-store, success and failure alike', async () => {
  const ctx = makeTestApp()
  const s = await seed(ctx)
  const ok = await ctx.app.request('/oauth/token', passwordGrant(s))
  const bad = await ctx.app.request(
    '/oauth/token',
    passwordGrant(s, { password: 'wrong' }),
  )

  for (const [label, res] of [['success', ok], ['failure', bad]] as const) {
    assertEquals(res.headers.get('cache-control'), 'no-store', label)
    assertEquals(res.headers.get('pragma'), 'no-cache', label)
  }
})
