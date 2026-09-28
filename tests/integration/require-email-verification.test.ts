import { assert, assertEquals } from '@std/assert'
import { authHeader, makeTestApp, submitLoginForm } from '../helpers.ts'
import { hashPassword } from '../../src/lib/password.ts'
import { s256Challenge } from '../../src/lib/pkce.ts'

// REQUIRE_EMAIL_VERIFICATION: an account with an email it has not verified
// gets no tokens and no session. The gate sits at every point that issues one
// -- password grant, login form, refresh grant, code exchange -- because
// refresh tokens slide: a gate at login alone would never reach anyone who
// already holds one.

const GATE = { REQUIRE_EMAIL_VERIFICATION: 'true' }
const PASSWORD = 'pw123456'
const VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
const REDIRECT = 'https://app.example/cb'
const NOT_VERIFIED = 'email address not verified'

type Ctx = ReturnType<typeof makeTestApp>

// Random names throughout: under `make test-db` every test shares one MySQL
// database between truncates.
async function seed(
  ctx: Ctx,
  { emailVerified, guest = false }: { emailVerified: boolean; guest?: boolean },
) {
  const now = new Date()
  const id = crypto.randomUUID()
  const email = guest ? null : `u-${id}@example.test`
  const username = guest ? `guest_${id.slice(0, 12)}` : undefined
  await ctx.userRepo.create({
    id,
    email,
    ...(username ? { username } : {}),
    passwordHash: await hashPassword(PASSWORD),
    emailVerified,
    createdAt: now,
    updatedAt: now,
  })
  const org = await ctx.orgRepo.createOrg({
    id: crypto.randomUUID(),
    slug: `org-${id}`,
    name: 'Org',
    createdAt: now,
  })
  const clientId = `cid_${id}`
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
  await ctx.orgRepo.addMember({
    id: crypto.randomUUID(),
    userId: id,
    orgId: org.id,
    createdAt: now,
  })
  return { id, email, login: email ?? username!, audience, clientId }
}

const form = (params: Record<string, string>) => ({
  method: 'POST',
  headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams(params).toString(),
})

const passwordGrant = (
  ctx: Ctx,
  s: Awaited<ReturnType<typeof seed>>,
  password = PASSWORD,
) =>
  ctx.app.request(
    '/oauth/token',
    form({
      grant_type: 'password',
      username: s.login,
      password,
      audience: s.audience,
    }),
  )

async function assertBlocked(res: Response, description = NOT_VERIFIED) {
  assertEquals(res.status, 400)
  assertEquals(await res.json(), {
    error: 'invalid_grant',
    error_description: description,
  })
}

// ---- the flag is off by default: nothing changes -------------------------

Deno.test('with the flag off, an unverified account signs in as before', async () => {
  const ctx = makeTestApp()
  const s = await seed(ctx, { emailVerified: false })
  assertEquals((await passwordGrant(ctx, s)).status, 200)
})

// ---- checkpoint 1: password grant ----------------------------------------

Deno.test('password grant: an unverified account is refused', async () => {
  const ctx = makeTestApp(GATE)
  const s = await seed(ctx, { emailVerified: false })
  await assertBlocked(await passwordGrant(ctx, s))
})

Deno.test('password grant: a wrong password on an unverified account says invalid credentials, not unverified', async () => {
  // The gate runs only AFTER the password is proven. Otherwise anyone could
  // learn which addresses belong to unverified accounts without knowing a
  // single password.
  const ctx = makeTestApp(GATE)
  const s = await seed(ctx, { emailVerified: false })
  await assertBlocked(
    await passwordGrant(ctx, s, 'not-the-password'),
    'invalid credentials',
  )
})

Deno.test('password grant: a verified account is let through', async () => {
  const ctx = makeTestApp(GATE)
  const s = await seed(ctx, { emailVerified: true })
  assertEquals((await passwordGrant(ctx, s)).status, 200)
})

Deno.test('password grant: a guest has no email to verify and is let through', async () => {
  const ctx = makeTestApp(GATE)
  const s = await seed(ctx, { emailVerified: false, guest: true })
  assertEquals((await passwordGrant(ctx, s)).status, 200)
})

// ---- checkpoint 2: refresh grant -----------------------------------------

Deno.test('refresh grant: a token held by an account that is now unverified is refused', async () => {
  // Refresh tokens slide, so this is the path that would otherwise keep an
  // unverified account alive forever. Losing verification is what confirming
  // an email change does to an account.
  const ctx = makeTestApp(GATE)
  const s = await seed(ctx, { emailVerified: true })
  const pair = await (await passwordGrant(ctx, s)).json()
  await ctx.userRepo.update(s.id, { emailVerified: false })

  await assertBlocked(
    await ctx.app.request(
      '/oauth/token',
      form({ grant_type: 'refresh_token', refresh_token: pair.refresh_token }),
    ),
  )
})

// ---- checkpoint 3: login form --------------------------------------------

Deno.test('login form: an unverified account gets a verify message and no session', async () => {
  const ctx = makeTestApp(GATE)
  const s = await seed(ctx, { emailVerified: false })
  const res = await submitLoginForm(ctx.app, {
    email: s.login,
    password: PASSWORD,
    client_id: s.clientId,
    redirect_uri: REDIRECT,
    scope: '',
    state: 'xyz',
    code_challenge: await s256Challenge(VERIFIER),
    code_challenge_method: 'S256',
  })

  assertEquals(res.status, 403)
  assert(
    !(res.headers.get('set-cookie') ?? '').includes('auth_session='),
    'no SSO session may be created for an unverified account',
  )
  const page = await res.text()
  assert(page.includes('verify'), 'the page must say what is wrong')
  assert(
    !page.includes('Invalid email or password'),
    'the right password must not be reported as wrong',
  )
})

// ---- checkpoint 4: authorization-code exchange ---------------------------

Deno.test('code exchange: a code issued to an account that is now unverified is refused', async () => {
  // Isolates the exchange's own gate: login succeeds (verified), and only the
  // exchange sees the account unverified.
  const ctx = makeTestApp(GATE)
  const s = await seed(ctx, { emailVerified: true })
  const login = await submitLoginForm(ctx.app, {
    email: s.login,
    password: PASSWORD,
    client_id: s.clientId,
    redirect_uri: REDIRECT,
    scope: '',
    state: 'xyz',
    code_challenge: await s256Challenge(VERIFIER),
    code_challenge_method: 'S256',
  })
  assertEquals(login.status, 302, 'setup: a verified login issues a code')
  const code = new URL(login.headers.get('location')!).searchParams.get('code')!
  await ctx.userRepo.update(s.id, { emailVerified: false })

  await assertBlocked(
    await ctx.app.request(
      '/oauth/token',
      form({
        grant_type: 'authorization_code',
        code,
        redirect_uri: REDIRECT,
        code_verifier: VERIFIER,
        client_id: s.clientId,
      }),
    ),
  )
})

// ---- supporting fix: an email change sends the new address a link --------

Deno.test('confirming an email change sends a verification link to the new address', async () => {
  // Confirming from the old address authorises the move but leaves the new
  // address unverified. Without a link to it, the gate above would lock the
  // user out with nothing in their inbox.
  const ctx = makeTestApp()
  const s = await seed(ctx, { emailVerified: true })
  const { Authorization } = await authHeader(
    ctx.app,
    s.login,
    PASSWORD,
    s.audience,
  )
  const next = `new-${crypto.randomUUID()}@example.test`
  const change = await ctx.app.request(`/users/${s.id}`, {
    method: 'PATCH',
    headers: { Authorization, 'content-type': 'application/json' },
    body: JSON.stringify({ email: next }),
  })
  assertEquals(change.status, 202, 'setup: the change is held for confirmation')
  const confirmLink = new URL(ctx.sentEmails.at(-1)!.link)

  const confirmed = await ctx.app.request(
    confirmLink.pathname + confirmLink.search,
  )
  assertEquals(confirmed.status, 200, 'setup: the change is confirmed')

  const last = ctx.sentEmails.at(-1)!
  assertEquals(last.to, next)
  assertEquals(last.purpose, 'verify_email')
})
