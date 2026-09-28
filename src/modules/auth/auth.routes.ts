import { Hono } from 'hono'
import { deleteCookie, getCookie, setCookie } from 'hono/cookie'
import { googleAuth } from '@hono/oauth-providers/google'
import { describeRoute } from 'hono-openapi'
import { resolver, validator } from 'hono-openapi/zod'
import { createSchema } from 'zod-openapi'
import type { OpenAPIV3 } from 'openapi-types'
import type { AppEnv } from '../../deps.ts'
import {
  authorizeFormSchema,
  authorizeQuerySchema,
  oauthErrorSchema,
  revokeSchema,
  tokenPairSchema,
  tokenRequestSchema,
  totpFormSchema,
} from './auth.schema.ts'
import { totpPage } from './totp-page.ts'
import type { LoginResult } from './auth.service.ts'
import { signMfaChallenge, verifyMfaChallenge } from '../../lib/jwt.ts'
import { AppError, type ErrorCode } from '../../lib/errors.ts'
import type { Context } from 'hono'
import type { z } from 'zod'
import {
  type AuthorizeQuery,
  csrfRefused,
  csrfToken,
  finishHostedLogin,
  GOOGLE_PATH,
  redirectTo,
  renderLogin,
  secureCookies,
  SESSION_COOKIE,
} from './hosted.ts'

// Allow-list, not a fall-through arm: the last ternary used to catch everything
// that was not one of the first three, so a grant type added to the schema would
// have been dispatched as client_credentials. `never` makes that a compile error.
function unsupportedGrant(_: never): never {
  throw AppError.of('unsupported_grant_type')
}

type OAuthError = z.infer<typeof oauthErrorSchema>['error']

// Catalogue code -> RFC 6749 section 5.2 code, for the token endpoints only.
// Allow-list: a catalogue code with no entry here is rethrown to app.onError
// and rendered the old way -- visibly wrong, rather than silently relabelled
// with a guessed RFC code.
const OAUTH_ERRORS: Partial<Record<ErrorCode, OAuthError>> = {
  invalid_request: 'invalid_request',
  invalid_client: 'invalid_client',
  unsupported_grant_type: 'unsupported_grant_type',
  // Credentials, a refresh token, or the grant itself is bad, expired, revoked,
  // replayed, or not usable by this subject: RFC 6749 has one code for all.
  invalid_grant: 'invalid_grant',
  invalid_credentials: 'invalid_grant',
  invalid_refresh_token: 'invalid_grant',
  refresh_token_reuse: 'invalid_grant',
  not_org_member: 'invalid_grant',
  email_not_verified: 'invalid_grant',
  // RFC 8707's code for an audience/resource the server does not know.
  unknown_audience: 'invalid_target',
  mfa_required: 'mfa_required',
}

function oauthError(c: Context, err: unknown, usedBasic = false): Response {
  if (!(err instanceof AppError)) throw err
  const error = OAUTH_ERRORS[err.code]
  if (!error) throw err
  // Section 5.2: a client that authenticated with the Authorization header
  // gets a challenge for the same scheme when that authentication fails.
  if (error === 'invalid_client' && usedBasic) {
    c.header('WWW-Authenticate', 'Basic realm="auth"')
  }
  // 400 for everything except a failed client authentication (section 5.2).
  // The catalogue message rides along as the description, so the specific
  // reason stays readable without adding anything a caller could not already
  // see.
  return c.json(
    { error, error_description: err.message },
    error === 'invalid_client' ? 401 : 400,
  )
}

// RFC 6749 section 3.2: the token endpoints take application/x-www-form-
// urlencoded, which is what every standard OAuth client library sends. JSON is
// accepted too: every caller written before form support sends it, and the RFC
// does not forbid a server understanding more. Anything else reads as no body.
async function readParams(c: Context): Promise<unknown> {
  const type = (c.req.header('content-type') ?? '').toLowerCase()
  if (type.startsWith('application/x-www-form-urlencoded')) {
    return Object.fromEntries(new URLSearchParams(await c.req.text()))
  }
  if (type.startsWith('application/json')) {
    return await c.req.json().catch(() => undefined)
  }
  return undefined
}

// Replaces validator('json'): its failure response is a raw zod dump, which is
// neither an RFC error nor something to show a client (it describes the
// internal schema).
function parseParams<S extends z.ZodTypeAny>(
  raw: unknown,
  schema: S,
): z.infer<S> {
  const parsed = schema.safeParse(raw)
  if (parsed.success) return parsed.data
  // A grant_type that is present but not one of ours has its own RFC code; a
  // missing one is just a malformed request.
  const grant = (raw as { grant_type?: unknown } | null | undefined)
    ?.grant_type
  if (
    typeof grant === 'string' &&
    parsed.error.issues.some((i: z.ZodIssue) => i.path[0] === 'grant_type')
  ) {
    throw AppError.of('unsupported_grant_type')
  }
  const at = parsed.error.issues[0]?.path.join('.')
  throw AppError.of(
    'invalid_request',
    at ? `invalid or missing parameter: ${at}` : undefined,
  )
}

// RFC 6749 section 2.3.1, client_secret_basic. Each half is form-urlencoded
// BEFORE the base64 step, so it is form-decoded after. undefined means the
// request carries no Basic header; a malformed one is a failed client
// authentication, not a malformed request.
function basicCredentials(
  header: string | undefined,
): { id: string; secret: string } | undefined {
  const match = /^basic(?:\s+(.*))?$/i.exec(header ?? '')
  if (!match) return undefined
  try {
    const pair = atob(match[1] ?? '')
    const colon = pair.indexOf(':')
    if (colon < 0) throw new Error('no colon')
    const form = (v: string) => decodeURIComponent(v.replaceAll('+', ' '))
    return {
      id: form(pair.slice(0, colon)),
      secret: form(pair.slice(colon + 1)),
    }
  } catch {
    throw AppError.of('invalid_client')
  }
}

// Folds Basic credentials into the body parameters, so everything that
// authenticates a client reads them exactly as it would client_secret_post.
// The password grant does not authenticate a client and drops them at the
// schema -- openid-client sends them on every request, so ignoring beats
// refusing.
function withBasic(
  raw: unknown,
  basic: { id: string; secret: string } | undefined,
): unknown {
  if (!basic || typeof raw !== 'object' || raw === null) return raw
  const params = raw as Record<string, unknown>
  // Section 2.3.1: a client MUST NOT use more than one method per request.
  if (params.client_secret !== undefined) {
    throw AppError.of(
      'invalid_request',
      'more than one client authentication method: Basic and client_secret',
    )
  }
  if (params.client_id !== undefined && params.client_id !== basic.id) {
    throw AppError.of(
      'invalid_request',
      'client_id does not match the Authorization header',
    )
  }
  return { ...params, client_id: basic.id, client_secret: basic.secret }
}

// Documents what parseParams accepts. There is no validator left for
// hono-openapi to derive the request body from, and describeRoute's
// requestBody takes a plain schema rather than a resolver, so zod-openapi (an
// existing dependency) converts it up front.
function oauthParams(schema: z.ZodTypeAny): OpenAPIV3.RequestBodyObject {
  // zod-openapi types its output as an OpenAPI 3.1 schema, hono-openapi wants
  // openapi-types' 3.0 one; the value is plain JSON Schema either way and is
  // only ever serialised into /openapi.
  const body = createSchema(schema).schema as OpenAPIV3.SchemaObject
  return {
    required: true,
    content: {
      'application/x-www-form-urlencoded': { schema: body },
      'application/json': { schema: body },
    },
  }
}

const json = (schema: ReturnType<typeof resolver>) => ({
  'application/json': { schema },
})

// The signed half-finished login between the first factor and the code.
// Scoped to /oauth: only /oauth/authorize/totp reads it.
const MFA_COOKIE = 'auth_mfa'
const MFA_PATH = '/oauth'
const MFA_CHALLENGE_TTL = 300
const MFA_CODE_ERROR = 'That code is not valid. Check your authenticator ' +
  'app or use a recovery code. After too many attempts, sign-in pauses for a while.'
// The authorize request a Google login resumes. Google echoes back only `code`
// and `state`, and `state` belongs to googleAuth, so the request rides in a
// cookie of our own, scoped to the one route that reads it.
const GOOGLE_AUTHORIZE_COOKIE = 'auth_google_authorize'

function renderTotp(
  c: Context<AppEnv>,
  q: AuthorizeQuery,
  error?: string,
  status: 200 | 401 = 200,
) {
  return c.html(totpPage({ ...q, csrf_token: csrfToken(c) }, error), status)
}

// First factor done, account has TOTP: no session yet. The challenge cookie
// says who passed the first factor; the page carries the authorize request.
async function startMfa(c: Context<AppEnv>, q: AuthorizeQuery, userId: string) {
  const challenge = await signMfaChallenge({
    sub: userId,
    issuer: c.var.config.issuer,
    privateKeyPem: c.var.keySet.privateKeyPem,
    kid: c.var.keySet.kid,
    ttlSeconds: MFA_CHALLENGE_TTL,
  })
  setCookie(c, MFA_COOKIE, challenge, {
    httpOnly: true,
    secure: secureCookies(c),
    sameSite: 'Lax',
    path: MFA_PATH,
    maxAge: MFA_CHALLENGE_TTL,
  })
  return renderTotp(c, q)
}

function pendingGoogleAuthorize(c: Context<AppEnv>): AuthorizeQuery | null {
  try {
    const parsed = authorizeQuerySchema.safeParse(
      JSON.parse(getCookie(c, GOOGLE_AUTHORIZE_COOKIE) ?? ''),
    )
    return parsed.success ? parsed.data : null
  } catch {
    return null
  }
}

// What the person at the login page is told when Google sign-in is refused.
// account_exists_link_password deliberately covers two cases; keep one message.
const GOOGLE_LOGIN_MESSAGES: Partial<Record<string, string>> = {
  google_email_unverified:
    "Your Google account's email address is not verified.",
  account_exists_link_password:
    'An account with this email already exists. Sign in with your password.',
}

function grant(c: Context<AppEnv>, body: z.infer<typeof tokenRequestSchema>) {
  const svc = c.var.authService
  return body.grant_type === 'password'
    ? svc.passwordGrant(body.username, body.password, body.audience)
    : body.grant_type === 'refresh_token'
    ? svc.refreshGrant(body.refresh_token, {
      id: body.client_id,
      secret: body.client_secret,
    })
    : body.grant_type === 'authorization_code'
    ? svc.exchangeAuthorizationCode({
      code: body.code,
      redirectUri: body.redirect_uri,
      codeVerifier: body.code_verifier,
      clientId: body.client_id,
      clientSecret: body.client_secret,
    })
    : body.grant_type === 'client_credentials'
    ? svc.clientCredentialsGrant(
      body.client_id,
      body.client_secret,
      body.audience,
    )
    : unsupportedGrant(body)
}

const auth = new Hono<AppEnv>()
  .post(
    '/token',
    describeRoute({
      tags: ['Auth'],
      summary:
        'Issue tokens (password, refresh_token, authorization_code or client_credentials grant)',
      requestBody: oauthParams(tokenRequestSchema),
      responses: {
        200: {
          description: 'A new access/refresh token pair',
          content: json(resolver(tokenPairSchema)),
        },
        400: {
          description: 'RFC 6749 error: invalid_request, invalid_grant, ' +
            'unsupported_grant_type or invalid_target',
          content: json(resolver(oauthErrorSchema)),
        },
        401: {
          description: 'RFC 6749 error: invalid_client. Carries ' +
            '`WWW-Authenticate: Basic` when the client authenticated with ' +
            'HTTP Basic (client_secret_basic).',
          content: json(resolver(oauthErrorSchema)),
        },
      },
    }),
    async (c) => {
      // Section 5.1: token responses must not be cached. Set before anything
      // can throw, so the error responses carry it too.
      c.header('Cache-Control', 'no-store')
      c.header('Pragma', 'no-cache')
      const authorization = c.req.header('authorization')
      // Decided before parsing, so a malformed Basic header still earns the
      // challenge on its invalid_client.
      const usedBasic = /^basic\b/i.test(authorization ?? '')
      try {
        const params = withBasic(
          await readParams(c),
          basicCredentials(authorization),
        )
        return c.json(
          await grant(c, parseParams(params, tokenRequestSchema)),
          200,
        )
      } catch (err) {
        return oauthError(c, err, usedBasic)
      }
    },
  )
  .post(
    '/revoke',
    describeRoute({
      tags: ['Auth'],
      summary: 'Revoke a refresh token',
      requestBody: oauthParams(revokeSchema),
      responses: {
        // RFC 7009 section 2.2 requires 200 here. A 204 is what this server sent
        // until an openid-client run proved standard libraries reject it.
        200: { description: 'Revoked (idempotent), empty body' },
        400: {
          description: 'RFC 6749 error: invalid_request',
          content: json(resolver(oauthErrorSchema)),
        },
        401: {
          description: 'RFC 6749 error: invalid_client -- a confidential ' +
            "client's token needs that client's credentials",
          content: json(resolver(oauthErrorSchema)),
        },
      },
    }),
    async (c) => {
      const authorization = c.req.header('authorization')
      const usedBasic = /^basic\b/i.test(authorization ?? '')
      try {
        const params = parseParams(
          withBasic(await readParams(c), basicCredentials(authorization)),
          revokeSchema,
        )
        await c.var.authService.revoke(
          (params.token ?? params.refresh_token)!,
          {
            id: params.client_id,
            secret: params.client_secret,
          },
        )
        return c.body(null, 200)
      } catch (err) {
        return oauthError(c, err, usedBasic)
      }
    },
  )
  .get(
    '/authorize',
    validator('query', authorizeQuerySchema),
    async (c) => {
      const q = c.req.valid('query')
      const service = await c.var.authService.validateAuthorizeRequest({
        clientId: q.client_id,
        redirectUri: q.redirect_uri,
        codeChallenge: q.code_challenge,
        codeChallengeMethod: q.code_challenge_method,
      })
      const sessionToken = getCookie(c, SESSION_COOKIE)
      // prompt=login is how an app gets a fresh auth_time (for a step-up such
      // as TOTP enrolment): the session is ignored, not ended.
      const forceLogin = q.prompt?.split(' ').includes('login')
      const session = sessionToken && !forceLogin
        ? await c.var.authService.resolveSession(sessionToken)
        : null
      if (!session) return renderLogin(c, q)
      const code = await c.var.authService.issueAuthorizationCode(
        session.userId,
        service,
        {
          redirectUri: q.redirect_uri,
          scope: q.scope,
          codeChallenge: q.code_challenge,
          codeChallengeMethod: q.code_challenge_method,
          nonce: q.nonce,
          authTime: session.authTime,
        },
      )
      return c.redirect(redirectTo(q.redirect_uri, { code, state: q.state }))
    },
  )
  .post(
    '/authorize',
    validator('form', authorizeFormSchema),
    async (c) => {
      const f = c.req.valid('form')
      const refused = csrfRefused(c, f, f.csrf_token)
      if (refused) return refused
      const service = await c.var.authService.validateAuthorizeRequest({
        clientId: f.client_id,
        redirectUri: f.redirect_uri,
        codeChallenge: f.code_challenge,
        codeChallengeMethod: f.code_challenge_method,
      })
      let login: LoginResult
      try {
        login = await c.var.authService.loginCreateSession(f.email, f.password)
      } catch (err) {
        // Only reachable with the right password (the gate runs after it), so
        // saying so reveals nothing to someone who does not already know it.
        if (err instanceof AppError && err.code === 'email_not_verified') {
          return renderLogin(
            c,
            f,
            'Please verify your email address before signing in. ' +
              'Check your inbox for the link, or request a new one.',
            403,
          )
        }
        return renderLogin(c, f, 'Invalid email or password', 401)
      }
      if (login.kind === 'mfa') return startMfa(c, f, login.userId)
      return finishHostedLogin(c, f, service, login, 'password')
    },
  )
  .post(
    '/authorize/totp',
    validator('form', totpFormSchema),
    async (c) => {
      const f = c.req.valid('form')
      const refused = csrfRefused(c, f, f.csrf_token)
      if (refused) return refused
      // Re-checked rather than trusted: the fields came back from the browser.
      const service = await c.var.authService.validateAuthorizeRequest({
        clientId: f.client_id,
        redirectUri: f.redirect_uri,
        codeChallenge: f.code_challenge,
        codeChallengeMethod: f.code_challenge_method,
      })
      const userId = await verifyMfaChallenge(
        getCookie(c, MFA_COOKIE) ?? '',
        c.var.keySet,
      )
      const timedOut = () =>
        renderLogin(c, f, 'Your sign-in timed out. Please sign in again.', 401)
      if (!userId) return timedOut()
      let login: { token: string; userId: string }
      try {
        login = await c.var.authService.completeMfaLogin(userId, f.code)
      } catch (err) {
        if (!(err instanceof AppError)) throw err
        // invalid_grant: the account went away while the challenge was live.
        if (err.code === 'invalid_grant') return timedOut()
        return renderTotp(c, f, MFA_CODE_ERROR, 401)
      }
      deleteCookie(c, MFA_COOKIE, { path: MFA_PATH })
      return finishHostedLogin(c, f, service, login, 'totp')
    },
  )
  .post('/logout', async (c) => {
    const sessionToken = getCookie(c, SESSION_COOKIE)
    if (sessionToken) await c.var.authService.logout(sessionToken)
    deleteCookie(c, SESSION_COOKIE, { path: '/' })
    return c.body(null, 204)
  })
  // Sign in with Google, as a step of the authorize flow. The login page links
  // here with the pending authorize request; this route remembers it, sends the
  // browser to Google, and on the way back finishes exactly like a password
  // login: SSO session, then an authorization code to the client's redirect_uri.
  // `googleAuth` serves both legs on this one route (it must equal
  // GOOGLE_REDIRECT_URI) and treats any request without a `code` as a start.
  .use('/google', async (c, next) => {
    const google = c.var.config.google
    if (!google.clientId) throw AppError.of('google_login_disabled')
    if (c.req.query('error')) {
      // Cancelled or refused at Google. There is no code, so googleAuth would
      // read this as a fresh start and bounce the user straight back to Google.
      const pending = pendingGoogleAuthorize(c)
      if (!pending) throw AppError.of('authorize_request_expired')
      return renderLogin(c, pending, 'Google sign-in was cancelled.', 401)
    }
    if (!c.req.query('code')) {
      const parsed = authorizeQuerySchema.safeParse(c.req.query())
      if (!parsed.success) throw AppError.of('invalid_request')
      const q = parsed.data
      // Refuse before leaving for Google, so a bad request never gets as far
      // as a consent screen.
      await c.var.authService.validateAuthorizeRequest({
        clientId: q.client_id,
        redirectUri: q.redirect_uri,
        codeChallenge: q.code_challenge,
        codeChallengeMethod: q.code_challenge_method,
      })
      setCookie(c, GOOGLE_AUTHORIZE_COOKIE, JSON.stringify(q), {
        httpOnly: true,
        secure: secureCookies(c),
        sameSite: 'Lax',
        path: GOOGLE_PATH,
        maxAge: 600,
      })
    }
    return googleAuth({
      client_id: google.clientId,
      client_secret: google.clientSecret,
      redirect_uri: google.redirectUri,
      scope: ['openid', 'email', 'profile'],
    })(c, next)
  })
  .get(
    '/google',
    describeRoute({
      tags: ['Auth'],
      summary: 'Sign in with Google (part of the authorize flow)',
      description:
        'Linked from the /oauth/authorize login page with the same query ' +
        'parameters. Redirects to Google; Google redirects back here, and the ' +
        'user is signed in and sent to redirect_uri with an authorization ' +
        'code, as after a password login.',
      responses: {
        302: {
          description:
            'To Google (start), or to redirect_uri with code and state (return)',
        },
        400: {
          description:
            'Invalid authorize parameters, or no sign-in in progress on return',
        },
        401: {
          description:
            'Login page with an error: cancelled at Google, bad state, or no profile',
        },
        403: {
          description:
            'Login page with an error: unverified Google email, or an existing account must sign in with its password',
        },
        404: { description: 'Google login is not configured' },
      },
    }),
    async (c) => {
      const pending = pendingGoogleAuthorize(c)
      if (!pending) throw AppError.of('authorize_request_expired')
      // Re-checked rather than trusted: the client may have changed since the
      // request was stored.
      const service = await c.var.authService.validateAuthorizeRequest({
        clientId: pending.client_id,
        redirectUri: pending.redirect_uri,
        codeChallenge: pending.code_challenge,
        codeChallengeMethod: pending.code_challenge_method,
      })
      const profile = c.get('user-google')
      if (!profile?.id || !profile.email) {
        return renderLogin(
          c,
          pending,
          'Google did not share an email address.',
          401,
        )
      }
      let login: LoginResult
      try {
        login = await c.var.authService.loginWithGoogle({
          providerAccountId: profile.id,
          email: profile.email,
          emailVerified: profile.verified_email ?? false,
        })
      } catch (e) {
        if (!(e instanceof AppError)) throw e
        return renderLogin(
          c,
          pending,
          GOOGLE_LOGIN_MESSAGES[e.code] ??
            'This Google account cannot be used to sign in.',
          e.status === 409 ? 409 : 403,
        )
      }
      deleteCookie(c, GOOGLE_AUTHORIZE_COOKIE, { path: GOOGLE_PATH })
      if (login.kind === 'mfa') return startMfa(c, pending, login.userId)
      return finishHostedLogin(c, pending, service, login, 'google')
    },
  )

export default auth
