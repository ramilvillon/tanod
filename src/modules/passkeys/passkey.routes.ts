import { Hono } from 'hono'
import { createMiddleware } from 'hono/factory'
import { getCookie, setCookie } from 'hono/cookie'
import { validator } from 'hono-openapi/zod'
import { describeRoute } from 'hono-openapi'
import { z } from 'zod'
import type { Context } from 'hono'
import type { AppEnv } from '../../deps.ts'
import { AppError } from '../../lib/errors.ts'
import { requireAuth } from '../../middleware/auth.ts'
import {
  authorizeQuerySchema,
  csrfOnlySchema,
  passkeyFormSchema,
} from '../auth/auth.schema.ts'
import {
  authorizeParams,
  csrfRefused,
  finishHostedLogin,
  PASSKEY_OFFER_COOKIE,
  renderLogin,
  requireCsrf,
  secureCookies,
  SESSION_COOKIE,
} from '../auth/hosted.ts'

const PASSKEY_FAILED = "That passkey couldn't be used."

// First on every passkey route: with passkeys off the routes must look
// absent (404), not forbidden -- so this runs before the CSRF check.
const passkeysOn = createMiddleware<AppEnv>(async (c, next) => {
  if (!c.var.passkeyService.enabled) {
    throw AppError.of('passkey_not_configured')
  }
  await next()
})

// The assertion arrives as a JSON string in a form field. Anything that is
// not JSON is just another unusable passkey.
export function parseCredential(s: string): unknown {
  try {
    return JSON.parse(s)
  } catch {
    throw AppError.of('passkey_invalid')
  }
}

// The SSO session is the authentication here: these run on this server's own page
// straight after a sign-in. No session reads as "sign in again".
async function signedInSession(c: Context<AppEnv>) {
  const token = getCookie(c, SESSION_COOKIE)
  const session = token ? await c.var.authService.resolveSession(token) : null
  if (!session) throw AppError.of('fresh_login_required')
  return session
}

// Mounted at /oauth. Rate limiting (app.ts): /authorize/passkey shares the
// strict `login` IP budget with the password and TOTP routes; its /options
// sibling gets its own `passkey-options` budget since it only mints a
// challenge and proves nothing about a credential. The register/dismiss
// routes below carry no route-specific limiter -- they need a fresh SSO
// session already, so there is no unauthenticated credential attempt to
// throttle; only the lenient global limiter applies.
const passkeys = new Hono<AppEnv>()
  .post(
    '/authorize/passkey/options',
    passkeysOn,
    validator('form', csrfOnlySchema),
    async (c) => {
      requireCsrf(c, c.req.valid('form').csrf_token)
      return c.json(await c.var.passkeyService.signInOptions(), 200)
    },
  )
  .post(
    '/authorize/passkey',
    passkeysOn,
    validator('form', passkeyFormSchema),
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
      let session: { token: string; userId: string }
      try {
        const userId = await c.var.passkeyService.verifySignIn(
          parseCredential(f.credential),
        )
        session = await c.var.authService.createPasskeySession(userId)
      } catch (err) {
        // A script (no text/html in Accept) gets the JSON error, as the CSRF
        // path already does -- an HTML re-render would be wasted on a caller
        // that cannot show it.
        if (!c.req.header('accept')?.includes('text/html')) throw err
        if (!(err instanceof AppError)) throw err
        // Only reachable with a valid passkey, so it reveals nothing.
        if (err.code === 'email_not_verified') {
          return renderLogin(
            c,
            f,
            'Please verify your email address before signing in. ' +
              'Check your inbox for the link, or request a new one.',
            403,
          )
        }
        return renderLogin(c, f, PASSKEY_FAILED, 401)
      }
      return finishHostedLogin(c, f, service, session, 'passkey')
    },
  )
  .get(
    '/passkeys/dismiss',
    passkeysOn,
    validator('query', authorizeQuerySchema),
    (c) => {
      setCookie(c, PASSKEY_OFFER_COOKIE, 'dismissed', {
        httpOnly: true,
        secure: secureCookies(c),
        sameSite: 'Lax',
        path: '/oauth',
        maxAge: 30 * 24 * 3600,
      })
      // Our own authorize route, which validates the request again.
      return c.redirect(
        `/oauth/authorize?${authorizeParams(c.req.valid('query'))}`,
      )
    },
  )
  .post(
    '/passkeys/register/options',
    passkeysOn,
    validator('form', csrfOnlySchema),
    async (c) => {
      requireCsrf(c, c.req.valid('form').csrf_token)
      const session = await signedInSession(c)
      return c.json(
        await c.var.passkeyService.registrationOptions(
          session.userId,
          session.authTime,
        ),
        200,
      )
    },
  )
  .post(
    '/passkeys/register',
    passkeysOn,
    validator(
      'form',
      csrfOnlySchema.extend({ credential: z.string().min(1).max(20_000) }),
    ),
    async (c) => {
      const f = c.req.valid('form')
      requireCsrf(c, f.csrf_token)
      const session = await signedInSession(c)
      // No freshness re-check: the challenge came from a fresh session and
      // lives 5 minutes, and it is bound to this user.
      await c.var.passkeyService.register(
        session.userId,
        parseCredential(f.credential),
      )
      return c.body(null, 204)
    },
  )

const NOT_CONFIGURED = 'Passkeys are not configured, or the token names no ' +
  'user (a service token)'

// Mounted at /users, before the users routes (as the TOTP ones are). Only
// list and delete: creating a passkey has to happen on this server's own page.
export const passkeyManagement = new Hono<AppEnv>()
  .get(
    '/me/passkeys',
    describeRoute({
      tags: ['Users'],
      summary: 'List your passkeys',
      description: 'aaguid names the password manager or security key model; ' +
        'map it to a display name with the public AAGUID list.',
      security: [{ bearerAuth: [] }],
      responses: {
        200: {
          description: '[{ id, created_at, last_used_at, backed_up, aaguid }]',
        },
        401: { description: 'Missing or invalid access token' },
        404: { description: NOT_CONFIGURED },
      },
    }),
    requireAuth,
    async (c) => c.json(await c.var.passkeyService.list(c.var.user.id), 200),
  )
  .delete(
    '/me/passkeys/:id',
    describeRoute({
      tags: ['Users'],
      summary: 'Delete one of your passkeys',
      description: 'A bearer token is enough: deleting a passkey removes a ' +
        'convenience, not access -- the password or Google sign-in it was ' +
        'created after still works.',
      security: [{ bearerAuth: [] }],
      responses: {
        204: { description: 'Deleted' },
        401: { description: 'Missing or invalid access token' },
        404: { description: `No such passkey of yours. Or: ${NOT_CONFIGURED}` },
      },
    }),
    requireAuth,
    async (c) => {
      await c.var.passkeyService.remove(c.var.user.id, c.req.param('id'))
      return c.body(null, 204)
    },
  )

export default passkeys
