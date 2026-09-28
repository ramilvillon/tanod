import { getCookie, setCookie } from 'hono/cookie'
import type { Context } from 'hono'
import type { z } from 'zod'
import type { AppEnv } from '../../deps.ts'
import { authorizeQuerySchema } from './auth.schema.ts'
import { loginPage } from './login-page.ts'
import { passkeyOfferPage } from '../passkeys/passkey-offer-page.ts'
import { AppError } from '../../lib/errors.ts'
import { generateRefreshToken } from '../../lib/tokens.ts'
import type { AppServiceRecord } from '../orgs/orgs.repository.ts'

export const SESSION_COOKIE = 'auth_session'
export const CSRF_COOKIE = 'auth_csrf'
export const GOOGLE_PATH = '/oauth/google'
export const PASSKEY_OFFER_COOKIE = 'auth_passkey_offer'

export type AuthorizeQuery = z.infer<typeof authorizeQuerySchema>
export type LoginMethod = 'password' | 'google' | 'totp' | 'passkey'

// Double-submit: the same random value in a cookie and in a hidden form field.
// An attacker's page can forge the field but cannot read or write a cookie on
// this origin, so it cannot make the two agree — which is what stops a
// drive-by POST from logging a victim into the attacker's account.
//
// Reuse an existing cookie instead of minting per render. Re-minting was what
// broke the previous attempt: every render would invalidate the field the last
// one handed out, killing two open tabs, the back button, and the
// wrong-password retry (which re-renders this very page).
export function csrfToken(c: Context<AppEnv>): string {
  const token = getCookie(c, CSRF_COOKIE) ?? generateRefreshToken()
  setCookie(c, CSRF_COOKIE, token, {
    httpOnly: true,
    // secure only over https (the issuer's scheme); lets local http dev work.
    secure: c.var.config.issuer.startsWith('https'),
    sameSite: 'Lax',
    path: '/',
    maxAge: 3600,
  })
  return token
}

export const secureCookies = (c: Context<AppEnv>) =>
  c.var.config.issuer.startsWith('https')

export function setSessionCookie(c: Context<AppEnv>, token: string) {
  // secure only over https (the issuer's scheme); lets local http dev work.
  setCookie(c, SESSION_COOKIE, token, {
    httpOnly: true,
    secure: secureCookies(c),
    sameSite: 'Lax',
    path: '/',
    maxAge: c.var.config.ssoSessionTtl,
  })
}

// Every authorize parameter except prompt: prompt=login has done its job once
// the user has signed in, and carrying it into a follow-up
// /oauth/authorize would send them straight back to the sign-in page.
export function authorizeParams(q: AuthorizeQuery): URLSearchParams {
  const params = new URLSearchParams({
    client_id: q.client_id,
    redirect_uri: q.redirect_uri,
    scope: q.scope,
    code_challenge: q.code_challenge,
    code_challenge_method: q.code_challenge_method,
  })
  if (q.state) params.set('state', q.state)
  if (q.nonce) params.set('nonce', q.nonce)
  return params
}

// Only the authorize parameters: `q` may be a submitted form that also holds
// the email and password, and none of that belongs in a link.
export function googleHref(
  c: Context<AppEnv>,
  q: AuthorizeQuery,
): string | undefined {
  if (!c.var.config.google.clientId) return undefined
  const params = authorizeParams(q)
  if (q.prompt) params.set('prompt', q.prompt)
  if (q.passkey) params.set('passkey', q.passkey)
  return `${GOOGLE_PATH}?${params}`
}

export function renderLogin(
  c: Context<AppEnv>,
  q: AuthorizeQuery,
  error?: string,
  status: 200 | 400 | 401 | 403 | 404 | 409 = 200,
) {
  return c.html(
    loginPage(
      { ...q, csrf_token: csrfToken(c) },
      error,
      googleHref(c, q),
      c.var.passkeyService.enabled,
    ),
    status,
  )
}

export function redirectTo(
  base: string,
  params: Record<string, string | undefined>,
): string {
  const u = new URL(base)
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined) u.searchParams.set(k, v)
  }
  return u.toString()
}

// The double-submit check every hosted form POST makes. A human gets the form
// back and simply retries; a script gets the machine-readable code instead
// (a login page would make a protocol mistake look like bad credentials).
export function csrfRefused(
  c: Context<AppEnv>,
  q: AuthorizeQuery,
  token: string | undefined,
): Response | null {
  const presented = getCookie(c, CSRF_COOKIE)
  if (presented && token === presented) return null
  if (!c.req.header('accept')?.includes('text/html')) {
    throw AppError.of('csrf_token_invalid')
  }
  // Re-render rather than dead-end: csrfToken reuses the cookie, so a
  // legitimate caller whose cookie was missing gets a working form back.
  return renderLogin(
    c,
    q,
    'This sign-in form is no longer valid. Please try again.',
    403,
  )
}

// For the fetch() endpoints the hosted pages' scripts call.
export function requireCsrf(c: Context<AppEnv>, token: string | undefined) {
  const presented = getCookie(c, CSRF_COOKIE)
  if (!presented || token !== presented) {
    throw AppError.of('csrf_token_invalid')
  }
}

// Offer a passkey after a fresh sign-in that was not one. passkey=add is how
// an app asks for the offer on purpose (an explicit "Add passkey" entry
// point), so it overrides "Not now" -- prompt=login keeps its OIDC meaning
// only (sign in again) and does not, on its own, override the dismiss cookie.
async function offersPasskey(
  c: Context<AppEnv>,
  q: AuthorizeQuery,
  method: LoginMethod,
  userId: string,
): Promise<boolean> {
  if (method === 'passkey' || !c.var.passkeyService.enabled) return false
  if (await c.var.passkeyService.atLimit(userId)) return false
  if (q.passkey === 'add') return true
  return getCookie(c, PASSKEY_OFFER_COOKIE) !== 'dismissed'
}

// Where every hosted sign-in ends: the SSO session, then a code to the
// client. One place, so the passkey path and the enrolment offer need no
// copies of it.
export async function finishHostedLogin(
  c: Context<AppEnv>,
  q: AuthorizeQuery,
  service: AppServiceRecord,
  session: { token: string; userId: string },
  method: LoginMethod,
): Promise<Response> {
  setSessionCookie(c, session.token)
  // Both buttons continue through GET /oauth/authorize, which finds the
  // session just set and issues the code: no second code path, no state.
  if (await offersPasskey(c, q, method, session.userId)) {
    const params = authorizeParams(q)
    return c.html(
      passkeyOfferPage(
        {
          ...q,
          prompt: undefined,
          passkey: undefined,
          csrf_token: csrfToken(c),
        },
        `/oauth/authorize?${params}`,
        `/oauth/passkeys/dismiss?${params}`,
      ),
      200,
    )
  }
  const code = await c.var.authService.issueAuthorizationCode(
    session.userId,
    service,
    {
      redirectUri: q.redirect_uri,
      scope: q.scope,
      codeChallenge: q.code_challenge,
      codeChallengeMethod: q.code_challenge_method,
      nonce: q.nonce,
      authTime: new Date(),
    },
  )
  return c.redirect(redirectTo(q.redirect_uri, { code, state: q.state }))
}
