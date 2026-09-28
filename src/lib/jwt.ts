import { decode, sign, verify } from 'hono/jwt'
import { type KeySet, privatePemToSigningJwk } from './keys.ts'

export type AccessPayload = {
  iss: string
  sub: string
  iat: number
  exp: number
}
export type AccessClaims = AccessPayload & {
  aud: string
  org: string
  scope: string
  client_id: string
  oidc_scope?: string
  // What `sub` identifies: a user row ('user') or an app service ('service',
  // client-credentials). Absent on tokens minted before this claim existed.
  sub_type?: 'user' | 'service'
  // When the user last actually signed in (seconds). Only on tokens straight
  // from an authorization code; a refresh is not a sign-in, so it omits it.
  auth_time?: number
}

export async function signAccessToken(
  opts: {
    sub: string
    issuer: string
    privateKeyPem: string
    kid: string
    ttlSeconds: number
    aud: string
    org: string
    scope: string
    clientId: string
    oidcScope?: string
    subType: 'user' | 'service'
    authTime?: Date
  },
): Promise<string> {
  const now = Math.floor(Date.now() / 1000)
  const payload = {
    iss: opts.issuer,
    sub: opts.sub,
    aud: opts.aud,
    org: opts.org,
    scope: opts.scope,
    client_id: opts.clientId,
    ...(opts.oidcScope ? { oidc_scope: opts.oidcScope } : {}),
    sub_type: opts.subType,
    ...(opts.authTime
      ? { auth_time: Math.floor(opts.authTime.getTime() / 1000) }
      : {}),
    iat: now,
    exp: now + opts.ttlSeconds,
  }
  // Sign with a JWK carrying alg+kid so the `kid` lands in the JWT header.
  // ponytail: converts PEM→JWK per call; precompute on the key ring if signing
  // throughput ever matters.
  const signingJwk = await privatePemToSigningJwk(opts.privateKeyPem, opts.kid)
  return await sign(payload, signingJwk, 'RS256')
}

export async function signIdToken(opts: {
  issuer: string
  privateKeyPem: string
  kid: string
  ttlSeconds: number
  sub: string
  aud: string
  authTime: Date
  nonce?: string | null
  claims: Record<string, unknown>
}): Promise<string> {
  const now = Math.floor(Date.now() / 1000)
  const payload = {
    iss: opts.issuer,
    sub: opts.sub,
    aud: opts.aud,
    iat: now,
    exp: now + opts.ttlSeconds,
    auth_time: Math.floor(opts.authTime.getTime() / 1000),
    ...(opts.nonce ? { nonce: opts.nonce } : {}),
    ...opts.claims,
  }
  const signingJwk = await privatePemToSigningJwk(opts.privateKeyPem, opts.kid)
  return await sign(payload, signingJwk, 'RS256')
}

export async function verifyAccessToken(
  token: string,
  publicKeyPem: string,
): Promise<AccessClaims> {
  return await verify(token, publicKeyPem, 'RS256') as AccessClaims
}

// Verify against the key ring: pick the key by the token's `kid`, or the active
// key when a token carries no kid (pre-rotation tokens). Unknown kid → reject.
export async function verifyWithKeyRing(
  token: string,
  keySet: KeySet,
): Promise<AccessClaims> {
  const { header } = decode(token) as { header: { kid?: string } }
  const publicKeyPem = header.kid
    ? keySet.byKid.get(header.kid)
    : keySet.publicKeyPem
  if (!publicKeyPem) throw new Error('unknown signing key')
  return await verify(token, publicKeyPem, 'RS256') as AccessClaims
}

// The half-finished login between "password (or Google) OK" and "code OK".
// Its own audience keeps it from being accepted as anything else, and it
// carries no client_id or scope, so requireAuth refuses it as an access token
// too. All it grants is the right to TRY codes, which the per-account lockout
// and the replay guard bound.
export const MFA_CHALLENGE_AUD = 'auth:mfa-challenge'
// The audience alone is not enough: a service registered with audience
// 'auth:mfa-challenge' would get access tokens carrying it. Access tokens
// never carry this typ.
const MFA_CHALLENGE_TYP = 'mfa-challenge'

export async function signMfaChallenge(opts: {
  sub: string
  issuer: string
  privateKeyPem: string
  kid: string
  ttlSeconds: number
}): Promise<string> {
  const now = Math.floor(Date.now() / 1000)
  const signingJwk = await privatePemToSigningJwk(opts.privateKeyPem, opts.kid)
  return await sign(
    {
      iss: opts.issuer,
      sub: opts.sub,
      aud: MFA_CHALLENGE_AUD,
      typ: MFA_CHALLENGE_TYP,
      iat: now,
      exp: now + opts.ttlSeconds,
    },
    signingJwk,
    'RS256',
  )
}

// The challenged user id, or null for anything that is not a live challenge.
export async function verifyMfaChallenge(
  token: string,
  keySet: KeySet,
): Promise<string | null> {
  try {
    const claims = await verifyWithKeyRing(token, keySet) as unknown as Record<
      string,
      unknown
    >
    return claims.aud === MFA_CHALLENGE_AUD &&
        claims.typ === MFA_CHALLENGE_TYP && typeof claims.sub === 'string'
      ? claims.sub
      : null
  } catch {
    return null
  }
}

export { decode }
