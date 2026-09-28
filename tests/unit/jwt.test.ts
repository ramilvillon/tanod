import { assertEquals } from '@std/assert'
import { sign } from 'hono/jwt'
import {
  decode,
  MFA_CHALLENGE_AUD,
  signAccessToken,
  signMfaChallenge,
  verifyAccessToken,
  verifyMfaChallenge,
  verifyWithKeyRing,
} from '../../src/lib/jwt.ts'
import { generateRsaKeyPairPem, loadKeyRing } from '../../src/lib/keys.ts'
import { keySet } from '../helpers.ts'

Deno.test('sign + verify access token (RS256)', async () => {
  const { privateKeyPem, publicKeyPem } = await generateRsaKeyPairPem()
  const token = await signAccessToken({
    sub: 'u1',
    issuer: 'http://localhost:3000',
    privateKeyPem,
    kid: 'k1',
    ttlSeconds: 900,
    aud: 'test-svc',
    org: 'o1',
    scope: '',
    clientId: 'cid_1',
    subType: 'user',
  })
  const payload = await verifyAccessToken(token, publicKeyPem)
  assertEquals(payload.sub, 'u1')
  assertEquals(payload.iss, 'http://localhost:3000')
})

Deno.test('access token carries aud, org, scope', async () => {
  const { privateKeyPem, publicKeyPem } = await generateRsaKeyPairPem()
  const token = await signAccessToken({
    sub: 'u1',
    issuer: 'iss',
    privateKeyPem,
    kid: 'k1',
    ttlSeconds: 900,
    aud: 'acme-billing',
    org: 'o1',
    scope: 'billing:read billing:write',
    clientId: 'cid_1',
    subType: 'user',
  })
  const p = await verifyAccessToken(token, publicKeyPem)
  assertEquals(p.aud, 'acme-billing')
  assertEquals(p.org, 'o1')
  assertEquals(p.scope, 'billing:read billing:write')
  assertEquals(p.client_id, 'cid_1')
})

Deno.test('signAccessToken writes the kid into the JWT header', async () => {
  const { privateKeyPem, publicKeyPem } = await generateRsaKeyPairPem()
  const ring = await loadKeyRing(privateKeyPem, publicKeyPem)
  const token = await signAccessToken({
    sub: 'u1',
    issuer: 'http://t',
    privateKeyPem,
    kid: ring.kid,
    ttlSeconds: 60,
    aud: 'a',
    org: 'o',
    scope: '',
    clientId: 'c',
    subType: 'user',
  })
  const { header } = decode(token) as { header: { kid?: string } }
  assertEquals(header.kid, ring.kid)
})

Deno.test('verifyWithKeyRing verifies by kid, falls back to active, rejects unknown kid', async () => {
  const a = await generateRsaKeyPairPem()
  const ring = await loadKeyRing(a.privateKeyPem, a.publicKeyPem)
  const token = await signAccessToken({
    sub: 'u1',
    issuer: 'http://t',
    privateKeyPem: a.privateKeyPem,
    kid: ring.kid,
    ttlSeconds: 60,
    aud: 'a',
    org: 'o',
    scope: 'x',
    clientId: 'c',
    subType: 'user',
  })
  const claims = await verifyWithKeyRing(token, ring)
  assertEquals(claims.sub, 'u1')

  // A token signed by a key not in the ring must be rejected.
  const b = await generateRsaKeyPairPem()
  const bRing = await loadKeyRing(b.privateKeyPem, b.publicKeyPem)
  const foreign = await signAccessToken({
    sub: 'u2',
    issuer: 'http://t',
    privateKeyPem: b.privateKeyPem,
    kid: bRing.kid,
    ttlSeconds: 60,
    aud: 'a',
    org: 'o',
    scope: '',
    clientId: 'c',
    subType: 'user',
  })
  let threw = false
  try {
    await verifyWithKeyRing(foreign, ring)
  } catch {
    threw = true
  }
  assertEquals(threw, true)
})

Deno.test('verifyWithKeyRing falls back to the active key for a kid-less token', async () => {
  const a = await generateRsaKeyPairPem()
  const ring = await loadKeyRing(a.privateKeyPem, a.publicKeyPem)
  // Sign with the raw PEM (not a JWK) so hono/jwt emits NO kid header — exactly
  // what a pre-rotation token looks like.
  const now = Math.floor(Date.now() / 1000)
  const legacy = await sign(
    {
      sub: 'legacy',
      iss: 'http://t',
      aud: 'a',
      org: 'o',
      scope: '',
      client_id: 'c',
      iat: now,
      exp: now + 60,
    },
    a.privateKeyPem,
    'RS256',
  )
  const { header } = decode(legacy) as { header: { kid?: string } }
  assertEquals(header.kid, undefined)
  const claims = await verifyWithKeyRing(legacy, ring)
  assertEquals(claims.sub, 'legacy')
})

const challenge = (ttlSeconds = 300) =>
  signMfaChallenge({
    sub: 'u-1',
    issuer: 'http://test.local',
    privateKeyPem: keySet.privateKeyPem,
    kid: keySet.kid,
    ttlSeconds,
  })

Deno.test('an MFA challenge verifies to its subject', async () => {
  assertEquals(await verifyMfaChallenge(await challenge(), keySet), 'u-1')
})

Deno.test('an expired or garbage challenge verifies to null', async () => {
  assertEquals(await verifyMfaChallenge(await challenge(-10), keySet), null)
  assertEquals(await verifyMfaChallenge('not-a-jwt', keySet), null)
})

Deno.test('an access token is not an MFA challenge', async () => {
  const access = await signAccessToken({
    sub: 'u-1',
    issuer: 'http://test.local',
    privateKeyPem: keySet.privateKeyPem,
    kid: keySet.kid,
    ttlSeconds: 900,
    aud: 'some-service',
    org: 'o',
    scope: '',
    clientId: 'c',
    subType: 'user',
  })
  assertEquals(await verifyMfaChallenge(access, keySet), null)
})

// A service registered with audience 'auth:mfa-challenge' gets access tokens
// carrying that aud; they must still not pass as a challenge.
Deno.test('an access token with the challenge audience is not a challenge', async () => {
  const access = await signAccessToken({
    sub: 'u-1',
    issuer: 'http://test.local',
    privateKeyPem: keySet.privateKeyPem,
    kid: keySet.kid,
    ttlSeconds: 900,
    aud: MFA_CHALLENGE_AUD,
    org: 'o',
    scope: '',
    clientId: 'c',
    subType: 'user',
  })
  assertEquals(await verifyMfaChallenge(access, keySet), null)
})
