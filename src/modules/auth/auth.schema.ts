import { z } from 'zod'

export const tokenRequestSchema = z.discriminatedUnion('grant_type', [
  z.object({
    grant_type: z.literal('password'),
    // Either an email or a generated guest username. NOT z.string().email():
    // that rejected every guest credential at the schema, before any lookup.
    username: z.string().min(1),
    password: z.string().min(1),
    audience: z.string().min(1),
  }),
  z.object({
    grant_type: z.literal('refresh_token'),
    refresh_token: z.string().min(1),
    // Required when the token belongs to a confidential client (or sent via
    // HTTP Basic instead); see authenticateTokenClient.
    client_id: z.string().min(1).optional(),
    client_secret: z.string().min(1).optional(),
  }),
  z.object({
    grant_type: z.literal('authorization_code'),
    code: z.string().min(1),
    redirect_uri: z.string().min(1),
    code_verifier: z.string().min(1),
    client_id: z.string().min(1),
    client_secret: z.string().optional(),
  }),
  z.object({
    grant_type: z.literal('client_credentials'),
    client_id: z.string().min(1),
    client_secret: z.string().min(1),
    audience: z.string().min(1),
  }),
])

export const revokeSchema = z.object({
  // RFC 7009 section 2.1 calls this `token`, which is what OAuth client
  // libraries send. `refresh_token` is what this server accepted before and keeps
  // working; one of the two must be present.
  token: z.string().min(1).optional(),
  refresh_token: z.string().min(1).optional(),
  // Accepted and ignored: the only token type this server revokes is a refresh
  // token, and the RFC makes the hint optional and non-binding.
  token_type_hint: z.string().optional(),
  // As on the refresh grant: required for a confidential client's token.
  client_id: z.string().min(1).optional(),
  client_secret: z.string().min(1).optional(),
}).refine((v) => !!(v.token ?? v.refresh_token), {
  message: 'token is required',
  path: ['token'],
})

// RFC 6749 section 5.2. Only the token endpoints speak this shape; the rest of
// the API keeps the catalogue's {error: {code, message}}.
export const oauthErrorSchema = z.object({
  error: z.enum([
    'invalid_request',
    'invalid_client',
    'invalid_grant',
    'unsupported_grant_type',
    'invalid_target',
    // Not RFC 6749: an extension code (section 5.2 allows them), the one
    // Auth0 uses. Distinct from invalid_grant, which client libraries read as
    // "bad credentials, start over" -- this one means "right password, finish
    // in the browser".
    'mfa_required',
  ]),
  error_description: z.string(),
})

export const tokenPairSchema = z.object({
  access_token: z.string(),
  refresh_token: z.string(),
  token_type: z.literal('Bearer'),
  expires_in: z.number(),
  id_token: z.string().optional(),
})

export const authorizeQuerySchema = z.object({
  client_id: z.string().min(1),
  redirect_uri: z.string().url(),
  scope: z.string().default(''),
  state: z.string().optional(),
  nonce: z.string().optional(),
  // OIDC: only 'login' is acted on (sign in again even with a live session).
  prompt: z.string().optional(),
  // Not OIDC: how an app asks for the post-sign-in passkey offer on purpose,
  // even with a dismiss cookie set. See offersPasskey in hosted.ts.
  passkey: z.literal('add').optional(),
  code_challenge: z.string().min(1),
  code_challenge_method: z.literal('S256'),
})

export const authorizeFormSchema = authorizeQuerySchema.extend({
  email: z.string().email(),
  password: z.string().min(1),
  // Optional here on purpose: a missing token is a CSRF refusal (403), not a
  // malformed body (400). The handler decides.
  csrf_token: z.string().optional(),
})

export const totpFormSchema = authorizeQuerySchema.extend({
  code: z.string().min(1).max(64),
  // Optional for the same reason as on authorizeFormSchema: missing is a CSRF
  // refusal (403), decided by the handler.
  csrf_token: z.string().optional(),
})

export const clientCredentialsResponseSchema = z.object({
  access_token: z.string(),
  token_type: z.literal('Bearer'),
  expires_in: z.number(),
})
export type ClientCredentialsResponse = z.infer<
  typeof clientCredentialsResponseSchema
>

// The passkey sign-in POST: the authorize request plus the assertion the
// browser produced, as JSON. Capped: a real assertion is a few KB.
export const passkeyFormSchema = authorizeQuerySchema.extend({
  credential: z.string().min(1).max(20_000),
  // Optional for the same reason as on authorizeFormSchema.
  csrf_token: z.string().optional(),
})

// The fetch() endpoints the hosted pages' scripts call.
export const csrfOnlySchema = z.object({ csrf_token: z.string().optional() })

export type TokenRequest = z.infer<typeof tokenRequestSchema>
export type TokenPair = z.infer<typeof tokenPairSchema>
