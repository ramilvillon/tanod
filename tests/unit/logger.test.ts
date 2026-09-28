import { assert, assertStringIncludes } from '@std/assert'
import { Hono } from 'hono'
import { requestId } from 'hono/request-id'
import { pinoLogger } from 'hono-pino'
import type { Config } from '../../src/config.ts'
import { createLogger } from '../../src/lib/logger.ts'

// Drives the real request-logger stack (hono-pino + createLogger) so this
// fails if hono-pino's binding shape drifts away from the redact paths.
async function logLineFor(headers: Record<string, string>) {
  const lines: string[] = []
  const logger = createLogger({ logLevel: 'info' } as Config, {
    write: (s: string) => void lines.push(s),
  })
  const app = new Hono()
    .use('*', requestId())
    .use('*', pinoLogger({ pino: logger }))
    .get('/x', (c) => c.text('ok'))

  await app.request('/x', { headers })
  return lines.join('')
}

Deno.test('request log redacts credential-bearing headers', async () => {
  const line = await logLineFor({
    authorization: 'Bearer TOKENSECRET',
    cookie: 'auth_session=COOKIESECRET',
    'proxy-authorization': 'Basic PROXYSECRET',
    'user-agent': 'probe',
  })

  assert(!line.includes('TOKENSECRET'), `bearer token leaked: ${line}`)
  assert(!line.includes('COOKIESECRET'), `session cookie leaked: ${line}`)
  assert(!line.includes('PROXYSECRET'), `proxy credential leaked: ${line}`)
  // Non-credential headers stay readable for debugging.
  assertStringIncludes(line, 'probe')
})
