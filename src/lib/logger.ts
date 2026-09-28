import { type DestinationStream, pino } from 'pino'
import type { Config } from '../config.ts'

export type Logger = ReturnType<typeof pino>

// hono-pino binds the whole client header map as `req.headers` on the
// always-on "Request completed" line, so bearer tokens and the auth_session
// cookie would be written to the log in cleartext. Header names arrive
// lowercased (fetch `Headers` normalises them), so these paths always match.
const REDACT_PATHS = [
  'req.headers.authorization',
  'req.headers.cookie',
  'req.headers["proxy-authorization"]',
]

export function createLogger(
  config: Config,
  // ponytail: test seam only — lets a test read what was actually emitted.
  destination?: DestinationStream,
): Logger {
  const isDev = config.logLevel === 'debug'
  const options = {
    level: config.logLevel,
    redact: REDACT_PATHS,
    ...(isDev && !destination
      ? { transport: { target: 'pino-pretty', options: { colorize: true } } }
      : {}),
  }
  return destination ? pino(options, destination) : pino(options)
}
