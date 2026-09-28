// Counts CONSECUTIVE failed password attempts per account and stops accepting
// passwords for that account once the limit is reached.
//
// This is not what the rate limiter does. That one is keyed on IP, so a
// password spray from many addresses walks straight past it: every address
// stays under the limit while one account takes every guess. Keying on the
// account is the other half (NIST SP 800-63B-4, OWASP ASVS).
//
// Callers must only track accounts that EXIST. Tracking arbitrary identifiers
// would let anyone grow this map without bound, and locking a non-existent
// account has nothing to protect.
//
// ponytail: per-process, like the rate-limit store beside it. Two replicas
// mean two counters and twice the guesses -- move both to a shared store at
// the same time if this server is ever scaled out.
export type LoginAttempts = {
  isLocked(accountId: string): boolean
  recordFailure(accountId: string): void
  clear(accountId: string): void
}

export function createLoginAttempts(
  opts: { maxFailures: number; lockoutMs: number },
): LoginAttempts {
  const failures = new Map<string, { count: number; lockedUntil: number }>()

  // Reads and drops an expired entry, so an account that waited out its
  // lockout starts from zero rather than one failure from the next one.
  function live(accountId: string) {
    const entry = failures.get(accountId)
    if (!entry) return undefined
    if (entry.lockedUntil !== 0 && entry.lockedUntil <= Date.now()) {
      failures.delete(accountId)
      return undefined
    }
    return entry
  }

  return {
    isLocked(accountId) {
      return (live(accountId)?.lockedUntil ?? 0) > Date.now()
    },
    recordFailure(accountId) {
      const entry = live(accountId) ?? { count: 0, lockedUntil: 0 }
      entry.count++
      if (entry.count >= opts.maxFailures) {
        entry.lockedUntil = Date.now() + opts.lockoutMs
      }
      failures.set(accountId, entry)
    },
    // A correct password ends the run: the limit counts consecutive failures,
    // so an account in daily use never accumulates its way into a lockout.
    clear(accountId) {
      failures.delete(accountId)
    },
  }
}
