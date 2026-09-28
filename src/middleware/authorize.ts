import { createMiddleware } from 'hono/factory'
import type { Context } from 'hono'
import type { AppEnv } from '../deps.ts'
import { AppError } from '../lib/errors.ts'
import { PLATFORM_AUDIENCE } from '../db/rbac-constants.ts'

// A token's scope only means what the service it was minted for says it means:
// permission keys are per-service (`permissions` is unique on
// (appServiceId, key)), so a tenant service whose RBAC defines a colliding key
// (e.g. 'users:update:any') would otherwise be authorized against this server's own
// platform-global resources. Every route guarded here protects such a resource,
// so a permission counts only on a token minted for the platform audience —
// the same binding requirePlatform applies to the management API.
function hasPermission(c: Context<AppEnv>, permission: string): boolean {
  return c.var.user.aud === PLATFORM_AUDIENCE &&
    c.var.user.permissions.includes(permission)
}

export function requirePermission(permission: string) {
  return createMiddleware<AppEnv>(async (c, next) => {
    if (!hasPermission(c, permission)) {
      // Generic message: don't disclose which permission the route requires.
      throw AppError.of('forbidden')
    }
    await next()
  })
}

export function requireSelfOrPermission(paramName: string, permission: string) {
  return createMiddleware<AppEnv>(async (c, next) => {
    // Self-service is unchanged: acting on your own record needs no permission
    // and so is not bound to an audience.
    const isSelf = c.req.param(paramName) === c.var.user.id
    if (!isSelf && !hasPermission(c, permission)) {
      throw AppError.of('forbidden')
    }
    await next()
  })
}
