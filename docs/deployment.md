# Deployment (dev, staging, prod)

`make bootstrap` is for local development only. For any deployed environment:

1. **Configure the environment** (see [Configuration](configuration.md)). Beyond
   the required `DB_*` and `JWT_*` values:
   - generate a separate keypair per environment with `deno task keys:gen`, and
     set `JWT_ISSUER` to the environment's public URL
   - set `LOG_LEVEL=info` (`debug` pretty-prints through a worker thread)
   - set `SMTP_HOST` and `EMAIL_FROM`. Without them emails are only logged, so
     verification, password-reset and confirmation links never reach users. Keep
     `EMAIL_LOG_LINKS` off
   - set `TRUST_PROXY` to the exact number of proxies in front of the server
   - if Google sign-in is on, point `GOOGLE_REDIRECT_URI` at the public
     `/oauth/google` URL
   - set `TOTP_ENCRYPTION_KEY` (`openssl rand -base64 32`) to offer two-factor
     authentication; leave it empty and its endpoints stay 404. No RBAC re-grant
     is needed for the operator reset route — it uses the existing
     `users:update:any`
   - a database on another host is reached over verified TLS by default. Set
     `DB_HOST` to the hostname on the server's certificate (an IP is refused),
     and `DB_SSL_CA` if that certificate is from a private CA (RDS, a
     self-managed CA). `DB_SSL=off` turns it off, e.g. over a private link you
     trust
   - set `WEBAUTHN_RP_ID` to offer passkeys; leave it empty and passkeys stay
     off. It must equal the `JWT_ISSUER` host or a parent domain of it, and
     **changing it later orphans every passkey already created** — pick the
     final domain before turning this on (see
     [Configuration](configuration.md#passkeys-webauthn))
2. **Run migrations** with `deno task db:migrate` on every release, before the
   new version starts. Migration `0013_totp` adds the two-factor tables;
   `0014_passkeys` adds the passkey and WebAuthn-challenge tables.
3. **Seed once** with `deno task db:seed` and `BOOTSTRAP_ADMIN_EMAIL` /
   `BOOTSTRAP_ADMIN_PASSWORD` set. The seed refuses to adopt an existing account
   unless it is already a platform admin or the password matches, and fails
   instead.
4. **Start the server** with `deno task start`.
   - Upgrading an environment seeded before `rbac:read` existed? Its admin role
     does not hold that key, so the RBAC listings answer 403. Re-run
     `deno task db:seed`: it backfills any missing platform permission and
     grants it to the admin role, skipping what is already there.
5. **Schedule `db:prune`**, described below.

## Scheduling `db:prune`

Nothing in the server removes expired rows or erases deleted accounts; only
`db:prune` does. Every deployed environment (dev, staging, prod) needs it on a
schedule, or:

- refresh tokens, sessions, authorization codes and verification tokens pile up
  forever (a new refresh-token row is written on every refresh)
- deleted accounts are never erased, so their data stays and their email stays
  reserved, since deletion only soft-deletes until `db:prune` purges it

It is a one-shot command, not an in-process timer, so it does not multiply
across replicas. Run it **once per environment, daily**, from wherever cron
lives on your platform:

```bash
# crontab on a VM
0 3 * * * cd /path/to/tanod && deno task db:prune
```

Kubernetes `CronJob`, Fly/Railway/Render cron jobs, or a scheduled GitHub
Actions workflow work the same way. Give the job the same environment variables
as the server; it loads the same config. A missing `.env` file only prints a
warning; variables from the platform environment are used.

Run it daily or more often, whatever the retention settings. `PRUNE_RETENTION`
and `ACCOUNT_PURGE_GRACE` decide what is old enough to delete, not when the job
runs. Lowering `PRUNE_RETENTION` also shortens replay detection: a retained
expired row is what lets a replayed refresh token or authorization code revoke
the whole token family.

[← Back to README](../README.md)
