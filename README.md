# @crit-fumble/auth

Single-source JWT mint/verify and JWE cookie decrypt for the [Crit-Fumble](https://crit-fumble.com) platform. Consumed by [`cfg-core-server`](https://github.com/Crit-Fumble/cfg-core-server) (verifies) and [`cfg-core-browser`](https://github.com/Crit-Fumble/cfg-core-browser) (mints).

By living in one published package, the auth contract becomes a TypeScript-checkable interface between the two apps — drift is impossible.

## API

```ts
import {
  mintSessionJwt,         // browser-side: short-lived HS256 Bearer for server-to-server calls
  verifySessionJwt,       // server-side:  verify said Bearer
  decryptSessionCookie,   // either side: decrypt the Auth.js v5 JWE session cookie
  COOKIE_NAMES,           // ['__Secure-authjs.session-token', 'authjs.session-token']
  type SessionPayload,
} from '@crit-fumble/auth'
```

The `SessionPayload` shape is the only contract:

```ts
type SessionPayload = {
  userId: string
  platformRole: string
  roles: string[]
  isAdmin: boolean
  subscriptionTier: string
  iat: number
  exp: number
}
```

Any breaking change here is a major version bump — both apps must upgrade in lockstep, enforced by TypeScript at build time.

## Crypto

- **Bearer tokens:** HS256 (HMAC-SHA256), minted with `AUTH_SECRET` as the HMAC key. 5-minute default lifetime, 15-second clock skew tolerance on verify. Compatible with tokens minted by Node's `createHmac` (the legacy core-browser mint path).
- **Session cookies:** JWE in `dir + A256CBC-HS512` (or `A256GCM`) format, with the encryption key derived via HKDF-SHA256 — exactly mirroring Auth.js v5's internal derivation. Compatible byte-for-byte with cookies minted by `@auth/core/jwt`'s `encode()`.

The only secret that matters is `AUTH_SECRET` (env var, never in code). Code is published openly; security depends on keeping the secret out of the repo and rotating it if it leaks.

## Install

```bash
# .npmrc
@crit-fumble:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${NODE_AUTH_TOKEN}

npm install @crit-fumble/auth
```

(`NODE_AUTH_TOKEN` only needed because GitHub Packages requires auth to install even public packages. Use `gh auth token` locally; CI gets `${{ secrets.GITHUB_TOKEN }}`.)

## Development

```bash
npm install
npm test           # jest, including byte-equiv tests against @auth/core/jwt
npm run typecheck
npm run build      # emit dist/
```

The library reads no `process.env` itself — consuming apps own the env-var
plumbing. See [`.env.example`](.env.example) for the values you may want at
install/test time (`NODE_AUTH_TOKEN`, `AUTH_SECRET`).

## License

AGPL-3.0-only. See [LICENSE](LICENSE), [NOTICE](NOTICE), and [TRADEMARK.md](TRADEMARK.md).
