import { decode } from '@auth/core/jwt'
import { normalizePlatformRole } from './jwt.js'
import type { CookiePayload } from './types.js'

export interface DecryptSessionCookieOptions {
  /**
   * Reserved for future use. Auth.js's `decode()` enforces a 15-second
   * tolerance internally; we have no current need to override it.
   */
  // (no fields yet — kept for API symmetry with future extensions)
  _?: never
}

/**
 * Decrypt an Auth.js v5 session cookie value and return the cookie payload
 * (incl. UI hints like `isAdmin` and `subscriptionTier`).
 *
 * Delegates to `@auth/core/jwt.decode()` so cfg-auth doesn't have to
 * track Auth.js' internal HKDF derivation manually. The cross-compat tests
 * pin the behavior; bumping `@auth/core` is a coordinated upgrade.
 *
 * @param token        the raw cookie value (the JWE compact string)
 * @param secret       AUTH_SECRET — the same value Auth.js used to encrypt
 * @param cookieName   the name of the cookie this token came from; used as
 *                     the HKDF salt, so it MUST be one of the `COOKIE_NAMES`
 *
 * Throws on signature / algorithm / expiry failure or missing required claims.
 *
 * **Important — the returned UI hint fields (`isAdmin`, `subscriptionTier`)
 * MUST NOT be trusted for server-side authorization.** See the type-level
 * docs on `CookiePayload` for why.
 */
export async function decryptSessionCookie(
  token: string,
  secret: string,
  cookieName: string,
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  _opts: DecryptSessionCookieOptions = {},
): Promise<CookiePayload> {
  const payload = await decode({ token, secret, salt: cookieName })
  if (!payload) {
    throw new Error('CookiePayload: decryption returned null (invalid or expired token)')
  }
  return normalizeCookiePayload(payload as Record<string, unknown>)
}

function normalizeCookiePayload(p: Record<string, unknown>): CookiePayload {
  const userId = (p.userId as string | undefined) ?? (p.sub as string | undefined)
  if (!userId) {
    throw new Error('CookiePayload: missing userId/sub claim')
  }
  const platformRole = normalizePlatformRole(p.platformRole)
  return {
    userId,
    platformRole,
    isAdmin: typeof p.isAdmin === 'boolean' ? p.isAdmin : platformRole === 'admin',
    subscriptionTier: (p.subscriptionTier as string | undefined) ?? 'basic',
    iat: (p.iat as number | undefined) ?? 0,
    exp: (p.exp as number | undefined) ?? 0,
  }
}
