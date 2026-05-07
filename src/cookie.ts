import hkdf from '@panva/hkdf'
import { jwtDecrypt } from 'jose'
import {
  HKDF_INFO_PREFIX,
  HKDF_KEY_LENGTH,
  JWE_CLOCK_TOLERANCE_SEC,
} from './constants.js'
import { normalizePlatformRole } from './jwt.js'
import type { CookiePayload } from './types.js'

export interface DecryptSessionCookieOptions {
  /** Clock skew tolerance in seconds. Defaults to {@link JWE_CLOCK_TOLERANCE_SEC}. */
  clockToleranceSec?: number
}

/**
 * Derive the encryption key Auth.js v5 uses for its session cookie.
 *
 * Mirrors Auth.js' internal HKDF derivation byte-for-byte:
 *   HKDF-SHA256(secret, salt=cookieName, info=`{HKDF_INFO_PREFIX} (${cookieName})`, 64 bytes)
 *
 * Exposed primarily so byte-equivalence tests can construct the same key the
 * decryption path uses; production callers should use `decryptSessionCookie`.
 */
export async function deriveCookieEncryptionKey(
  secret: string,
  cookieName: string,
): Promise<Uint8Array> {
  return new Uint8Array(
    await hkdf(
      'sha256',
      secret,
      cookieName,
      `${HKDF_INFO_PREFIX} (${cookieName})`,
      HKDF_KEY_LENGTH,
    ),
  )
}

/**
 * Decrypt an Auth.js v5 session cookie value and return the cookie payload
 * (incl. UI hints like `isAdmin` and `subscriptionTier`).
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
  opts: DecryptSessionCookieOptions = {},
): Promise<CookiePayload> {
  const key = await deriveCookieEncryptionKey(secret, cookieName)
  const { payload } = await jwtDecrypt(token, key, {
    clockTolerance: opts.clockToleranceSec ?? JWE_CLOCK_TOLERANCE_SEC,
    keyManagementAlgorithms: ['dir'],
    contentEncryptionAlgorithms: ['A256CBC-HS512', 'A256GCM'],
  })
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
