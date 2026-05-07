import hkdf from '@panva/hkdf'
import { jwtDecrypt } from 'jose'
import {
  HKDF_INFO_PREFIX,
  HKDF_KEY_LENGTH,
  JWE_CLOCK_TOLERANCE_SEC,
} from './constants.js'
import type { SessionPayload } from './types.js'

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
 * Decrypt an Auth.js v5 session cookie value and return the session payload.
 *
 * @param token        the raw cookie value (the JWE compact string)
 * @param secret       AUTH_SECRET — the same value Auth.js used to encrypt
 * @param cookieName   the name of the cookie this token came from; used as the
 *                     HKDF salt, so it MUST be one of the `COOKIE_NAMES`
 *
 * Throws on signature/algorithm/expiry failure.
 */
export async function decryptSessionCookie(
  token: string,
  secret: string,
  cookieName: string,
  opts: DecryptSessionCookieOptions = {},
): Promise<SessionPayload> {
  const key = await deriveCookieEncryptionKey(secret, cookieName)
  const { payload } = await jwtDecrypt(token, key, {
    clockTolerance: opts.clockToleranceSec ?? JWE_CLOCK_TOLERANCE_SEC,
    keyManagementAlgorithms: ['dir'],
    contentEncryptionAlgorithms: ['A256CBC-HS512', 'A256GCM'],
  })
  return normalizeCookiePayload(payload as Record<string, unknown>)
}

function normalizeCookiePayload(p: Record<string, unknown>): SessionPayload {
  const userId = (p.userId as string | undefined) ?? (p.sub as string | undefined)
  if (!userId) {
    throw new Error('Session cookie payload missing userId/sub claim')
  }
  const rawRoles = Array.isArray(p.roles) ? (p.roles as unknown[]) : []
  const roles = rawRoles.map((r) =>
    typeof r === 'string' ? r : ((r as { slug: string }).slug ?? ''),
  )
  return {
    userId,
    platformRole: (p.platformRole as string | undefined) ?? 'player',
    roles,
    isAdmin: (p.isAdmin as boolean | undefined) ?? false,
    subscriptionTier: (p.subscriptionTier as string | undefined) ?? 'basic',
    iat: (p.iat as number | undefined) ?? 0,
    exp: (p.exp as number | undefined) ?? 0,
  }
}
