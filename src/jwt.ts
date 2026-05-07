import { SignJWT, jwtVerify } from 'jose'
import {
  DEFAULT_HS256_EXPIRES_IN_SEC,
  HS256_CLOCK_TOLERANCE_SEC,
} from './constants.js'
import type { BearerPayload, BearerPayloadInput, PlatformRole } from './types.js'

export interface MintSessionJwtOptions {
  /** Token lifetime in seconds. Defaults to {@link DEFAULT_HS256_EXPIRES_IN_SEC}. */
  expiresInSec?: number
}

export interface VerifySessionJwtOptions {
  /** Clock skew tolerance in seconds. Defaults to {@link HS256_CLOCK_TOLERANCE_SEC}. */
  clockToleranceSec?: number
}

/**
 * Mint a short-lived HS256 Bearer JWT for server-to-server calls.
 *
 * Used by core-browser to authenticate into core-server admin endpoints. The
 * `secret` MUST be the same `AUTH_SECRET` env var that core-server uses to
 * verify.
 *
 * The payload is intentionally minimal — only userId + platformRole. If the
 * server needs richer data (subscription tier, account status), it must
 * re-read from the DB. Don't try to stuff hints into Bearer tokens; that's
 * what `CookiePayload` is for.
 *
 * Note: this Bearer flow is the "transitional" server-fetch pattern in
 * core-browser. Long-term, those admin pages migrate to direct DB reads in
 * core-server and this API can be deprecated. For now (phase 0/1) it stays.
 */
export async function mintSessionJwt(
  payload: BearerPayloadInput,
  secret: string,
  opts: MintSessionJwtOptions = {},
): Promise<string> {
  const expiresInSec = opts.expiresInSec ?? DEFAULT_HS256_EXPIRES_IN_SEC
  const key = new TextEncoder().encode(secret)
  return await new SignJWT({
    userId: payload.userId,
    platformRole: payload.platformRole,
  })
    .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
    .setIssuedAt()
    .setExpirationTime(`${expiresInSec}s`)
    .sign(key)
}

/**
 * Verify an HS256 Bearer JWT and return the minimal Bearer payload.
 *
 * Throws if the signature, algorithm, or expiry checks fail. Throws if the
 * payload is missing `userId` or has an invalid `platformRole`.
 *
 * Note: this returns *only* the Bearer fields — even if the input token
 * carries extra claims (legacy tokens may include `roles`, `isAdmin`, etc.),
 * they are dropped. To read the full session shape, decrypt the JWE cookie
 * via `decryptSessionCookie`.
 */
export async function verifySessionJwt(
  token: string,
  secret: string,
  opts: VerifySessionJwtOptions = {},
): Promise<BearerPayload> {
  const clockTolerance = opts.clockToleranceSec ?? HS256_CLOCK_TOLERANCE_SEC
  const key = new TextEncoder().encode(secret)
  const { payload } = await jwtVerify(token, key, {
    algorithms: ['HS256'],
    clockTolerance,
  })
  return normalizeBearerPayload(payload as Record<string, unknown>)
}

function normalizeBearerPayload(p: Record<string, unknown>): BearerPayload {
  const userId = (p.userId as string | undefined) ?? (p.sub as string | undefined)
  if (!userId) {
    throw new Error('BearerPayload: missing userId/sub claim')
  }
  return {
    userId,
    platformRole: normalizePlatformRole(p.platformRole),
    iat: (p.iat as number | undefined) ?? 0,
    exp: (p.exp as number | undefined) ?? 0,
  }
}

/**
 * Coerce an arbitrary claim value into the narrow PlatformRole union. Defaults
 * to 'player' for missing/unknown values, matching the long-standing default
 * in core-server's auth plugin.
 */
export function normalizePlatformRole(raw: unknown): PlatformRole {
  return raw === 'admin' ? 'admin' : 'player'
}
