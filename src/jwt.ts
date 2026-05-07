import { SignJWT, jwtVerify } from 'jose'
import {
  DEFAULT_HS256_EXPIRES_IN_SEC,
  HS256_CLOCK_TOLERANCE_SEC,
} from './constants.js'
import type { SessionPayload, SessionPayloadInput } from './types.js'

export interface MintSessionJwtOptions {
  /** Token lifetime in seconds. Defaults to {@link DEFAULT_HS256_EXPIRES_IN_SEC}. */
  expiresInSec?: number
}

export interface VerifySessionJwtOptions {
  /** Clock skew tolerance in seconds. Defaults to {@link HS256_CLOCK_TOLERANCE_SEC}. */
  clockToleranceSec?: number
}

/**
 * Mint a short-lived HS256 Bearer JWT carrying a session payload.
 *
 * Used by core-browser to authenticate server-to-server calls into core-server
 * (when a server component needs to fetch admin data). The `secret` MUST be the
 * same `AUTH_SECRET` env var that core-server uses to verify.
 */
export async function mintSessionJwt(
  payload: SessionPayloadInput,
  secret: string,
  opts: MintSessionJwtOptions = {},
): Promise<string> {
  const expiresInSec = opts.expiresInSec ?? DEFAULT_HS256_EXPIRES_IN_SEC
  const key = new TextEncoder().encode(secret)
  return await new SignJWT({ ...payload })
    .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
    .setIssuedAt()
    .setExpirationTime(`${expiresInSec}s`)
    .sign(key)
}

/**
 * Verify an HS256 Bearer JWT and return its session payload. Throws if the
 * signature, algorithm, or expiry checks fail.
 */
export async function verifySessionJwt(
  token: string,
  secret: string,
  opts: VerifySessionJwtOptions = {},
): Promise<SessionPayload> {
  const clockTolerance = opts.clockToleranceSec ?? HS256_CLOCK_TOLERANCE_SEC
  const key = new TextEncoder().encode(secret)
  const { payload } = await jwtVerify(token, key, {
    algorithms: ['HS256'],
    clockTolerance,
  })
  return normalizeSessionPayload(payload)
}

/**
 * Normalize a JWT claims object into our SessionPayload shape, applying the
 * same defaults the existing core-server auth plugin applies (platformRole
 * defaults to 'player', roles to [], etc.).
 */
function normalizeSessionPayload(p: Record<string, unknown>): SessionPayload {
  const userId = (p.userId as string | undefined) ?? (p.sub as string | undefined)
  if (!userId) {
    throw new Error('SessionPayload: missing userId/sub claim')
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
