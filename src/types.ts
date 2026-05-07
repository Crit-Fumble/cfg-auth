/**
 * The two valid platform roles. Sourced from the project's `PlatformRole`
 * domain; intentionally narrow because routing/permission code branches
 * exhaustively on these.
 *
 * Adding a third role is a major version bump for this package, since every
 * consumer's `platformRole === 'admin'` style checks become incomplete.
 */
export type PlatformRole = 'admin' | 'player'

interface BaseFields {
  userId: string
  platformRole: PlatformRole
}

/**
 * Bearer JWT payload — short-lived HS256 tokens minted by core-browser to
 * call core-server admin endpoints. Intentionally minimal: only what's
 * needed to identify the caller. Anything beyond this (isAdmin, subscription
 * status) MUST be re-read server-side from the DB.
 *
 * `iat` / `exp` are added by jose's SignJWT and read by jose's jwtVerify.
 */
export interface BearerPayload extends BaseFields {
  iat: number
  exp: number
}

/**
 * Input shape accepted by `mintSessionJwt`. `iat` and `exp` are filled in by
 * jose from `expiresInSec`.
 */
export type BearerPayloadInput = BaseFields

/**
 * Auth.js v5 session cookie payload — minted by Auth.js in core-browser via
 * its JWE encoder, decrypted by both apps' server-side code.
 *
 * Includes UI HINTS (isAdmin, subscriptionTier) that the client may use for
 * rendering decisions. The cookie's JWE wrapping makes these tamper-proof
 * in transit, BUT they are **NOT authoritative for server-side
 * authorization**:
 *
 *   ❌ Don't: `if (cookie.subscriptionTier === 'pro') allowPremiumApi()`
 *   ✓  Do:   re-read the user's tier from the DB / Stripe each time you gate
 *            on it server-side.
 *
 * Why: a session cookie can lag behind real-world state (downgrade,
 * cancellation, role revocation) by up to one session-refresh interval.
 * Treating the cookie value as authoritative lets a downgraded user keep
 * premium access until their cookie expires. The cookie value is also one
 * of the easier vectors for a stolen session — even though signatures
 * prevent in-flight tampering, an attacker holding a valid cookie holds
 * whatever entitlements it claims until you re-check.
 *
 * `isAdmin` is technically derivable as `platformRole === 'admin'`. It's
 * carried along for compatibility with existing code; prefer the comparison
 * in new code. Slated for removal in cfg-auth v2.0.
 */
export interface CookiePayload extends BearerPayload {
  /** Convenience for `platformRole === 'admin'`. Will be dropped in v2.0. */
  isAdmin: boolean
  /**
   * UI hint for premium-feature visibility. NEVER trust this for
   * server-side authorization — see the type-level docs on `CookiePayload`.
   * Server-side gates must re-read the authoritative tier from the DB.
   */
  subscriptionTier: string
}

/**
 * @deprecated Prefer `BearerPayload` for verify, `CookiePayload` for cookie
 * decrypt. Aliased to `CookiePayload` for compatibility during the v1
 * transition; will be removed in v2.0.
 */
export type SessionPayload = CookiePayload
