/**
 * Cookie names Auth.js v5 sets for the session JWE. The first is the secure
 * variant used in production (HTTPS); the second is the dev variant. Decryption
 * code should try each in order.
 */
export const COOKIE_NAMES = [
  '__Secure-authjs.session-token',
  'authjs.session-token',
] as const

export type AuthCookieName = (typeof COOKIE_NAMES)[number]

/** Clock skew tolerance for HS256 Bearer JWT verification. */
export const HS256_CLOCK_TOLERANCE_SEC = 15

/**
 * Default lifetime of a server-fetch HS256 token (used by core-browser when
 * minting a Bearer token to call core-server). Short by design — it carries
 * a session derived from a longer-lived cookie.
 */
export const DEFAULT_HS256_EXPIRES_IN_SEC = 300
