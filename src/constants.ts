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

/** Clock skew tolerance for JWT verification, matching the existing core-server behavior. */
export const HS256_CLOCK_TOLERANCE_SEC = 15

/** JWE clock skew tolerance for session cookie decryption, matching the existing core-server behavior. */
export const JWE_CLOCK_TOLERANCE_SEC = 15

/**
 * Default lifetime of a server-fetch HS256 token (used by core-browser when
 * minting a Bearer token to call core-server). Short by design — it carries
 * a session derived from a longer-lived cookie.
 */
export const DEFAULT_HS256_EXPIRES_IN_SEC = 300

/**
 * HKDF info string for deriving the JWE encryption key from AUTH_SECRET.
 * Mirrors Auth.js v5's internal derivation. Do not change without coordinating
 * with every Auth.js version your apps run.
 */
export const HKDF_INFO_PREFIX = 'Auth.js Generated Encryption Key'

/** Length (bytes) of the derived encryption key. 64 = A256CBC-HS512 takes 64 bytes. */
export const HKDF_KEY_LENGTH = 64
