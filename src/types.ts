/**
 * The single-source-of-truth shape for an authenticated session payload,
 * shared by core-browser (mints) and core-server (verifies).
 *
 * Any breaking change here is a major version bump. Both consumer apps must
 * upgrade in lockstep — TypeScript will surface the drift at build time.
 */
export interface SessionPayload {
  userId: string
  platformRole: string
  roles: string[]
  isAdmin: boolean
  subscriptionTier: string
  iat: number
  exp: number
}

/**
 * Subset of SessionPayload accepted at mint time. `iat` and `exp` are filled
 * in by mintSessionJwt from `expiresInSec`.
 */
export type SessionPayloadInput = Omit<SessionPayload, 'iat' | 'exp'>
