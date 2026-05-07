import { createHmac } from 'node:crypto'
import {
  DEFAULT_HS256_EXPIRES_IN_SEC,
  mintSessionJwt,
  verifySessionJwt,
  type BearerPayloadInput,
} from '../src/index.js'

const SECRET = 'a'.repeat(64) // test secret only

const PAYLOAD: BearerPayloadInput = {
  userId: 'user-123',
  platformRole: 'player',
}

describe('mintSessionJwt + verifySessionJwt', () => {
  it('mint+verify roundtrip preserves the Bearer fields', async () => {
    const token = await mintSessionJwt(PAYLOAD, SECRET)
    const verified = await verifySessionJwt(token, SECRET)

    expect(verified.userId).toBe(PAYLOAD.userId)
    expect(verified.platformRole).toBe(PAYLOAD.platformRole)
    expect(verified.exp - verified.iat).toBe(DEFAULT_HS256_EXPIRES_IN_SEC)
    // Bearer payloads MUST NOT carry isAdmin / subscriptionTier / roles —
    // those are cookie-only hints, never authoritative for server side.
    expect(Object.keys(verified).sort()).toEqual(['exp', 'iat', 'platformRole', 'userId'])
  })

  it('verify rejects a token signed with a different secret', async () => {
    const token = await mintSessionJwt(PAYLOAD, SECRET)
    await expect(verifySessionJwt(token, 'b'.repeat(64))).rejects.toThrow()
  })

  it('verify rejects a tampered payload', async () => {
    const token = await mintSessionJwt(PAYLOAD, SECRET)
    const [header, , sig] = token.split('.')
    const tamperedPayload = Buffer.from(
      JSON.stringify({ ...PAYLOAD, isAdmin: true, iat: 1, exp: 9999999999 }),
    ).toString('base64url')
    const tampered = `${header}.${tamperedPayload}.${sig}`
    await expect(verifySessionJwt(tampered, SECRET)).rejects.toThrow()
  })

  it('respects a shorter expiresInSec', async () => {
    const token = await mintSessionJwt(PAYLOAD, SECRET, { expiresInSec: 60 })
    const verified = await verifySessionJwt(token, SECRET)
    expect(verified.exp - verified.iat).toBe(60)
  })

  it('coerces unknown platformRole values to "player"', async () => {
    const verified = await verifySessionJwt(
      legacyMint({ userId: 'u', platformRole: 'spectator', iat: now(), exp: now() + 60 }, SECRET),
      SECRET,
    )
    expect(verified.platformRole).toBe('player')
  })

  describe('cross-compat with legacy createHmac mint', () => {
    /**
     * The old apps/core-browser/src/utils/server/server-fetch.ts hand-rolled
     * HS256 with Node's createHmac and stuffed legacy `roles` claims. Those
     * tokens must still verify under cfg-auth — but cfg-auth strips the
     * legacy claims, since they're not part of the v1 contract.
     */
    it('verifySessionJwt accepts a legacy-shaped token (with extra `roles`)', async () => {
      const token = legacyMint(
        {
          userId: 'user-123',
          platformRole: 'admin',
          roles: ['admin'], // legacy claim, ignored by cfg-auth
          iat: now(),
          exp: now() + 300,
        },
        SECRET,
      )
      const verified = await verifySessionJwt(token, SECRET)
      expect(verified.userId).toBe('user-123')
      expect(verified.platformRole).toBe('admin')
      expect((verified as Record<string, unknown>).roles).toBeUndefined()
    })

    it('verifySessionJwt accepts a legacy token with `sub` claim instead of `userId`', async () => {
      const token = legacyMint(
        { sub: 'user-456', platformRole: 'player', iat: now(), exp: now() + 300 },
        SECRET,
      )
      const verified = await verifySessionJwt(token, SECRET)
      expect(verified.userId).toBe('user-456')
    })
  })
})

// ── helpers ───────────────────────────────────────────────────────────────────

function legacyMint(payload: Record<string, unknown>, secret: string): string {
  const b64url = (s: string) => Buffer.from(s).toString('base64url')
  const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
  const body = b64url(JSON.stringify(payload))
  const sig = createHmac('sha256', secret).update(`${header}.${body}`).digest('base64url')
  return `${header}.${body}.${sig}`
}

function now(): number {
  return Math.floor(Date.now() / 1000)
}
