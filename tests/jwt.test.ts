import { createHmac } from 'node:crypto'
import {
  DEFAULT_HS256_EXPIRES_IN_SEC,
  mintSessionJwt,
  verifySessionJwt,
  type SessionPayloadInput,
} from '../src/index.js'

const SECRET = 'a'.repeat(64) // test secret only

const PAYLOAD: SessionPayloadInput = {
  userId: 'user-123',
  platformRole: 'player',
  roles: ['player'],
  isAdmin: false,
  subscriptionTier: 'basic',
}

describe('mintSessionJwt + verifySessionJwt', () => {
  it('mint+verify roundtrip preserves the payload', async () => {
    const token = await mintSessionJwt(PAYLOAD, SECRET)
    const verified = await verifySessionJwt(token, SECRET)

    expect(verified.userId).toBe(PAYLOAD.userId)
    expect(verified.platformRole).toBe(PAYLOAD.platformRole)
    expect(verified.roles).toEqual(PAYLOAD.roles)
    expect(verified.isAdmin).toBe(PAYLOAD.isAdmin)
    expect(verified.subscriptionTier).toBe(PAYLOAD.subscriptionTier)
    expect(verified.exp - verified.iat).toBe(DEFAULT_HS256_EXPIRES_IN_SEC)
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

  describe('cross-compat with old core-browser mint (createHmac path)', () => {
    /**
     * The old apps/core-browser/src/utils/server/server-fetch.ts hand-rolled
     * HS256 with Node's createHmac. Tokens it produced must verify under the
     * new cfg-auth verifier — otherwise live cookies/tokens break at cutover.
     */
    function legacyMint(payload: Record<string, unknown>, secret: string): string {
      const b64url = (s: string) => Buffer.from(s).toString('base64url')
      const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
      const body = b64url(JSON.stringify(payload))
      const sig = createHmac('sha256', secret).update(`${header}.${body}`).digest('base64url')
      return `${header}.${body}.${sig}`
    }

    it('verifySessionJwt accepts a token minted by the legacy createHmac path', async () => {
      const now = Math.floor(Date.now() / 1000)
      const token = legacyMint(
        {
          userId: 'user-123',
          platformRole: 'spectator', // legacy default differed from current default
          roles: ['player', 'admin'],
          iat: now,
          exp: now + 300,
        },
        SECRET,
      )
      const verified = await verifySessionJwt(token, SECRET)
      expect(verified.userId).toBe('user-123')
      expect(verified.platformRole).toBe('spectator')
      expect(verified.roles).toEqual(['player', 'admin'])
      // Legacy mint did not include isAdmin/subscriptionTier — defaults apply
      expect(verified.isAdmin).toBe(false)
      expect(verified.subscriptionTier).toBe('basic')
    })

    it('verifySessionJwt accepts a legacy token with role objects (mapped from .slug)', async () => {
      const now = Math.floor(Date.now() / 1000)
      const token = legacyMint(
        {
          userId: 'user-456',
          platformRole: 'player',
          roles: [{ slug: 'gm' }, { slug: 'player' }],
          iat: now,
          exp: now + 300,
        },
        SECRET,
      )
      const verified = await verifySessionJwt(token, SECRET)
      expect(verified.roles).toEqual(['gm', 'player'])
    })
  })
})
