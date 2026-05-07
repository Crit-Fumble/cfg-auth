import { encode } from '@auth/core/jwt'
import { COOKIE_NAMES, decryptSessionCookie } from '../src/index.js'

const SECRET = 'a'.repeat(64) // test secret only

describe('decryptSessionCookie', () => {
  /**
   * Cross-compat test against @auth/core's encode (the same code Auth.js v5
   * uses inside core-browser to mint the session cookie). cfg-auth must
   * decrypt cookies that Auth.js mints — if this test ever fails, every
   * live session breaks at deploy time. Since cfg-auth now delegates the
   * decrypt to `@auth/core/jwt.decode`, this test also acts as the canary
   * for upgrading the `@auth/core` dependency.
   */
  describe('cross-compat with @auth/core/jwt encode', () => {
    for (const cookieName of COOKIE_NAMES) {
      it(`decrypts a cookie minted by @auth/core encode (${cookieName})`, async () => {
        const token = await encode({
          token: {
            userId: 'user-123',
            platformRole: 'admin',
            isAdmin: true,
            subscriptionTier: 'patron',
          },
          secret: SECRET,
          salt: cookieName,
          maxAge: 30 * 24 * 60 * 60, // 30 days, Auth.js default
        })

        const payload = await decryptSessionCookie(token, SECRET, cookieName)

        expect(payload.userId).toBe('user-123')
        expect(payload.platformRole).toBe('admin')
        expect(payload.isAdmin).toBe(true)
        expect(payload.subscriptionTier).toBe('patron')
        expect(payload.exp).toBeGreaterThan(payload.iat)
      })
    }

    it('drops legacy `roles` claim from the returned payload', async () => {
      const cookieName = COOKIE_NAMES[0]
      const token = await encode({
        token: {
          userId: 'user-789',
          platformRole: 'player',
          // legacy claim — must not surface in cfg-auth's return type
          roles: [{ slug: 'player' }],
        },
        secret: SECRET,
        salt: cookieName,
      })
      const payload = await decryptSessionCookie(token, SECRET, cookieName)
      expect((payload as Record<string, unknown>).roles).toBeUndefined()
    })

    it('coerces unknown platformRole to "player" and derives isAdmin', async () => {
      const cookieName = COOKIE_NAMES[0]
      const token = await encode({
        token: { userId: 'user-x', platformRole: 'spectator' }, // not in narrow union
        secret: SECRET,
        salt: cookieName,
      })
      const payload = await decryptSessionCookie(token, SECRET, cookieName)
      expect(payload.platformRole).toBe('player')
      expect(payload.isAdmin).toBe(false) // derived from coerced platformRole
      expect(payload.subscriptionTier).toBe('basic') // default
    })
  })

  describe('failure modes', () => {
    it('rejects a cookie minted with a different secret', async () => {
      const cookieName = COOKIE_NAMES[0]
      const token = await encode({
        token: { userId: 'user-x' },
        secret: SECRET,
        salt: cookieName,
      })
      await expect(
        decryptSessionCookie(token, 'b'.repeat(64), cookieName),
      ).rejects.toThrow()
    })

    it('rejects a cookie minted with a different cookieName (HKDF salt mismatch)', async () => {
      const token = await encode({
        token: { userId: 'user-y' },
        secret: SECRET,
        salt: COOKIE_NAMES[0],
      })
      await expect(
        decryptSessionCookie(token, SECRET, COOKIE_NAMES[1]),
      ).rejects.toThrow()
    })

    it('throws when the payload has no userId/sub claim', async () => {
      const cookieName = COOKIE_NAMES[0]
      const token = await encode({
        token: { unrelated: 'value' },
        secret: SECRET,
        salt: cookieName,
      })
      await expect(decryptSessionCookie(token, SECRET, cookieName)).rejects.toThrow(
        /missing userId/,
      )
    })
  })
})
