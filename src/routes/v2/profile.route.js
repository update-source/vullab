const express = require("express");
const router = express.Router();
const { profileController } = require("../../controllers/v2");
const {
  requireAuthJwt,
  requireAuthSession,
  requireAuthSessionOrCookie,
  resolveCookieIdentity,
} = require("../../middlewares");

/**
 * @swagger
 * /api/v2/profile:
 *   get:
 *     tags: [V2 - Profile (Secure)]
 *     summary: Get user profile (secure - requires logged_in stage)
 *     description: Securely retrieves user profile data. Properly validates session stage.
 *     security:
 *       - cookieAuth: []
 *     responses:
 *       200:
 *         description: User profile data
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 data:
 *                   type: object
 *       401:
 *         description: Unauthorized - missing or invalid session
 *       403:
 *         description: Forbidden - session stage not valid
 */
router.get("/", requireAuthSession, profileController.getProfile);

/**
 * @swagger
 * /api/v2/profile/cookie:
 *   get:
 *     tags: [V2 - Profile (Secure)]
 *     summary: Get profile via session or secure remember-me cookie
 *     description: |
 *       Accepts authentication via either a valid session or a secure `stay-logged-in` cookie.
 *
 *       **Secure cookie format:** `selector:validator`
 *       - `selector` (16 hex chars): used to look up the token record in DB
 *       - `validator` (64 hex chars): raw value that is SHA-256 hashed and compared against stored hash
 *
 *       **Security properties:**
 *       - Validator is never stored in plain text — only its SHA-256 hash is persisted
 *       - Comparison uses `crypto.timingSafeEqual` to prevent timing attacks
 *       - If selector exists but validator is wrong → all tokens for that user are immediately revoked (theft detection)
 *       - Token has a configurable expiry (default: 30 days)
 *     security:
 *       - cookieAuth: []
 *     parameters:
 *       - in: cookie
 *         name: stay-logged-in
 *         schema:
 *           type: string
 *           example: "a1b2c3d4e5f6a7b8:c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0"
 *         description: Secure remember-me cookie in `selector:validator` format
 *         required: false
 *     responses:
 *       200:
 *         description: Profile fetched successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 data:
 *                   type: object
 *       401:
 *         description: |
 *           Unauthorized. Possible reasons:
 *           - No session and no cookie provided
 *           - Cookie selector not found
 *           - Validator mismatch (all tokens revoked — possible theft)
 *           - Token expired
 */
router.get(
  "/cookie",
  requireAuthSessionOrCookie,
  resolveCookieIdentity,
  profileController.getProfile,
);

/**
 * @swagger
 * /api/v2/profile/jwt/unverified-signature:
 *   get:
 *     tags: [V2 - Profile (Secure)]
 *     summary: Get profile via JWT with verified signature (secure)
 *     description: |
 *       **This is the SECURE version** of the JWT-protected profile endpoint.
 *
 *       **Security fix:** This route uses `jwt.verify(token, secret)` instead of `jwt.decode()`.
 *       The middleware validates:
 *       - Token signature is cryptographically correct
 *       - Token has not been tampered with
 *       - Issuer, audience, and algorithm claims match expected values
 *       - Token has not expired
 *
 *       **Differences from vulnerable v1:**
 *       - v1: Uses `jwt.decode()` — accepts forged tokens with modified `id`/`username`
 *       - v2: Uses `jwt.verify()` — rejects any token with invalid signature
 *
 *       **Why this prevents ATO:**
 *       An attacker cannot modify the payload (e.g., change `id` to victim's ID) without
 *       knowing the signing secret, because `jwt.verify()` will reject the forged signature.
 *
 *       **Test steps (should FAIL):**
 *       1. Login at `POST /api/v2/jwt/unverified-signature/login` to get a valid token
 *       2. Decode payload and change `id` to another user's ID
 *       3. Re-encode with `alg: none` or forge signature
 *       4. Send to this endpoint → **401 Unauthorized** (signature verification fails)
 *
 *       **References:**
 *       - https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html
 *
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: User profile fetched successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *                 message:
 *                   type: string
 *                   example: "Profile fetched successfully"
 *                 data:
 *                   type: object
 *                   description: User profile (only if token signature is valid)
 *       401:
 *         description: |
 *           Unauthorized. Possible reasons:
 *           - Missing Authorization header
 *           - Token signature is invalid (forged token)
 *           - Token has expired
 *           - Algorithm mismatch (e.g., `alg: none`)
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 */
router.get(
  "/jwt/unverified-signature",
  requireAuthJwt,
  profileController.getProfile,
);

module.exports = router;
