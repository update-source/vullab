const express = require("express");
const router = express.Router();
const { profileController } = require("../../controllers/v1");
const {
  requireAuthJwtButFlawedSignatureVerification,
  requireAuthJwtButUnverifiedSignature,
  requireAuthSession,
  requireAuthSessionIgnoreStage,
  requireAuthSessionOrCookie,
  resolveCookieByBase64,
} = require("../../middlewares");

/**
 * @swagger
 * /api/v1/profile:
 *   get:
 *     tags: [Profile]
 *     summary: Get user profile (requires logged_in stage)
 *     security:
 *       - cookieAuth: []
 *     responses:
 *       200:
 *         description: User profile data
 *       401:
 *         description: Unauthorized
 */
router.get("/", requireAuthSession, profileController.getProfile);

/**
 * @swagger
 * /api/v1/profile/ignored-stage:
 *   get:
 *     tags: [Profile]
 *     summary: Get profile (ignores session stage - vulnerable)
 *     security:
 *       - cookieAuth: []
 *     responses:
 *       200:
 *         description: User profile data
 *       401:
 *         description: Unauthorized
 */
router.get(
  "/ignored-stage",
  requireAuthSessionIgnoreStage,
  profileController.getProfile,
);
/**
 * @swagger
 * /api/v1/profile/cookie:
 *   get:
 *     tags: [Profile]
 *     summary: Get profile with flexible auth (session OR stay-logged-in cookie)
 *     description: |
 *       This endpoint accepts authentication via either:
 *       - Session cookie (standard session-based auth)
 *       - stay-logged-in cookie (persistent cookie with base64 encoded credentials)
 *
 *       At least one of these must be present. If both are present, session takes priority.
 *     security:
 *       - cookieAuth: []
 *     parameters:
 *       - in: cookie
 *         name: stay-logged-in
 *         schema:
 *           type: string
 *         description: Base64 encoded string containing username + MD5 password hash
 *         required: false
 *     responses:
 *       200:
 *         description: User profile data retrieved successfully
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
 *                   example: Profile fetched successfully
 *                 data:
 *                   type: object
 *                   description: User profile information
 *       401:
 *         description: Unauthorized - neither valid session nor stay-logged-in cookie provided
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: false
 *                 message:
 *                   type: string
 *                   example: Unauthorized
 */
router.get(
  "/cookie",
  requireAuthSessionOrCookie,
  resolveCookieByBase64,
  profileController.getProfile,
);

/**
 * @swagger
 * /api/v1/profile/jwt/unverified-signature:
 *   get:
 *     tags: [Profile]
 *     summary: Get profile via JWT with unverified signature (vulnerable)
 *     description: |
 *       Protected endpoint vulnerable to **Authentication Bypass via Unverified JWT Signature**.
 *
 *       **Root cause:** This route uses `jwt.decode()` instead of `jwt.verify()`.
 *       `jwt.decode()` simply parses the base64url payload without validating the
 *       cryptographic signature, so the server blindly trusts whatever is in the token.
 *
 *       An attacker can forge a token by modifying the `id` or `username` field in the
 *       payload to impersonate any user — leading to full **Account Takeover (ATO)**.
 *
 *       **Exploit steps:**
 *       1. Login at `POST /api/v1/jwt/unverified-signature/login` to get a real JWT
 *       2. Decode the payload: `{ "id": 1, "username": "carlos", "role": "user" }`
 *       3. Change `id` to the victim's user ID (or `username` to the victim's username)
 *       4. Send as `Authorization: Bearer <forged_token>` — server returns victim's profile
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
 *                   description: User profile (of whoever's `id` was in the token payload)
 *       401:
 *         description: Unauthorized — missing or malformed token
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 */
router.get(
  "/jwt/unverified-signature",
  requireAuthJwtButUnverifiedSignature,
  profileController.getProfile,
);

/**
 * @swagger
 * /api/v1/profile/jwt/flawed-signature-verification:
 *   get:
 *     tags: [Profile]
 *     summary: Get profile via JWT with flawed signature verification (vulnerable to algorithm "none" attack)
 *     description: |
 *       Protected endpoint vulnerable to **JWT Authentication Bypass via Algorithm Confusion** ("none" attack).
 *
 *       **Root cause:** This route uses `jwt.verify()` but explicitly allows the `"none"` algorithm
 *       in the verification options. The "none" algorithm means the token has NO signature at all.
 *
 *       When a JWT uses `alg: "none"`, the signature is removed entirely, and the server
 *       accepts it without cryptographic validation. This allows attackers to forge tokens
 *       with arbitrary payloads without knowing the secret key.
 *
 *       **Code vulnerability (in `verifyUnsignedAccessToken()`):**
 *       ```javascript
 *       jwt.verify(token, JWT_SECRET, {
 *         algorithms: ["HS256", "none"]
 *       });
 *       ```
 *
 *       **Exploit steps (Account Takeover):**
 *       1. Login at `POST /api/v1/jwt/flawed-signature-verification/login` to get a real JWT
 *       2. Decode the token structure:
 *          - Header: `{"alg": "HS256", "typ": "JWT"}`
 *          - Payload: `{"id": 1, "username": "carlos", "iat": 1709826400, "exp": 1709827300}`
 *       3. **Create forged token with algorithm "none":**
 *          - Change header to: `{"alg": "none", "typ": "JWT"}`
 *          - Change payload to impersonate victim: `{"id": 2, "username": "administrator"}`
 *          - Encode as: `base64url(header) + "." + base64url(payload) + "."` (no signature, trailing dot)
 *       4. Send forged token: `Authorization: Bearer eyJhbGciOiJub25lIn0.eyJpZCI6Mn0.`
 *       5. Server accepts it → returns victim's profile → **Account Takeover**
 *       ```
 *
 *       **References:**
 *       - https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-flawed-signature-verification
 *
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: User profile fetched successfully (including forged tokens with "none" algorithm)
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
 *                   description: User profile data (of whoever's `id` was in the token payload — even if forged)
 *                   properties:
 *                     id:
 *                       type: integer
 *                       example: 2
 *                     username:
 *                       type: string
 *                       example: "administrator"
 *                     email:
 *                       type: string
 *                       example: "admin@example.com"
 *       401:
 *         description: Unauthorized — missing, malformed, or expired token
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 */
router.get(
  "/jwt/flawed-signature-verification",
  requireAuthJwtButFlawedSignatureVerification,
  profileController.getProfile,
);

module.exports = router;
