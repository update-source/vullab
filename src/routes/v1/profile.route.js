const express = require("express");
const router = express.Router();
const { profileController } = require("../../controllers/v1");
const {
  requireAuthJwtButFlawedSignatureVerification,
  requireAuthJwtButJkuHeaderInjection,
  requireAuthJwtButJwkHeaderInjection,
  requireAuthJwtButUnverifiedSignature,
  requireAuthJwtButWeakSigningKey,
  requireAuthSession,
  requireAuthSessionIgnoreStage,
  requireAuthSessionOrCookie,
  resolveCookieByBase64,
} = require("../../middlewares");

/**
 * @swagger
 * /api/v1/profile:
 *   get:
 *     tags: [V1 - Profile (Vulnerable)]
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
 *     tags: [V1 - Profile (Vulnerable)]
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
 *     tags: [V1 - Profile (Vulnerable)]
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
 *     tags: [V1 - Profile (Vulnerable)]
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
 *     tags: [V1 - Profile (Vulnerable)]
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

/**
 * @swagger
 * /api/v1/profile/jwt/weak-signing-key:
 *   get:
 *     tags: [V1 - Profile (Vulnerable)]
 *     summary: Get profile via JWT signed with a weak key (vulnerable to brute-forcing)
 *     description: |
 *       Protected endpoint vulnerable to **JWT Authentication Bypass via Weak Signing Key**.
 *
 *       **Root cause:** The server uses a very weak, easily guessable secret key (e.g., "secret1") to sign JWT tokens.
 *
 *       **Exploit steps (Account Takeover):**
 *       1. Login at `POST /api/v1/jwt/weak-signing-key/login` to get a real JWT
 *       2. Use a cracking tool like `hashcat` to brute-force the secret offline
 *       3. Once you crack the key (e.g., "secret1"), use it to sign a new forged JWT
 *       4. In the forged JWT payload, change the `username` or `id` to the victim's (e.g., `administrator`)
 *       5. Send the perfectly signed forged token here as `Authorization: Bearer <forged_token>`
 *       6. The server validates the signature correctly, but grants you access to the victim's account
 *
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: User profile fetched successfully (including forged tokens verified with the weak key)
 *       401:
 *         description: Unauthorized — missing, malformed, or fake signature token
 */
router.get(
  "/jwt/weak-signing-key",
  requireAuthJwtButWeakSigningKey,
  profileController.getProfile,
);

/**
 * @swagger
 * /api/v1/profile/jwt/jwk-header-injection:
 *   get:
 *     tags: [V1 - Profile (Vulnerable)]
 *     summary: Get profile via JWT with JWK Header Injection (vulnerable)
 *     description: |
 *       Protected endpoint vulnerable to **JWT Authentication Bypass via JWK Header Injection**.
 *
 *       **Root cause:** The middleware (`requireAuthJwtButJwkHeaderInjection`) calls
 *       `verifyAccessTokenViaJwk()`, which reads the `jwk` field from the token's own header
 *       and uses it as the verification key. An attacker can embed their own RSA public key
 *       in the header and sign the token with the matching private key — the server
 *       will verify it successfully.
 *
 *
 *       **Exploit steps (Account Takeover):**
 *       1. Generate your own RSA key pair
 *       2. Build a JWT with header `{ "alg": "RS256", "jwk": { <your public key> } }`
 *       3. Set payload `{ "username": "administrator" }` and sign with your private key
 *       4. Send `Authorization: Bearer <forged_token>` to this endpoint
 *       5. Server trusts your embedded `jwk`, verifies successfully → returns admin profile
 *
 *
 *       **References:**
 *       - https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jwk-header-injection
 *
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: User profile fetched successfully (including forged tokens with attacker-embedded JWK)
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
 *                   description: Profile of whoever's `username` was in the forged token payload
 *       401:
 *         description: Unauthorized — missing or malformed token
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 */
router.get(
  "/jwt/jwk-header-injection",
  requireAuthJwtButJwkHeaderInjection,
  profileController.getProfile,
);

/**
 * @swagger
 * /api/v1/profile/jwt/jku-header-injection:
 *   get:
 *     tags: [V1 - Profile (Vulnerable)]
 *     summary: Get profile via JWT — vulnerable to JKU Header Injection
 *     description: |
 *       **VULNERABLE endpoint.** The server fetches the JWKS from the URL in the token's
 *       own `jku` header field — without validating that the URL belongs to a trusted domain.
 *
 *       **Root cause:** `verifyAccessTokenViaJku()` in `utils/jwt.js`:
 *       ```js
 *       const jwksUrl = decodedHeader?.jku ?? `http://localhost:${port}/api/v1/.well-known/jwks.json`;
 *       const jwk = await fetchJwkByKid(jwksUrl, decodedHeader?.kid);
 *       ```
 *       When `jku` is present the server blindly fetches it, selects the key by `kid`,
 *       and verifies the signature — so an attacker-hosted JWKS is fully trusted.
 *
 *       **Attack flow:**
 *       1. Attacker generates their own RSA key-pair
 *       2. Hosts JWKS at `https://attacker.com/jwks.json` with `kid: "vullab-rs256-key-1"`
 *       3. Crafts a forged RS256 token:
 *          - Header: `{ "alg": "RS256", "kid": "vullab-rs256-key-1", "jku": "https://attacker.com/jwks.json" }`
 *          - Payload: `{ "id": <victim_id>, "username": "administrator" }`
 *          - Signed with attacker's private key
 *       4. Sends token here → server follows `jku`, trusts attacker's key → **ATO**
 *
 *       **Secure fix (v2):** `GET /api/v2/profile/jwt/jwk-header-injection` uses
 *       `requireAuthJwtWithRS256Alg` which always verifies against the server's own
 *       public key — `jku` / `jwk` header fields are completely ignored.
 *
 *       **References:**
 *       - https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jku-header-injection
 *       - https://www.rfc-editor.org/rfc/rfc7515#section-4.1.2
 *
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: |
 *           User profile returned — attacker receives victim's profile if forged token is accepted.
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
 *                   description: Profile of whoever's `id` was in the (possibly forged) token payload
 *       401:
 *         description: Unauthorized — missing or malformed token
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 */
router.get(
  "/jwt/jku-header-injection",
  requireAuthJwtButJkuHeaderInjection,
  profileController.getProfile,
);
module.exports = router;
