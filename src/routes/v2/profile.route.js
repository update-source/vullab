const express = require("express");
const router = express.Router();
const { profileController } = require("../../controllers/v2");
const {
  requireAuthJwtWithHS256Alg,
  requireAuthJwtWithRS256Alg,
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
  requireAuthJwtWithHS256Alg,
  profileController.getProfile,
);

/**
 * @swagger
 * /api/v2/profile/jwt/flawed-signature-verification:
 *   get:
 *     tags: [V2 - Profile (Secure)]
 *     summary: Get profile via JWT with securely verified signature (fixed algorithm confusion)
 *     description: |
 *       **This is the SECURE version** of the JWT-protected profile endpoint.
 *
 *       **Security fix:** This route uses strictly configured `jwt.verify(token, secret)` instead of allowing `"none"`.
 *       The middleware explicitly ensures tokens using the `"none"` algorithm are completely rejected.
 *
 *       **Differences from vulnerable v1:**
 *       - v1: `verifyUnsignedAccessToken` allows `algorithms: ["HS256", "none"]` — accepting forged, unsigned tokens.
 *       - v2: `verifyAccessToken` explicitly limits `algorithms: ["HS256"]` — actively rejecting `"none"`.
 *
 *       **Why this prevents ATO via Algorithm Confusion:**
 *       When an attacker tampers with the token structure, modifies the header to use `alg: "none"`,
 *       and removes the signature, `jwt.verify()` notices that the algorithm is unapproved.
 *       The parsing fails immediately, raising a `JsonWebTokenError`, preventing account access.
 *
 *       **Test steps (should FAIL with forged token):**
 *       1. Login to get a valid token.
 *       2. Change header to use `alg: none` and remove the signature payload.
 *       3. Send to this endpoint → **401 Unauthorized** (invalid algorithm / missing signature).
 *
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: User profile fetched successfully (only if legitimately signed token provided)
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
 *       401:
 *         description: |
 *           Unauthorized. Possible reasons:
 *           - Missing Authorization header
 *           - Token signature is missing or tampered with
 *           - Algorithm mismatch (e.g., `alg: "none"`)
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 */
router.get(
  "/jwt/flawed-signature-verification",
  requireAuthJwtWithHS256Alg,
  profileController.getProfile,
);

/**
 * @swagger
 * /api/v2/profile/jwt/weak-signing-key:
 *   get:
 *     tags: [V2 - Profile (Secure)]
 *     summary: Get profile via JWT with strongly verified signature (fixed weak signing key)
 *     description: |
 *       **This is the SECURE version** of the JWT-protected profile endpoint.
 *
 *       **Security fix:** This route uses `jwt.verify(token, process.env.JWT_SECRET)` with a strong, high-entropy secret.
 *       The token signature is strictly verified against this complex secret.
 *
 *       **Why this prevents ATO via Weak Key Cracking:**
 *       An attacker who obtains a valid token cannot crack the signature offline because
 *       the secret key is sufficiently long and random. Consequently, they cannot forge their own tokens
 *       with arbitrary payloads (e.g., changing `id` to a victim's user ID).
 *
 *       **Test steps (should FAIL with forged token):**
 *       1. Login to get a legitimately signed token.
 *       2. Attempt to crack the token signature offline (will fail for v2 due to the strong secret).
 *       3. Any spoofed token will be rejected by this endpoint because it is correctly verified against the strong secret.
 *       4. Send a forged token to this endpoint → **401 Unauthorized** (invalid signature).
 *
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: User profile fetched successfully (only if legitimately signed token provided)
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
 *       401:
 *         description: |
 *           Unauthorized. Possible reasons:
 *           - Missing Authorization header
 *           - Token signature is missing or securely rejected (forged token)
 *           - Token expired
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 */
router.get(
  "/jwt/weak-signing-key",
  requireAuthJwtWithHS256Alg,
  profileController.getProfile,
);

/**
 * @swagger
 * /api/v2/profile/jwt/jwk-header-injection:
 *   get:
 *     tags: [V2 - Profile (Secure)]
 *     summary: Get profile via RS256 JWT — JWK header injection blocked (secure)
 *     description: |
 *       **This is the SECURE version** of the JWK header injection profile endpoint.
 *
 *       **Security fix:** This route uses `requireAuthJwtWithRS256Alg` middleware, which verifies
 *       the token signature **exclusively** against the server's own RS256 public key stored on disk.
 *       The `jwk`, `jku`, and `x5u` header fields inside the token are completely ignored.
 *
 *       **Differences from vulnerable v1:**
 *       - v1: Extracts the `jwk` field from the token's own header and uses it for verification,
 *         allowing an attacker to embed their own public key and sign tokens with the matching private key.
 *       - v2: Ignores any key material in the token header; verification always uses the
 *         server's trusted public key — the attacker's embedded key has no effect.
 *
 *       **Why this prevents ATO via JWK Header Injection:**
 *       1. Attacker generates their own RSA key-pair.
 *       2. Attacker crafts a token, embeds their public key in the `jwk` header field,
 *          and signs it with their private key.
 *       3. On v2 the middleware ignores the `jwk` field and verifies against the server's public key.
 *       4. Signature validation fails → **401 Unauthorized**.
 *
 *       **Test steps (should FAIL with injected key):**
 *       1. Login at `POST /api/v2/jwt/jwk-header-injection/login` to get a valid RS256 token.
 *       2. Generate your own RSA key-pair and embed the public key as `jwk` in the token header.
 *       3. Change payload (e.g., set `id` to another user's ID) and sign with your private key.
 *       4. Send the forged token to this endpoint → **401 Unauthorized**.
 *
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: User profile fetched successfully (only if signed with server's RS256 private key)
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
 *       401:
 *         description: |
 *           Unauthorized. Possible reasons:
 *           - Missing Authorization header
 *           - Token signed with an attacker-supplied key (JWK header injection attempt)
 *           - Token signature invalid against server's public key
 *           - Token has expired
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 */
router.get(
  "/jwt/jwk-header-injection",
  requireAuthJwtWithRS256Alg,
  profileController.getProfile,
);
//
/**
 * @swagger
 * /api/v2/profile/jwt/jku-header-injection:
 *   get:
 *     tags: [V2 - Profile (Secure)]
 *     summary: Get profile via RS256 JWT — JKU header injection blocked (secure)
 *     description: |
 *       **This is the SECURE version** of the JKU header injection profile endpoint.
 *
 *       **Security fix:** This route uses `requireAuthJwtWithRS256Alg` middleware, which verifies
 *       the token signature **exclusively** against the server's own RS256 public key loaded from
 *       disk. The `jku` field inside the token header is completely ignored — no external URL
 *       is ever fetched during verification, eliminating both the JKU injection attack and
 *       any associated SSRF risk.
 *
 *       **Differences from vulnerable v1:**
 *       - v1: Reads the `jku` (JWK Set URL) field from the token header and fetches the
 *         JWKS from that URL to obtain the public key for verification, allowing an attacker
 *         to host their own JWKS endpoint and forge trusted tokens.
 *       - v2: Ignores any `jku` field in the token header; verification always uses the
 *         server's trusted public key from disk — attacker-supplied URLs have no effect.
 *
 *       **Why this prevents ATO via JKU Header Injection:**
 *       1. Attacker generates their own RSA key-pair.
 *       2. Attacker hosts a JWKS endpoint containing their public key.
 *       3. Attacker crafts a token, sets `jku` to their JWKS URL, and signs with their private key.
 *       4. On v2 the middleware ignores the `jku` field and verifies against the server's public key.
 *       5. Signature validation fails → **401 Unauthorized**.
 *
 *       **Why this also prevents SSRF:**
 *       - The server never makes outbound HTTP requests based on `jku` header values.
 *       - Internal URLs (e.g., `http://locahost/...`) in `jku` will never be fetched.
 *
 *       **Test steps (should FAIL with injected key):**
 *       1. Login at `POST /api/v2/jwt/jku-header-injection/login` to get a valid RS256 token.
 *       2. Host your own JWKS at an external URL with your public key.
 *       3. Change `jku` in the token header to your JWKS URL, modify the payload, and sign with your private key.
 *       4. Send the forged token to this endpoint → **401 Unauthorized**.
 *
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: User profile fetched successfully (only if signed with server's RS256 private key)
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
 *       401:
 *         description: |
 *           Unauthorized. Possible reasons:
 *           - Missing Authorization header
 *           - Token signed with an attacker-supplied key (JKU header injection attempt)
 *           - Token signature invalid against server's public key
 *           - Token has expired
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 */
router.get(
  "/jwt/jku-header-injection",
  //I will directly use the public key in the source code
  //instead of calling the api,
  //because it can lead to ssrf if not handled carefully.
  requireAuthJwtWithRS256Alg,
  profileController.getProfile,
);

/**
 * @swagger
 * /api/v2/profile/jwt/kid-header-injection:
 *   get:
 *     tags: [V2 - Profile (Secure)]
 *     summary: Get profile via JWT — KID header path traversal blocked (secure)
 *     description: |
 *       **This is the SECURE version** of the KID header injection profile endpoint.
 *
 *       **Security fix:** This route uses `requireAuthJwtWithHS256Alg` middleware, which verifies
 *       the token signature **exclusively** against the server's own HS256 secret key stored in
 *       the environment variable. The `kid` field inside the token header is completely ignored —
 *       **no file is ever read from the filesystem** during token verification.
 *
 *       **Differences from vulnerable v1:**
 *       - v1: Calls `fs.readFileSync(path.join(__dirname, decodedHeader.kid))` — uses the
 *         attacker-controlled `kid` field as a file path, enabling path traversal to any
 *         readable file (e.g., `/dev/null`) which silently becomes the HMAC secret (`""`).
 *       - v2: Ignores the `kid` field entirely; always verifies against `process.env.JWT_SECRET` —
 *         no filesystem access involved, path traversal is impossible.
 *
 *       **Why this prevents ATO via KID Header Path Traversal:**
 *       1. Attacker crafts a forged HS256 token with `kid: "../../../../../../dev/null"` in the header.
 *       2. Attacker signs the token with an empty string `""` (content of `/dev/null`).
 *       3. On v2 the middleware ignores the `kid` field and verifies against the server's own secret.
 *       4. Signature validation fails → **401 Unauthorized**.
 *
 *       **Test steps (should FAIL with forged token):**
 *       1. Login at `POST /api/v2/jwt/kid-header-injection/login` to get a valid HS256 token.
 *       2. Craft a forged token with `kid: "../../../../../../dev/null"` and payload `{ "username": "administrator" }`.
 *       3. Sign with empty string `""`.
 *       4. Send to this endpoint → **401 Unauthorized** (signature mismatch against server secret).
 *
 *       **References:**
 *       - https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-kid-header-path-traversal
 *       - https://www.rfc-editor.org/rfc/rfc7515#section-4.1.4
 *
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: User profile fetched successfully (only if signed with server's own HMAC secret)
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
 *       401:
 *         description: |
 *           Unauthorized. Possible reasons:
 *           - Missing Authorization header
 *           - Token signed with an attacker-supplied key via `kid` path traversal
 *           - Token signature invalid against server's HMAC secret
 *           - Token has expired
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 */
router.get(
  "/jwt/kid-header-injection",
  requireAuthJwtWithHS256Alg,
  profileController.getProfile,
);

/**
 * @swagger
 * /api/v2/profile/jwt/algorithm-confusion:
 *   get:
 *     tags: [V2 - Profile (Secure)]
 *     summary: Get profile via JWT (algorithm confusion blocked)
 *     description: |
 *       Secure version of the algorithm-confusion profile endpoint.
 *
 *       Unlike v1, this route does not trust attacker-provided `alg` header values
 *       to choose verification logic. Token validation is pinned to the server's
 *       configured algorithm/key, so forged HS256 tokens derived from an RS256 public
 *       key are rejected.
 *
 *       **Expected behavior:**
 *       - Valid server-issued token -> 200
 *       - Forged token using RS256->HS256 confusion -> 401
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
 *       401:
 *         description: Unauthorized (missing token, invalid token, or algorithm confusion attempt)
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 */
router.get(
  "/jwt/algorithm-confusion",
  requireAuthJwtWithHS256Alg,
  profileController.getProfile,
);

module.exports = router;
