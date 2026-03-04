const express = require("express");
const router = express.Router();
const { jwtController } = require("../../controllers/v1");

const { handleValidation, loginRules } = require("../../middlewares");

/**
 * @swagger
 * /api/v1/jwt/unverified-signature/login:
 *   post:
 *     tags: [V1 - JWT (Vulnerable)]
 *     summary: Login and get JWT token (no vulnerability here)
 *     description: |
 *       Standard login endpoint that validates credentials and returns a signed JWT token.
 *       **This endpoint itself has no vulnerability** — it correctly signs the token.
 *
 *       The vulnerability exists in the protected route that consumes this token:
 *       **`GET /api/v1/profile/jwt/unverified-signature`**
 *
 *       **Root cause:** The protected route uses `jwt.decode()` instead of `jwt.verify()`.
 *       `jwt.decode()` only parses the payload without checking the signature, so any
 *       tampered token is accepted as long as it is well-formed.
 *
 *       **How to exploit (Account Takeover):**
 *       1. Login here with your own credentials to obtain a valid JWT
 *       2. Decode the payload (base64url) — structure: `{ "id": 1, "username": "carlos", "role": "user" }`
 *       3. Change `id` or `username` to any victim's values
 *       4. Send the forged token to `GET /api/v1/profile/jwt/unverified-signature` → ATO
 *
 *
 *       **References:**
 *       - https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-unverified-signature
 *
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/LoginRequest'
 *           examples:
 *             valid_credentials:
 *               summary: Login with valid credentials
 *               value:
 *                 username: "carlos"
 *                 password: "SecurePass123!"
 *     responses:
 *       200:
 *         description: Login successful — returns a signed JWT access token
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
 *                   example: "Login successfully"
 *                 data:
 *                   type: string
 *                   description: Signed JWT — signature is NOT verified on subsequent requests
 *                   example: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwidXNlcm5hbWUiOiJjYXJsb3MiLCJyb2xlIjoidXNlciJ9.signature"
 *       400:
 *         description: Validation error (missing or invalid fields)
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 *       401:
 *         description: Invalid username or password
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 *             example:
 *               status: "error"
 *               message: "Invalid username or password"
 */
router.post(
  "/unverified-signature/login",
  loginRules,
  handleValidation,
  jwtController.jwtAuthenticationBypassViaUnverifiedSignature,
);

/**
 * @swagger
 * /api/v1/jwt/flawed-signature-verification/login:
 *   post:
 *     tags: [V1 - JWT (Vulnerable)]
 *     summary: Login and get JWT token (no vulnerability here)
 *     description: |
 *       Standard login endpoint that validates credentials and returns a signed JWT token.
 *       **This endpoint itself has no vulnerability** — it correctly signs the token with HS256.
 *
 *       The vulnerability exists in the protected route that consumes this token:
 *       **`GET /api/v1/profile/jwt/flawed-signature-verification`**
 *
 *       **Root cause:** The protected route accepts JWT tokens with `algorithm: "none"`.
 *       It uses `jwt.verify()` but allows the "none" algorithm in the verification options,
 *       which means tokens WITHOUT a signature are treated as valid.
 *
 *       **How to exploit (Account Takeover via Algorithm Confusion):**
 *       1. Login here with your own credentials to obtain a valid JWT
 *       2. Decode the JWT structure:
 *          - Header: `{"alg": "HS256", "typ": "JWT"}`
 *          - Payload: `{"id": 1, "username": "carlos", "iat": ..., "exp": ...}`
 *          - Signature: `<valid_signature>`
 *       3. **Modify the header** to use algorithm "none":
 *          - New header: `{"alg": "none", "typ": "JWT"}`
 *       4. **Modify the payload** to impersonate the victim:
 *          - Change `id` to victim's user ID (e.g., `"id": 2`)
 *          - Or change `username` to victim's username (e.g., `"username": "administrator"`)
 *       5. **Create forged token without signature**:
 *          - Format: `base64url(header) + "." + base64url(payload) + "."` (note the trailing dot with no signature)
 *          - Example: `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpZCI6MiwidXNlcm5hbWUiOiJhZG1pbmlzdHJhdG9yIn0.`
 *       6. Send the forged token to `GET /api/v1/profile/jwt/flawed-signature-verification` → ATO
 *
 *       **Why this works:**
 *       - The server's `verifyUnsignedAccessToken()` function includes `algorithm: "none"` in allowed algorithms
 *       - `jwt.verify()` accepts tokens with `alg: none` and skips signature validation
 *       - Attacker can forge any payload without knowing the JWT secret
 *
 *       **References:**
 *       - https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-flawed-signature-verification
 *
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/LoginRequest'
 *           examples:
 *             valid_credentials:
 *               summary: Login with valid credentials
 *               value:
 *                 username: "carlos"
 *                 password: "SecurePass123!"
 *     responses:
 *       200:
 *         description: Login successful — returns a signed JWT access token (HS256)
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
 *                   example: "Login successfully"
 *                 data:
 *                   type: string
 *                   description: Valid JWT signed with HS256 — but can be modified to use "none" algorithm
 *                   example: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwidXNlcm5hbWUiOiJjYXJsb3MiLCJpYXQiOjE3MDk4MjY0MDAsImV4cCI6MTcwOTgyNzMwMH0.signature_here"
 *       400:
 *         description: Validation error (missing or invalid fields)
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 *       401:
 *         description: Invalid username or password
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 *             example:
 *               status: "error"
 *               message: "Invalid username or password"
 */
router.post(
  "/flawed-signature-verification/login",
  loginRules,
  handleValidation,
  jwtController.jwtAuthenticationBypassViaFlawedSignatureVerification,
);

/**
 * @swagger
 * /api/v1/jwt/weak-signing-key/login:
 *   post:
 *     tags: [V1 - JWT (Vulnerable)]
 *     summary: Login and get JWT token
 *     description: |
 *       Standard login endpoint that validates credentials and returns a signed JWT token.
 *       **This endpoint itself has no vulnerability** — it correctly signs the token with a weak key.
 *
 *       The vulnerability lies in the fact that the token is signed using a weak secret.
 *       Because the secret is short or easily guessable (like a dictionary word), it can be brute-forced.
 *
 *       **How to exploit (Account Takeover via Weak Key):**
 *       1. Login with valid credentials to retrieve a JWT
 *       2. Use a brute-force tool (e.g., `hashcat`, `john the ripper`) to crack the signature offline
 *       3. Once the weak key is discovered, use it to sign a forged JWT with victim's data
 *       4. Send the new, validly-signed forged token to the corresponding profile endpoint
 *
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/LoginRequest'
 *           examples:
 *             valid_credentials:
 *               summary: Login with valid credentials
 *               value:
 *                 username: "carlos"
 *                 password: "SecurePass123!"
 *     responses:
 *       200:
 *         description: Login successful — returns a signed JWT access token
 *       400:
 *         description: Validation error
 *       401:
 *         description: Invalid username or password
 */
router.post(
  "/weak-signing-key/login",
  loginRules,
  handleValidation,
  jwtController.jwtAuthenticationBypassViaWeakSigningKey,
);
/**
 * @swagger
 * /api/v1/jwt/jwk-header-injection/login:
 *   post:
 *     tags: [V1 - JWT (Vulnerable)]
 *     summary: Vulnerable JWT login (JWK Header Injection)
 *     description: |
 *       Login endpoint for the **JWT Authentication Bypass via JWK Header Injection** lab.
 *
 *       **Vulnerability:** The protected route (`GET /api/v1/profile/jwt/jwk-header-injection`)
 *       verifies the token using the `jwk` field embedded inside the token's own header.
 *       This means an attacker can supply their own RSA key pair, embed the public key as `jwk`
 *       in the header, sign the token with the matching private key, and the server will
 *       blindly trust it — leading to full **Account Takeover (ATO)**.
 *
 *       **Exploit steps:**
 *       1. Generate an RSA key pair (attacker-controlled)
 *       2. Login here to get a legitimate token and observe its structure
 *       3. Craft a forged token:
 *          - Set header: `{ "alg": "RS256", "jwk": { <attacker's public key> } }`
 *          - Set payload: `{ "username": "administrator", "role": "admin", ... }`
 *          - Sign with attacker's **private** key
 *       4. Send to `GET /api/v1/profile/jwt/jwk-header-injection` as `Authorization: Bearer <forged_token>`
 *       5. Server extracts `jwk` from the header, trusts it, verifies signature → **ATO**
 *       **References:**
 *       - https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jwk-header-injection
 *       - https://www.rfc-editor.org/rfc/rfc7515#section-4.1.3
 *
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/LoginRequest'
 *           examples:
 *             valid_credentials:
 *               summary: Login with valid credentials
 *               value:
 *                 username: "carlos"
 *                 password: "SecurePass123!"
 *     responses:
 *       200:
 *         description: Login successful — returns a JWT signed with server's RSA private key
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
 *                   example: "Login successfully"
 *                 data:
 *                   type: string
 *                   description: RS256-signed JWT — use this to study the token structure before forging
 *                   example: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwidXNlcm5hbWUiOiJjYXJsb3MifQ.signature"
 *       400:
 *         description: Validation error
 *       401:
 *         description: Invalid username or password
 */
router.post(
  "/jwk-header-injection/login",
  loginRules,
  handleValidation,
  jwtController.jwtAuthenticationBypassViaJwkHeaderInjection,
);
/**
 * @swagger
 * /api/v1/jwt/jku-header-injection/login:
 *   post:
 *     tags: [V1 - JWT (Vulnerable)]
 *     summary: Vulnerable JWT login (JKU Header Injection)
 *     description: |
 *       Login endpoint for the **JWT Authentication Bypass via JKU Header Injection** lab.
 *       (`jku` = JWK Set URL — defined in RFC 7515 §4.1.2)
 *
 *       **Vulnerability:** The protected route (`GET /api/v1/profile/jwt/jku-header-injection`)
 *       verifies the token by fetching the JWKS from the URL specified in the token's own `jku`
 *       header field, then selecting the key whose `kid` matches `decodedHeader.kid`.
 *       Because the server **does not validate** that `jku` points to a trusted domain,
 *       an attacker can host their own JWKS, embed its URL as `jku`, and sign the token
 *       with the matching private key — leading to full **Account Takeover (ATO)**.
 *
 *       **Exploit steps:**
 *       1. Generate an RSA key-pair (attacker-controlled)
 *       2. Host a JWKS file containing the attacker's public key on a server you control:
 *          ```json
 *          { "keys": [{ "kty": "RSA", "kid": "vullab-rs256-key-1", ... }] }
 *          ```
 *       3. Login here to obtain a legitimate RS256 token and note its structure
 *       4. Craft a forged token:
 *          - Header: `{ "alg": "RS256", "kid": "vullab-rs256-key-1", "jku": "https://attacker.com/jwks.json" }`
 *          - Payload: `{ "id": <victim_id>, "username": "administrator", ... }`
 *          - Sign with attacker's **private** key
 *       5. Send to `GET /api/v1/profile/jwt/jku-header-injection` as `Authorization: Bearer <forged_token>`
 *       6. Server follows `jku`, fetches attacker's JWKS, verifies signature → **ATO**
 *
 *       **Root cause:** `verifyAccessTokenViaJku()` in `utils/jwt.js` uses `decodedHeader.jku`
 *       without any allowlist check — any URL is trusted.
 *
 *       **References:**
 *       - https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jku-header-injection
 *       - https://www.rfc-editor.org/rfc/rfc7515#section-4.1.2
 *
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/LoginRequest'
 *           examples:
 *             valid_credentials:
 *               summary: Login with valid credentials
 *               value:
 *                 username: "carlos"
 *                 password: "SecurePass123!"
 *     responses:
 *       200:
 *         description: Login successful — returns an RS256-signed JWT (study structure before forging)
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
 *                   example: "Login successfully"
 *                 data:
 *                   type: string
 *                   description: |
 *                     RS256-signed JWT. Decode the header to observe `kid` — reuse this value
 *                     in your forged token's header so the server selects your attacker-hosted key.
 *                   example: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InZ1bGxhYi1yczI1Ni1rZXktMSJ9.eyJpZCI6MX0.signature"
 *       400:
 *         description: Validation error (missing or invalid fields)
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 *       401:
 *         description: Invalid username or password
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 */
router.post(
  "/jku-header-injection/login",
  loginRules,
  handleValidation,
  jwtController.jwtAuthenticationBypassViaJkuHeaderInjection,
);
module.exports = router;
