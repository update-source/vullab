const express = require("express");
const router = express.Router();
const { jwtController, profileController } = require("../../controllers/v1");

const {
  handleValidation,
  loginRules,
  requireAuthJwtButAlgorithmConfusion,
  requireAuthJwtButFlawedSignatureVerification,
  requireAuthJwtButJkuHeaderInjection,
  requireAuthJwtButJwkHeaderInjection,
  requireAuthJwtButKidHeaderInjection,
  requireAuthJwtButUnverifiedSignature,
  requireAuthJwtButWeakSigningKey,
} = require("../../middlewares");

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
 *       **`GET /api/v1/jwt/unverified-signature`**
 *
 *       **Root cause:** The protected route uses `jwt.decode()` instead of `jwt.verify()`.
 *       `jwt.decode()` only parses the payload without checking the signature, so any
 *       tampered token is accepted as long as it is well-formed.
 *
 *       **How to exploit (Account Takeover):**
 *       1. Login here with your own credentials to obtain a valid JWT
 *       2. Decode the payload (base64url) — structure: `{ "id": 1, "username": "carlos", "role": "user" }`
 *       3. Change `id` or `username` to any victim's values
 *       4. Send the forged token to `GET /api/v1/jwt/unverified-signature` → ATO
 *
 *       ---
 *       **Lab Guide — API call order:**
 *       | Step | Method | Endpoint | Purpose |
 *       |------|--------|----------|---------|
 *       | 1 | POST | `/api/v1/jwt/unverified-signature/login` ← you are here | Get a valid JWT token |
 *       | 2 | GET | `/api/v1/jwt/unverified-signature` | Use token (vuln: signature not verified) |
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
  jwtController.loginUnverifiedSignature,
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
 *       **`GET /api/v1/jwt/flawed-signature-verification`**
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
 *       6. Send the forged token to `GET /api/v1/jwt/flawed-signature-verification` → ATO
 *
 *       ---
 *       **Lab Guide — API call order:**
 *       | Step | Method | Endpoint | Purpose |
 *       |------|--------|----------|---------|
 *       | 1 | POST | `/api/v1/jwt/flawed-signature-verification/login` ← you are here | Get a valid JWT token |
 *       | 2 | GET | `/api/v1/jwt/flawed-signature-verification` | Use token (vuln: accepts alg "none") |
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
  jwtController.loginFlawedSignatureVerification,
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
 *       ---
 *       **Lab Guide — API call order:**
 *       | Step | Method | Endpoint | Purpose |
 *       |------|--------|----------|---------|
 *       | 1 | POST | `/api/v1/jwt/weak-signing-key/login` ← you are here | Get JWT signed with weak key |
 *       | 2 | GET | `/api/v1/jwt/weak-signing-key` | Use token (vuln: key is brute-forceable) |
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
  jwtController.loginWeakSigningKey,
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
 *       **Vulnerability:** The protected route (`GET /api/v1/jwt/jwk-header-injection`)
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
 *       4. Send to `GET /api/v1/jwt/jwk-header-injection` as `Authorization: Bearer <forged_token>`
 *       5. Server extracts `jwk` from the header, trusts it, verifies signature → **ATO**
 *
 *       ---
 *       **Lab Guide — API call order:**
 *       | Step | Method | Endpoint | Purpose |
 *       |------|--------|----------|---------|
 *       | 1 | POST | `/api/v1/jwt/jwk-header-injection/login` ← you are here | Get RS256 JWT |
 *       | 2 | GET | `/api/v1/jwt/jwk-header-injection` | Use token (vuln: trusts embedded jwk) |
 *
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
  jwtController.loginJwkHeaderInjection,
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
 *       **Vulnerability:** The protected route (`GET /api/v1/jwt/jku-header-injection`)
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
 *       5. Send to `GET /api/v1/jwt/jku-header-injection` as `Authorization: Bearer <forged_token>`
 *       6. Server follows `jku`, fetches attacker's JWKS, verifies signature → **ATO**
 *
 *       ---
 *       **Lab Guide — API call order:**
 *       | Step | Method | Endpoint | Purpose |
 *       |------|--------|----------|---------|
 *       | 1 | POST | `/api/v1/jwt/jku-header-injection/login` ← you are here | Get RS256 JWT |
 *       | 2 | GET | `/api/v1/.well-known/jwks.json` | (Optional) Observe server's JWKS structure |
 *       | 3 | GET | `/api/v1/jwt/jku-header-injection` | Use token (vuln: fetches untrusted jku URL) |
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
  jwtController.loginJkuHeaderInjection,
);

/**
 * @swagger
 * /api/v1/jwt/kid-header-injection/login:
 *   post:
 *     tags: [V1 - JWT (Vulnerable)]
 *     summary: Login and get JWT token (KID Header Injection)
 *     description: |
 *       Login endpoint for the **JWT Authentication Bypass via KID Header Path Traversal** lab.
 *
 *       **This endpoint itself has no vulnerability** — it correctly signs the token using the
 *       server's HS256 secret, and embeds the `kid` (Key ID) field in the JWT header pointing
 *       to the server's own key file path.
 *
 *       The vulnerability exists in the protected route that consumes this token:
 *       **`GET /api/v1/jwt/kid-header-injection`**
 *
 *       **Root cause:** The protected route calls `verifyAccessTokenViaKid()`, which reads the
 *       signing key by calling `fs.readFileSync(path.join(__dirname, decodedHeader.kid))`.
 *       Because `kid` is controlled by the attacker and is never sanitised, this enables a
 *       **path traversal** — the attacker can point `kid` to any readable file on the server
 *       (e.g., `/dev/null`) to choose the HMAC secret.
 *
 *       **How to exploit (Account Takeover via KID Path Traversal):**
 *       1. Login here with valid credentials to obtain a legitimate JWT and observe the `kid` field
 *       2. Craft a forged HS256 token:
 *          - Header: `{ "alg": "HS256", "kid": "../../../../../../dev/null" }`
 *          - Payload: `{ "username": "administrator" }` (or any victim's username)
 *          - Sign the token using an **empty string** `""` as the HMAC secret
 *            (because `/dev/null` is an empty file → the key material is `""`)
 *       3. Send `Authorization: Bearer <forged_token>` to
 *          `GET /api/v1/jwt/kid-header-injection`
 *       4. Server traverses to `/dev/null`, reads `""`, verifies HMAC successfully → **ATO**
 *
 *       ---
 *       **Lab Guide — API call order:**
 *       | Step | Method | Endpoint | Purpose |
 *       |------|--------|----------|---------|
 *       | 1 | POST | `/api/v1/jwt/kid-header-injection/login` ← you are here | Get HS256 JWT with kid field |
 *       | 2 | GET | `/api/v1/jwt/kid-header-injection` | Use token (vuln: kid path traversal) |
 *
 *       **References:**
 *       - https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-kid-header-path-traversal
 *       - https://www.rfc-editor.org/rfc/rfc7515#section-4.1.4
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
 *         description: Login successful — returns a signed JWT with a `kid` field in the header
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
 *                   description: HS256-signed JWT — decode the header to observe the `kid` field
 *                   example: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleXMvaG1hYy5rZXkifQ.eyJpZCI6MSwidXNlcm5hbWUiOiJjYXJsb3MifQ.signature"
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
  "/kid-header-injection/login",
  loginRules,
  handleValidation,
  jwtController.loginKidHeaderInjection,
);

/**
 * @swagger
 * /api/v1/jwt/algorithm-confusion/login:
 *   post:
 *     tags: [V1 - JWT (Vulnerable)]
 *     summary: Login and get JWT token (Algorithm Confusion)
 *     description: |
 *       Login endpoint for the **JWT Authentication Bypass via Algorithm Confusion** lab.
 *
 *       **This endpoint is not vulnerable** — it correctly signs tokens using RS256
 *       with the server's RSA private key.
 *
 *       The vulnerability exists in the protected route that consumes this token:
 *       **`GET /api/v1/jwt/algorithm-confusion`**
 *
 *       **Root cause:** The protected route calls `verifyAccessTokenViaAlg()`, which
 *       branches on the `alg` field declared in the **attacker-controlled** token header.
 *       The `HS256` branch performs no verification, allowing an attacker to bypass
 *       authentication by switching the algorithm to `HS256` and signing with the
 *       server's known RSA public key as the HMAC secret.
 *
 *       **How to exploit (Account Takeover via Algorithm Confusion):**
 *       1. Login here with valid credentials to obtain a legitimate RS256-signed JWT
 *       2. Fetch the server's public key from `GET /api/v1/.well-known/jwks.json`
 *       3. Convert the public key JWK → PEM format
 *       4. Craft a forged token:
 *          - Header: `{ "alg": "HS256", "typ": "JWT" }`
 *          - Payload: `{ "username": "administrator" }` (victim's account)
 *          - Sign with the RSA public key PEM as the HMAC-SHA256 secret
 *       5. Send `Authorization: Bearer <forged_token>` to
 *          `GET /api/v1/jwt/algorithm-confusion`
 *       6. Server enters the unguarded `HS256` branch → bypasses verification → **ATO**
 *
 *       ---
 *       **Lab Guide — API call order:**
 *       | Step | Method | Endpoint | Purpose |
 *       |------|--------|----------|---------|
 *       | 1 | POST | `/api/v1/jwt/algorithm-confusion/login` ← you are here | Get RS256 JWT |
 *       | 2 | GET | `/api/v1/.well-known/jwks.json` | Get server's public key (for forging HS256 token) |
 *       | 3 | GET | `/api/v1/jwt/algorithm-confusion` | Use token (vuln: trusts alg from header) |
 *
 *       **References:**
 *       - https://portswigger.net/web-security/jwt/algorithm-confusion
 *       - https://www.rfc-editor.org/rfc/rfc7518#section-3.1
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
 *         description: Login successful — returns an RS256-signed JWT
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
 *                   description: "RS256-signed JWT — decode the header to observe `alg: \"RS256\"` and `kid`"
 *                   example: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InZ1bGxhYi1yczI1Ni1rZXktMSJ9.eyJpZCI6MSwidXNlcm5hbWUiOiJjYXJsb3MifQ.signature"
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
  "/algorithm-confusion/login",
  loginRules,
  handleValidation,
  jwtController.loginAlgorithmConfusion,
);

// ═══════════════════════════════════════════════════════════════
// PROTECTED PROFILE ENDPOINTS (vulnerability lives HERE)
// Each route uses a different vulnerable JWT verification middleware.
// The login endpoints above generate tokens; these endpoints CONSUME them.
// ═══════════════════════════════════════════════════════════════

/**
 * @swagger
 * /api/v1/jwt/unverified-signature/profile:
 *   get:
 *     tags: [V1 - JWT (Vulnerable)]
 *     summary: Get profile via JWT with unverified signature (vulnerable)
 *     description: |
 *       Protected endpoint vulnerable to **Authentication Bypass via Unverified JWT Signature**.
 *
 *       **Root cause:** This route uses `jwt.decode()` instead of `jwt.verify()`.
 *       `jwt.decode()` simply parses the base64url payload without validating the
 *       cryptographic signature, so the server blindly trusts whatever is in the token.
 *
 *       ---
 *       **🧭 Lab Guide — API call order:**
 *       | Step | Method | Endpoint | Purpose |
 *       |------|--------|----------|---------|
 *       | 1 | POST | `/api/v1/jwt/unverified-signature/login` | Get a valid JWT token |
 *       | 2 | GET | `/api/v1/jwt/unverified-signature/profile` ← you are here | Use token (vuln: signature not verified) |
 *
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: User profile fetched successfully
 *       401:
 *         description: Unauthorized — missing or malformed token
 */
router.get(
  "/unverified-signature/profile",
  requireAuthJwtButUnverifiedSignature,
  profileController.getProfile,
);

/**
 * @swagger
 * /api/v1/jwt/flawed-signature-verification/profile:
 *   get:
 *     tags: [V1 - JWT (Vulnerable)]
 *     summary: Get profile via JWT with flawed signature verification (vulnerable to alg "none")
 *     description: |
 *       Protected endpoint vulnerable to **JWT Algorithm Confusion** ("none" attack).
 *
 *       **Root cause:** This route accepts `alg: "none"` in the JWT header.
 *
 *       ---
 *       **🧭 Lab Guide — API call order:**
 *       | Step | Method | Endpoint | Purpose |
 *       |------|--------|----------|---------|
 *       | 1 | POST | `/api/v1/jwt/flawed-signature-verification/login` | Get JWT |
 *       | 2 | GET | `/api/v1/jwt/flawed-signature-verification/profile` ← you are here | Use token (vuln: accepts alg "none") |
 *
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: User profile fetched successfully
 *       401:
 *         description: Unauthorized
 */
router.get(
  "/flawed-signature-verification/profile",
  requireAuthJwtButFlawedSignatureVerification,
  profileController.getProfile,
);

/**
 * @swagger
 * /api/v1/jwt/weak-signing-key/profile:
 *   get:
 *     tags: [V1 - JWT (Vulnerable)]
 *     summary: Get profile via JWT signed with a weak key (vulnerable to brute-forcing)
 *     description: |
 *       Protected endpoint vulnerable to **JWT Weak Signing Key** brute-force.
 *
 *       ---
 *       **🧭 Lab Guide — API call order:**
 *       | Step | Method | Endpoint | Purpose |
 *       |------|--------|----------|---------|
 *       | 1 | POST | `/api/v1/jwt/weak-signing-key/login` | Get JWT (signed with weak key) |
 *       | 2 | GET | `/api/v1/jwt/weak-signing-key/profile` ← you are here | Use token (vuln: key is brute-forceable) |
 *
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: User profile fetched successfully
 *       401:
 *         description: Unauthorized
 */
router.get(
  "/weak-signing-key/profile",
  requireAuthJwtButWeakSigningKey,
  profileController.getProfile,
);

/**
 * @swagger
 * /api/v1/jwt/jwk-header-injection/profile:
 *   get:
 *     tags: [V1 - JWT (Vulnerable)]
 *     summary: Get profile via JWT with JWK Header Injection (vulnerable)
 *     description: |
 *       Protected endpoint vulnerable to **JWK Header Injection**.
 *       The middleware trusts the `jwk` field from the token header.
 *
 *       ---
 *       **🧭 Lab Guide — API call order:**
 *       | Step | Method | Endpoint | Purpose |
 *       |------|--------|----------|---------|
 *       | 1 | POST | `/api/v1/jwt/jwk-header-injection/login` | Get RS256 JWT |
 *       | 2 | GET | `/api/v1/jwt/jwk-header-injection/profile` ← you are here | Use token (vuln: trusts embedded jwk) |
 *
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: User profile fetched successfully
 *       401:
 *         description: Unauthorized
 */
router.get(
  "/jwk-header-injection/profile",
  requireAuthJwtButJwkHeaderInjection,
  profileController.getProfile,
);

/**
 * @swagger
 * /api/v1/jwt/jku-header-injection/profile:
 *   get:
 *     tags: [V1 - JWT (Vulnerable)]
 *     summary: Get profile via JWT — vulnerable to JKU Header Injection
 *     description: |
 *       Protected endpoint vulnerable to **JKU Header Injection**.
 *       The server fetches JWKS from the untrusted `jku` URL in the token header.
 *
 *       ---
 *       **🧭 Lab Guide — API call order:**
 *       | Step | Method | Endpoint | Purpose |
 *       |------|--------|----------|---------|
 *       | 1 | POST | `/api/v1/jwt/jku-header-injection/login` | Get RS256 JWT |
 *       | 2 | GET | `/api/v1/.well-known/jwks.json` | (Optional) Observe server's JWKS |
 *       | 3 | GET | `/api/v1/jwt/jku-header-injection/profile` ← you are here | Use token (vuln: fetches untrusted jku) |
 *
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: User profile fetched successfully
 *       401:
 *         description: Unauthorized
 */
router.get(
  "/jku-header-injection/profile",
  requireAuthJwtButJkuHeaderInjection,
  profileController.getProfile,
);

/**
 * @swagger
 * /api/v1/jwt/kid-header-injection/profile:
 *   get:
 *     tags: [V1 - JWT (Vulnerable)]
 *     summary: Get profile via JWT — vulnerable to KID Header Path Traversal
 *     description: |
 *       Protected endpoint vulnerable to **KID Header Path Traversal**.
 *       The server reads HMAC key from `fs.readFileSync(decodedHeader.kid)`.
 *
 *       ---
 *       **🧭 Lab Guide — API call order:**
 *       | Step | Method | Endpoint | Purpose |
 *       |------|--------|----------|---------|
 *       | 1 | POST | `/api/v1/jwt/kid-header-injection/login` | Get HS256 JWT with kid field |
 *       | 2 | GET | `/api/v1/jwt/kid-header-injection/profile` ← you are here | Use token (vuln: kid path traversal) |
 *
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: User profile fetched successfully
 *       401:
 *         description: Unauthorized
 */
router.get(
  "/kid-header-injection/profile",
  requireAuthJwtButKidHeaderInjection,
  profileController.getProfile,
);

/**
 * @swagger
 * /api/v1/jwt/algorithm-confusion/profile:
 *   get:
 *     tags: [V1 - JWT (Vulnerable)]
 *     summary: Get profile via JWT — vulnerable to Algorithm Confusion
 *     description: |
 *       Protected endpoint vulnerable to **Algorithm Confusion** (RS256 → HS256).
 *       The server trusts the `alg` header and allows switching to HS256.
 *
 *       ---
 *       **🧭 Lab Guide — API call order:**
 *       | Step | Method | Endpoint | Purpose |
 *       |------|--------|----------|---------|
 *       | 1 | POST | `/api/v1/jwt/algorithm-confusion/login` | Get RS256 JWT |
 *       | 2 | GET | `/api/v1/.well-known/jwks.json` | Get server's public key |
 *       | 3 | GET | `/api/v1/jwt/algorithm-confusion/profile` ← you are here | Use token (vuln: trusts alg from header) |
 *
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: User profile fetched successfully
 *       401:
 *         description: Unauthorized
 */
router.get(
  "/algorithm-confusion/profile",
  requireAuthJwtButAlgorithmConfusion,
  profileController.getProfile,
);

module.exports = router;
