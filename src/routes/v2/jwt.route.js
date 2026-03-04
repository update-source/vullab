const express = require("express");
const router = express.Router();
const { jwtController } = require("../../controllers/v2");

const { handleValidation, loginRules } = require("../../middlewares");

/**
 * @swagger
 * /api/v2/jwt/unverified-signature/login:
 *   post:
 *     tags: [V2 - JWT (Secure)]
 *     summary: Secure JWT login (fixed unverified signature vulnerability)
 *     description: |
 *       **This is the SECURE version** of the JWT login endpoint.
 *       It correctly signs the token, and the protected route (`GET /api/v2/profile/jwt/unverified-signature`)
 *       uses `jwt.verify()` to validate the signature, preventing token tampering.
 *
 *       **Differences from vulnerable v1:**
 *       - v1 uses `jwt.decode()` — accepts any token without signature validation
 *       - v2 uses `jwt.verify(token, secret)` — cryptographically validates signature
 *
 *       **Security properties:**
 *       - Rejects tokens with invalid signatures
 *       - Rejects tokens with `alg: none`
 *       - Validates issuer, audience, and algorithm
 *       - Prevents Account Takeover (ATO) via forged tokens
 *
 *       **Token payload structure:**
 *       ```json
 *       { "id": 1, "username": "carlos", "role": "user", "iat": 1700000000, "exp": 1700003600 }
 *       ```
 *
 *       **References:**
 *       - https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html
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
 *         description: Login successful — returns a properly signed JWT
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
 *                   description: Signed JWT token — signature is VERIFIED on protected routes
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
  jwtController.jwtSecureAuthenticationBypassViaUnverifiedSignature,
);

/**
 * @swagger
 * /api/v2/jwt/flawed-signature-verification/login:
 *   post:
 *     tags: [V2 - JWT (Secure)]
 *     summary: Secure JWT login (fixed flawed signature verification)
 *     description: |
 *       **This is the SECURE version** of the JWT login endpoint.
 *       It correctly signs the token, and the protected route (`GET /api/v2/profile/jwt/flawed-signature-verification`)
 *       uses `jwt.verify()` without allowing the `"none"` algorithm, breaking the algorithm confusion attack.
 *
 *       **Differences from vulnerable v1:**
 *       - v1 `jwt.verify()` allows `algorithms: ["HS256", "none"]` — accepting unsigned tokens.
 *       - v2 `jwt.verify()` strictly enforces `algorithms: ["HS256"]` — rejecting unsigned tokens.
 *
 *       **Security properties:**
 *       - Rejects tokens with `alg: none`
 *       - Validates cryptographic signature strictly
 *       - Prevents Account Takeover (ATO) via algorithm confusion
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
 *         description: Login successful — returns a properly signed JWT
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
 *                   description: Signed JWT token
 *                   example: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwidXNlcm5hbWUiOiJjYXJsb3MiLCJyb2xlIjoidXNlciJ9.signature"
 *       400:
 *         description: Validation error
 *       401:
 *         description: Invalid username or password
 */
router.post(
  "/flawed-signature-verification/login",
  loginRules,
  handleValidation,
  jwtController.jwtSecureAuthenticationBypassViaFlawedSignatureVerification,
);

/**
 * @swagger
 * /api/v2/jwt/weak-signing-key/login:
 *   post:
 *     tags: [V2 - JWT (Secure)]
 *     summary: Secure JWT login (fixed weak signing key)
 *     description: |
 *       **This is the SECURE version** of the JWT login endpoint.
 *       It correctly signs the token using a strong secure secret key.
 *
 *       **Differences from vulnerable v1:**
 *       - v1 uses a weak, predictable secret (`secret1`) that can be easily cracked via brute-force or dictionary attacks.
 *       - v2 uses secret key from environment variable that is mathematically infeasible to guess or crack.
 *
 *       **Security properties:**
 *       - Uses a strong HMAC secret key for signing
 *       - Prevents offline brute-force attacks against the signature
 *       - Prevents Account Takeover (ATO) via forged tokens signed with a cracked key
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
 *         description: Login successful — returns a properly signed JWT
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
 *                   description: Signed JWT token using a strong secret
 *                   example: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwidXNlcm5hbWUiOiJjYXJsb3MiLCJyb2xlIjoidXNlciJ9.signature"
 *       400:
 *         description: Validation error
 *       401:
 *         description: Invalid username or password
 */
router.post(
  "/weak-signing-key/login",
  loginRules,
  handleValidation,
  jwtController.jwtSecureAuthenticationBypassViaWeakSigningKey,
);

/**
 * @swagger
 * /api/v2/jwt/jwk-header-injection/login:
 *   post:
 *     tags: [V2 - JWT (Secure)]
 *     summary: Secure JWT login (fixed JWK header injection)
 *     description: |
 *       **This is the SECURE version** of the JWT login endpoint for the JWK header injection lab.
 *       It issues an RS256-signed JWT using the server's private key.
 *       The protected route (`GET /api/v2/profile/jwt/jwk-header-injection`) verifies the token
 *       exclusively against the **server's own trusted public key* ignoring any `jwk` embedded inside the token header.
 *
 *       **Differences from vulnerable v1:**
 *       - v1 extracts the `jwk` from the token's own header and uses it to verify the signature,
 *         allowing an attacker to supply their own key-pair and forge trusted tokens.
 *       - v2 fetches the public key from the server-controlled JWKS endpoint and **never trusts**
 *         the `jwk` / `jku` / `x5u` fields in the token header.
 *
 *       **Security properties:**
 *       - Rejects tokens whose signature cannot be verified with the server's RS256 public key
 *       - Attacker-supplied keys in `jwk` header are completely ignored
 *       - Prevents Account Takeover (ATO) via JWK header injection
 *
 *       **Token payload structure:**
 *       ```json
 *       { "id": 1, "username": "carlos", "role": "user", "iat": 1700000000, "exp": 1700003600 }
 *       ```
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
 *                   description: RS256-signed JWT — header injection attack will fail on the protected route
 *                   example: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwidXNlcm5hbWUiOiJjYXJsb3MifQ.signature"
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
  "/jwk-header-injection/login",
  loginRules,
  handleValidation,
  jwtController.jwtSecureAuthenticationBypassViaJwkHeaderInjection,
);
module.exports = router;
