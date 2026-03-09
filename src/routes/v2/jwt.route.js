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
 *       ---
 *       **🧭 Lab Guide — API call order:**
 *       | Step | Method | Endpoint | Purpose |
 *       |------|--------|----------|---------|
 *       | 1 | POST | `/api/v2/jwt/unverified-signature/login` ← you are here | Get a valid JWT token |
 *       | 2 | GET | `/api/v2/profile/jwt/unverified-signature` | Use token (secure: signature is verified) |
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
  jwtController.loginUnverifiedSignature,
);

/**
 * @swagger
 * /api/v2/jwt/flawed-signature-verification/login:
 *   post:
 *     tags: [V2 - JWT (Secure)]
 *     summary: Secure JWT login (fixed flawed signature verification)
 *     description: |
 *       **This is the SECURE version** of the JWT login endpoint.
 *       The protected route (`GET /api/v2/profile/jwt/flawed-signature-verification`)
 *       uses `jwt.verify()` without allowing the `"none"` algorithm.
 *
 *       **Differences from vulnerable v1:**
 *       - v1 `jwt.verify()` allows `algorithms: ["HS256", "none"]` — accepting unsigned tokens.
 *       - v2 `jwt.verify()` strictly enforces `algorithms: ["HS256"]` — rejecting unsigned tokens.
 *
 *       ---
 *       **🧭 Lab Guide — API call order:**
 *       | Step | Method | Endpoint | Purpose |
 *       |------|--------|----------|---------|
 *       | 1 | POST | `/api/v2/jwt/flawed-signature-verification/login` ← you are here | Get JWT |
 *       | 2 | GET | `/api/v2/profile/jwt/flawed-signature-verification` | Use token (secure: rejects alg "none") |
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
 *       400:
 *         description: Validation error
 *       401:
 *         description: Invalid username or password
 */
router.post(
  "/flawed-signature-verification/login",
  loginRules,
  handleValidation,
  jwtController.loginFlawedSignatureVerification,
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
 *       - v1 uses a weak, predictable secret (`secret1`) that can be easily cracked via brute-force.
 *       - v2 uses secret key from environment variable that is mathematically infeasible to crack.
 *
 *       ---
 *       **🧭 Lab Guide — API call order:**
 *       | Step | Method | Endpoint | Purpose |
 *       |------|--------|----------|---------|
 *       | 1 | POST | `/api/v2/jwt/weak-signing-key/login` ← you are here | Get JWT (signed with strong key) |
 *       | 2 | GET | `/api/v2/profile/jwt/weak-signing-key` | Use token (secure: key can't be brute-forced) |
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
 * /api/v2/jwt/jwk-header-injection/login:
 *   post:
 *     tags: [V2 - JWT (Secure)]
 *     summary: Secure JWT login (fixed JWK header injection)
 *     description: |
 *       **This is the SECURE version** of the JWK header injection lab.
 *       The protected route verifies the token exclusively against the **server's own trusted
 *       public key**, ignoring any `jwk` embedded inside the token header.
 *
 *       **Differences from vulnerable v1:**
 *       - v1 extracts the `jwk` from the token's own header to verify — attacker-controlled
 *       - v2 ignores `jwk` / `jku` header fields and uses server-side public key only
 *
 *       ---
 *       **🧭 Lab Guide — API call order:**
 *       | Step | Method | Endpoint | Purpose |
 *       |------|--------|----------|---------|
 *       | 1 | POST | `/api/v2/jwt/jwk-header-injection/login` ← you are here | Get RS256 JWT |
 *       | 2 | GET | `/api/v2/profile/jwt/jwk-header-injection` | Use token (secure: ignores embedded jwk) |
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
 * /api/v2/jwt/jku-header-injection/login:
 *   post:
 *     tags: [V2 - JWT (Secure)]
 *     summary: Secure JWT login (fixed JKU header injection)
 *     description: |
 *       **This is the SECURE version** of the JKU header injection lab.
 *       The protected route verifies the token using the server's own trusted public key,
 *       completely ignoring any `jku` field in the token header.
 *
 *       **Differences from vulnerable v1:**
 *       - v1 fetches JWKS from the `jku` URL in the token header — attacker-controlled
 *       - v2 ignores `jku` header entirely, uses server-side public key only
 *
 *       ---
 *       **🧭 Lab Guide — API call order:**
 *       | Step | Method | Endpoint | Purpose |
 *       |------|--------|----------|---------|
 *       | 1 | POST | `/api/v2/jwt/jku-header-injection/login` ← you are here | Get RS256 JWT |
 *       | 2 | GET | `/api/v2/profile/jwt/jku-header-injection` | Use token (secure: ignores jku URL) |
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
 *       400:
 *         description: Validation error
 *       401:
 *         description: Invalid username or password
 */
router.post(
  "/jku-header-injection/login",
  loginRules,
  handleValidation,
  jwtController.loginJkuHeaderInjection,
);

/**
 * @swagger
 * /api/v2/jwt/kid-header-injection/login:
 *   post:
 *     tags: [V2 - JWT (Secure)]
 *     summary: Secure JWT login (fixed KID header injection)
 *     description: |
 *       **This is the SECURE version** of the KID header injection lab.
 *       The protected route ignores the `kid` header and verifies using the server's own
 *       stored secret key — no filesystem access is performed.
 *
 *       **Differences from vulnerable v1:**
 *       - v1 reads the key from `fs.readFileSync(path.join(__dirname, decodedHeader.kid))` — path traversal
 *       - v2 ignores `kid` header, uses `JWT_SECRET` from env — no file read
 *
 *       ---
 *       **🧭 Lab Guide — API call order:**
 *       | Step | Method | Endpoint | Purpose |
 *       |------|--------|----------|---------|
 *       | 1 | POST | `/api/v2/jwt/kid-header-injection/login` ← you are here | Get HS256 JWT |
 *       | 2 | GET | `/api/v2/profile/jwt/kid-header-injection` | Use token (secure: ignores kid path) |
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
 *         description: Login successful — returns an HS256-signed JWT
 *       400:
 *         description: Validation error
 *       401:
 *         description: Invalid username or password
 */
router.post(
  "/kid-header-injection/login",
  loginRules,
  handleValidation,
  jwtController.loginKidHeaderInjection,
);

/**
 * @swagger
 * /api/v2/jwt/algorithm-confusion/login:
 *   post:
 *     tags: [V2 - JWT (Secure)]
 *     summary: Secure JWT login (fixed algorithm confusion)
 *     description: |
 *       **This is the SECURE version** of the algorithm confusion lab.
 *       The protected route verifies tokens using a fixed server-side key policy
 *       and does not trust the `alg` header value from the client.
 *
 *       **Differences from vulnerable v1:**
 *       - v1 branches verification logic based on attacker-controlled `alg` header
 *       - v2 pins verification to RS256 only, ignoring `alg` from the token
 *
 *       ---
 *       **🧭 Lab Guide — API call order:**
 *       | Step | Method | Endpoint | Purpose |
 *       |------|--------|----------|---------|
 *       | 1 | POST | `/api/v2/jwt/algorithm-confusion/login` ← you are here | Get RS256 JWT |
 *       | 2 | GET | `/api/v2/profile/jwt/algorithm-confusion` | Use token (secure: RS256 enforced) |
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
 *       400:
 *         description: Validation error
 *       401:
 *         description: Invalid username or password
 */
router.post(
  "/algorithm-confusion/login",
  loginRules,
  handleValidation,
  jwtController.loginAlgorithmConfusion,
);

module.exports = router;
