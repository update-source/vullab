const express = require("express");
const router = express.Router();
const { jwtController } = require("../../controllers/v1");

const { loginRules, handleValidation } = require("../../middlewares");

/**
 * @swagger
 * /api/v1/jwt/unverified-signature/login:
 *   post:
 *     tags: [V1 - JWT (Vulnerable)]
 *     summary: JWT login with unverified signature vulnerability
 *     description: |
 *       Login endpoint that issues a JWT token but **does not verify the signature** when
 *       the token is later presented to protected routes.
 *
 *       **Vulnerability: Authentication Bypass via Unverified Signature**
 *
 *       The server signs the JWT on login, but the token validation middleware trusts the
 *       payload without verifying the cryptographic signature. This allows an attacker to:
 *       1. Obtain any valid JWT (e.g. login with their own account)
 *       2. Decode the base64url payload
 *       3. Modify `sub` / `userId` (or any claim) to impersonate another user
 *       4. Re-encode and send the tampered token — the server accepts it
 *
 *       **Exploit example using `jsonwebtoken` `{ algorithms: ['none'] }` or manual base64 edit:**
 *       ```
 *       Header:  { "alg": "none", "typ": "JWT" }
 *       Payload: { "userId": <victim_id>, ... }
 *       Signature: (empty)
 *       ```
 *
 *       **Fix:** Always call `jwt.verify(token, secret)` and reject tokens with `alg: none`.
 *
 *       **References:**
 *       - [JWT Security Best Practices](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)
 *       - [CWE-347: Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html)
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
 *                 status:
 *                   type: string
 *                   example: "success"
 *                 data:
 *                   type: object
 *                   properties:
 *                     accessToken:
 *                       type: string
 *                       description: Signed JWT — signature is NOT verified on subsequent requests
 *                       example: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjEsImlhdCI6MTYwMDAwMDAwMH0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
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
module.exports = router;
