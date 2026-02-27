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

module.exports = router;
