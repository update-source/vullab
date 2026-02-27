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
module.exports = router;
