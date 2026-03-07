const express = require("express");
const router = express.Router();
const AppError = require("../../utils/AppError");
const { JWT_KID, JWT_PUBLIC_KEY } = require("../../config/jwt.config");
const { generateJwkFromPem } = require("../../utils/jwt");

/**
 * @swagger
 * /api/v1/.well-known/jwks.json:
 *   get:
 *     tags: [V1 - Well-Known]
 *     summary: Get the server's JSON Web Key Set (JWKS)
 *     description: |
 *       Returns the server's RS256 public key in **JSON Web Key Set (JWKS)** format.
 *
 *       This endpoint is **publicly accessible** and intentionally exposes the RSA public key —
 *       which is normal and expected. However, it becomes exploitable in combination with
 *       vulnerable JWT verification routes:
 *
 *       - **JKU Header Injection** (`GET /api/v1/profile/jwt/jku-header-injection`):
 *         The server fetches JWKS from a URL in the attacker-controlled `jku` header field.
 *         This endpoint serves as the *legitimate* JWKS source — an attacker can host a
 *         malicious copy at an external URL to redirect trust.
 *
 *       - **KID Header Injection** (`GET /api/v1/profile/jwt/kid-header-injection`):
 *         The server uses the `kid` value as a **file path** to read the signing key.
 *         This endpoint leaks the `kid` value (`vullab-rs256-key-1`) which an attacker
 *         replaces with a path traversal string (e.g., `../../../../../../dev/null`).
 *
 *       - **Algorithm Confusion** (`GET /api/v1/profile/jwt/algorithm-confusion`):
 *         The RSA public key returned here is used as the **HMAC-SHA256 secret** when
 *         forging a token with `alg: "HS256"`. Specifically, the raw DER bytes
 *         (base64url-decoded content of the PEM, without headers/footer) are used as
 *         the key material — matching how Burp Suite JWT Editor and jwt.io handle it.
 *
 *       **Cache-Control:** `public, max-age=3600` (1 hour)
 *
 *       **References:**
 *       - https://www.rfc-editor.org/rfc/rfc7517 (JSON Web Key)
 *       - https://portswigger.net/web-security/jwt/algorithm-confusion
 *       - https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jku-header-injection
 *     responses:
 *       200:
 *         description: JWKS containing the server's RS256 public key
 *         headers:
 *           Cache-Control:
 *             schema:
 *               type: string
 *               example: "public, max-age=3600"
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 keys:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       kty:
 *                         type: string
 *                         example: "RSA"
 *                       n:
 *                         type: string
 *                         description: RSA modulus (base64url-encoded)
 *                       e:
 *                         type: string
 *                         example: "AQAB"
 *                       use:
 *                         type: string
 *                         example: "sig"
 *                       alg:
 *                         type: string
 *                         example: "RS256"
 *                       kid:
 *                         type: string
 *                         example: "vullab-rs256-key-1"
 *       500:
 *         description: Server error — public key could not be loaded or converted
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/ErrorResponse'
 */
router.get("/jwks.json", (req, res, next) => {
  try {
    const jwk = generateJwkFromPem(JWT_PUBLIC_KEY);
    const jwks = {
      keys: [
        {
          ...jwk,
          use: "sig",
          alg: "RS256",
          kid: JWT_KID,
        },
      ],
    };
    res.setHeader("Cache-Control", "public, max-age=3600");
    res.json(jwks);
  } catch (error) {
    next(new AppError(500, error.message));
  }
});

module.exports = router;
