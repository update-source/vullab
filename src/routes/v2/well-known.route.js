const express = require("express");
const router = express.Router();
const AppError = require("../../utils/AppError");
const { JWT_PUBLIC_KEY } = require("../../config/jwt.config");
const { generateJwkFromPem } = require("../../utils/jwt");

/**
 * @swagger
 * /api/v2/.well-known/jwks.json:
 *   get:
 *     tags: [V2 - Well-Known]
 *     summary: Get the server's JSON Web Key Set (JWKS)
 *     description: |
 *       Returns the server's RS256 public key in **JSON Web Key Set (JWKS)** format.
 *       This endpoint is used by JWT verification routines as the **trusted** source of truth
 *       for the server's public key.
 *
 *       **Response format (RFC 7517 — JSON Web Key):**
 *       ```json
 *       {
 *         "keys": [
 *           {
 *             "kty": "RSA",
 *             "n": "<base64url-encoded modulus>",
 *             "e": "AQAB",
 *             "use": "sig",
 *             "alg": "RS256",
 *             "kid": "vullab-rs256-key-1"
 *           }
 *         ]
 *       }
 *       ```
 *
 *       **Cache-Control:** `public, max-age=3600` (1 hour)
 *
 *       **References:**
 *       - https://www.rfc-editor.org/rfc/rfc7517 (JSON Web Key)
 *       - https://www.rfc-editor.org/rfc/rfc7518 (JSON Web Algorithms)
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
 *                         description: Key type
 *                       n:
 *                         type: string
 *                         description: RSA modulus (base64url-encoded)
 *                       e:
 *                         type: string
 *                         example: "AQAB"
 *                         description: RSA public exponent (base64url-encoded)
 *                       use:
 *                         type: string
 *                         example: "sig"
 *                         description: Intended use — signature verification
 *                       alg:
 *                         type: string
 *                         example: "RS256"
 *                         description: Algorithm this key is intended for
 *                       kid:
 *                         type: string
 *                         example: "vullab-rs256-key-1"
 *                         description: Key identifier
 *       500:
 *         description: Server error — RS256 public key could not be loaded or converted
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
          kid: "vullab-rs256-key-1",
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
