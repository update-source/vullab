const express = require("express");
const router = express.Router();
const AppError = require("../../utils/AppError");
const { JWT_PUBLIC_KEY } = require("../../config/jwt.config");
const { generateJwkFromPem } = require("../../utils/jwt");

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
