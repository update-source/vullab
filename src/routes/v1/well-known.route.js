const express = require("express");
const router = express.Router();
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

let cachedJwks = null;

function buildJwks() {
  if (cachedJwks) return cachedJwks;

  const pem = fs.readFileSync(
    path.resolve(__dirname, "../../../src/config/keys/public.key"),
    "utf8",
  );
  const keyObject = crypto.createPublicKey(pem);
  const jwk = keyObject.export({ format: "jwk" });

  cachedJwks = {
    keys: [
      {
        ...jwk,
        use: "sig",
        alg: "RS256",
        kid: "vullab-rs256-key-1",
      },
    ],
  };

  return cachedJwks;
}

console.log(buildJwks());

router.get("/jwks.json", (req, res) => {
  try {
    const jwks = buildJwks();
    res.setHeader("Cache-Control", "public, max-age=3600");
    res.json(jwks);
  } catch (err) {
    res.status(500).json({ error: "Failed to load JWKS" });
  }
});

module.exports = router;
