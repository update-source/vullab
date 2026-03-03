const crypto = require("crypto");
const fs = require("fs");
const path = require("path")

const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: {
    type: "spki",
    format: "pem",
  },
  privateKeyEncoding: {
    type: "pkcs8",
    format: "pem",
  },
});

const keyDir = path.join(__dirname, '../src/config/keys');
if (!fs.existsSync(keyDir)) fs.mkdirSync(keyDir, { recursive: true });

fs.writeFileSync(path.join(keyDir, 'private.key'), privateKey);
fs.writeFileSync(path.join(keyDir, 'public.key'), publicKey);