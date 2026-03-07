const fs = require("fs");
const path = require("path");
require("dotenv").config({
  path: path.resolve(__dirname, "../../.env"),
});

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_ACCESS_EXPIRES_IN = process.env.JWT_ACCESS_EXPIRES_IN || "15m";
const JWT_REFRESH_EXPIRES_IN = process.env.JWT_REFRESH_EXPIRES_IN || "7d";
const JWT_ISSUER = process.env.JWT_ISSUER || "vullab-api";
const JWT_AUDIENCE = process.env.JWT_AUDIENCE || "vullab-client";
const JWT_KID = process.env.JWT_KID || "vullab-rs256-key-1";
const JWT_PRIVATE_KEY = fs.readFileSync(
  path.join(__dirname, "keys/private.key"),
  "utf8",
);
const WEAK_JWT_SECRET = "secret1";
const JWT_PUBLIC_KEY = fs.readFileSync(
  path.join(__dirname, "keys/public.key"),
  "utf8",
);

const accessTokenOptions = {
  expiresIn: JWT_ACCESS_EXPIRES_IN,
  issuer: JWT_ISSUER,
  audience: JWT_AUDIENCE,
  algorithm: "HS256",
  keyid: JWT_KID,
};

const refreshTokenOptions = {
  expiresIn: JWT_REFRESH_EXPIRES_IN,
  issuer: JWT_ISSUER,
  audience: JWT_AUDIENCE,
  algorithm: "HS256",
};

module.exports = {
  JWT_SECRET,
  JWT_KID,
  JWT_PUBLIC_KEY,
  JWT_PRIVATE_KEY,
  WEAK_JWT_SECRET,
  accessTokenOptions,
  refreshTokenOptions,
};
