require("dotenv").config({
  path: require("path").resolve(__dirname, "../../.env"),
});

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_ACCESS_EXPIRES_IN = process.env.JWT_ACCESS_EXPIRES_IN || "15m";
const JWT_REFRESH_EXPIRES_IN = process.env.JWT_REFRESH_EXPIRES_IN || "7d";
const JWT_ISSUER = process.env.JWT_ISSUER || "vullab-api";
const JWT_AUDIENCE = process.env.JWT_AUDIENCE || "vullab-client";

const accessTokenOptions = {
  expiresIn: JWT_ACCESS_EXPIRES_IN,
  issuer: JWT_ISSUER,
  audience: JWT_AUDIENCE,
  algorithm: "HS256",
};

const refreshTokenOptions = {
  expiresIn: JWT_REFRESH_EXPIRES_IN,
  issuer: JWT_ISSUER,
  audience: JWT_AUDIENCE,
  algorithm: "HS256",
};

module.exports = {
  JWT_SECRET,
  accessTokenOptions,
  refreshTokenOptions,
};
