const {
  JWT_SECRET,
  accessTokenOptions,
  refreshTokenOptions,
} = require("../config/jwt.config");

const fs = require("fs");
const jwt = require("jsonwebtoken");
const jwkToPem = require("jwk-to-pem");

const JWT_PRIVATE_KEY = fs.readFileSync("private.key", "utf8");
const JWT_PUBLIC_KEY = fs.readFileSync("public.key", "utf8");
const WEAK_JWT_SECRET = "secret1";

const generateAccessToken = (payload) => {
  return jwt.sign(payload, JWT_SECRET, accessTokenOptions);
};

const generateAccessTokenWithWeakSecret = (payload) => {
  return jwt.sign(payload, WEAK_JWT_SECRET, accessTokenOptions);
};

const generateAccessTokenWithRS256Alg = (payload) => {
  const options = { ...accessTokenOptions, algorithm: "RS256" };
  return jwt.sign(payload, JWT_PRIVATE_KEY, options);
};
const generateRefreshToken = (payload) => {
  return jwt.sign(payload, JWT_SECRET, refreshTokenOptions);
};

const verifyAccessToken = (token) => {
  return jwt.verify(token, JWT_SECRET, {
    issuer: accessTokenOptions.issuer,
    audience: accessTokenOptions.audience,
    algorithms: [accessTokenOptions.algorithm],
  });
};

const verifyRefreshToken = (token) => {
  return jwt.verify(token, JWT_SECRET, {
    issuer: refreshTokenOptions.issuer,
    audience: refreshTokenOptions.audience,
    algorithms: [refreshTokenOptions.algorithm],
  });
};

const verifyUnsignedAccessToken = (token) => {
  const decodedHeader = jwt.decode(token, { complete: true })?.header;
  const secret = decodedHeader?.alg === "none" ? undefined : JWT_SECRET;
  return jwt.verify(token, secret, {
    issuer: refreshTokenOptions.issuer,
    audience: refreshTokenOptions.audience,
    algorithms: [refreshTokenOptions.algorithm, "none"],
  });
};
const verifyAccessTokenWithWeakSecret = (token) => {
  return jwt.verify(token, WEAK_JWT_SECRET, {
    issuer: accessTokenOptions.issuer,
    audience: accessTokenOptions.audience,
    algorithms: [accessTokenOptions.algorithm],
  });
};

const verifyAccessTokenViaJwk = (token) => {
  const decodedHeader = jwt.decode(token, { complete: true })?.header;
  if (decodedHeader?.jwk) {
    const pem = jwkToPem(decodedHeader.jwk);
    return jwt.verify(token, pem, {
      issuer: accessTokenOptions.issuer,
      audience: accessTokenOptions.audience,
      algorithms: ["RS256"],
    });
  }
  // If user does not send jwk, the public key will be used
  return jwt.verify(token, JWT_PUBLIC_KEY, {
    issuer: accessTokenOptions.issuer,
    audience: accessTokenOptions.audience,
    algorithms: ["RS256"],
  });

};const decodeToken = (token) => {
  return jwt.decode(token);
};

module.exports = {
  decodeToken,
  verifyAccessToken,
  verifyRefreshToken,
  verifyAccessTokenViaJwk,
  verifyUnsignedAccessToken,
  verifyAccessTokenWithWeakSecret,
  generateAccessToken,
  generateRefreshToken,
  generateAccessTokenWithRS256Alg,
  generateAccessTokenWithWeakSecret,
};
