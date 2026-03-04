const {
  JWT_PRIVATE_KEY,
  JWT_PUBLIC_KEY,
  JWT_SECRET,
  WEAK_JWT_SECRET,
  accessTokenOptions,
  refreshTokenOptions,
} = require("../config/jwt.config");

const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const jwkToPem = require("jwk-to-pem");

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

const verifyAccessTokenViaHS256Alg = (token) => {
  return jwt.verify(token, JWT_SECRET, {
    issuer: accessTokenOptions.issuer,
    audience: accessTokenOptions.audience,
    algorithms: [accessTokenOptions.algorithm],
  });
};

const verifyAccessTokenViaRS256Alg = (token) => {
  return jwt.verify(token, JWT_PUBLIC_KEY, {
    issuer: accessTokenOptions.issuer,
    audience: accessTokenOptions.audience,
    algorithms: ["RS256"],
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
};

const generateJwkFromPem = (pem) => {
  return crypto.createPublicKey(pem).export({ format: "jwk" });
};

const decodeToken = (token) => {
  return jwt.decode(token);
};

module.exports = {
  decodeToken,
  verifyAccessTokenViaHS256Alg,
  verifyRefreshToken,
  verifyAccessTokenViaJwk,
  verifyUnsignedAccessToken,
  verifyAccessTokenViaRS256Alg,
  verifyAccessTokenWithWeakSecret,
  generateJwkFromPem,
  generateAccessToken,
  generateRefreshToken,
  generateAccessTokenWithRS256Alg,
  generateAccessTokenWithWeakSecret,
};
