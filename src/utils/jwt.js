const {
  JWT_KID,
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
  const options = { ...accessTokenOptions, algorithm: "RS256", keyid: JWT_KID };
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

const fetchJwkByKid = async (url, kid) => {
  const { keys } = await (await fetch(url)).json();
  return keys.find((k) => k.kid === kid);
};

const verifyAccessTokenViaJku = async (token) => {
  //To fit the scenario, instead of using JWT_PUBLIC_KEY directly, we will call api to get jwks
  const decodedHeader = jwt.decode(token, { complete: true })?.header;
  const port = process.env.PORT || 3500;
  const jwksUrl =
    decodedHeader?.jku ??
    `http://localhost:${port}/api/v1/.well-known/jwks.json`;

  const jwk = await fetchJwkByKid(jwksUrl, decodedHeader?.kid);
  const pem = jwkToPem(jwk);
  return jwt.verify(token, pem, {
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
  verifyAccessTokenViaJku,
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
