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
const fs = require("fs");
const path = require("path");
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
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Fail to fetch ${url}`);
  }
  const data = await response.json();
  if (!data || !Array.isArray(data.keys)) {
    throw new Error("Invalid jwks format");
  }
  return data.keys.find((k) => k.kid === kid);
};

const verifyAccessTokenViaJku = async (token) => {
  try {
    //To fit the scenario, instead of using JWT_PUBLIC_KEY directly, we will call api to get jwks
    const decodedHeader = jwt.decode(token, { complete: true })?.header;
    const port = process.env.PORT || 3500;
    const jwksUrl =
      decodedHeader?.jku ??
      `http://localhost:${port}/api/v1/.well-known/jwks.json`;

    const jwk = await fetchJwkByKid(jwksUrl, decodedHeader?.kid);
    if (!jwt) {
      return null;
    }
    const pem = jwkToPem(jwk);
    return jwt.verify(token, pem, {
      issuer: accessTokenOptions.issuer,
      audience: accessTokenOptions.audience,
      algorithms: ["RS256"],
    });
  } catch (error) {
    return null;
  }
};

const verifyAccessTokenViaKid = (token) => {
  const decodedHeader = jwt.decode(token, { complete: true })?.header;
  if (decodedHeader?.kid) {
    try {
      const pem = fs.readFileSync(path.join(__dirname, decodedHeader.kid), {
        // path traversal
        encoding: "utf-8",
      });
      return jwt.verify(token, pem, {
        issuer: accessTokenOptions.issuer,
        audience: accessTokenOptions.audience,
        algorithms: [accessTokenOptions.algorithm],
      });
    } catch (error) {
      return;
    }
  }
  return jwt.verify(token, JWT_SECRET, {
    issuer: accessTokenOptions.issuer,
    audience: accessTokenOptions.audience,
    algorithms: [accessTokenOptions.algorithm],
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
  verifyAccessTokenViaKid,
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
