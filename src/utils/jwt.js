const {
  JWT_SECRET,
  accessTokenOptions,
  refreshTokenOptions,
} = require("../config/jwt.config");
const jwt = require("jsonwebtoken");

const WEAK_JWT_SECRET = "secret1"

const generateAccessToken = (payload) => {
  return jwt.sign(payload, JWT_SECRET, accessTokenOptions);
};

const generateAccessTokenWithWeakSecret = (payload) => {
  return jwt.sign(payload, WEAK_JWT_SECRET, accessTokenOptions);
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
    algorithms: [refreshTokenOptions.algorithm, "none"]
  });
};
const verifyAccessTokenWithWeakSecret = (token) => {
  return jwt.verify(token, WEAK_JWT_SECRET, {
    issuer: accessTokenOptions.issuer,
    audience: accessTokenOptions.audience,
    algorithms: [accessTokenOptions.algorithm],
  });
}
const decodeToken = (token) => {
  return jwt.decode(token);
};

module.exports = {
  verifyAccessToken,
  verifyRefreshToken,
  verifyUnsignedAccessToken,
  verifyAccessTokenWithWeakSecret,
  decodeToken,
  generateAccessToken,
  generateRefreshToken,
  generateAccessTokenWithWeakSecret,
};
