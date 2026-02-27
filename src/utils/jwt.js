const {
  JWT_SECRET,
  accessTokenOptions,
  refreshTokenOptions,
} = require("../config/jwt.config");
const jwt = require("jsonwebtoken");

const generateAccessToken = (payload) => {
  return jwt.sign(payload, JWT_SECRET, accessTokenOptions);
}

const verifyToken = (token) => {
  return jwt.verify(token, JWT_SECRET);
}

const generateRefreshToken = (payload) => {
  return jwt.sign(payload, JWT_SECRET, refreshTokenOptions);
}
module.exports = {
  verifyToken,
  generateAccessToken,
  generateRefreshToken,
};
