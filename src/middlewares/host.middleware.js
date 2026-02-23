const AppError = require("../utils/AppError");

const ALLOWED_HOSTS = (process.env.ALLOWED_HOSTS || "localhost")
  .split(",")
  .map((h) => h.trim());

const requireTrustedHost = (req, res, next) => {
  if (!ALLOWED_HOSTS.includes(req.hostname)) {
    return next(new AppError(400, "Invalid or untrusted host"));
  }
  return next();
};

module.exports = { requireTrustedHost };
