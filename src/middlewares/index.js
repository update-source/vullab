const {
  registerRules,
  loginRules,
  otpRules,
  generateForgotPasswordTokenRules,
  resetPasswordBrokenLogicRules,
  resetSecurePasswordBrokenLogicRules,
} = require("./auth-validation.middleware");
const {
  requireAuthSession,
  resolveCookieByBase64,
  resolveCookieIdentity,
  requirePendingOtpSession,
  requireAuthSessionOrCookie,
  requireAuthSessionIgnoreStage,
} = require("./auth-session.middleware");
const errorHandler = require("./error.middleware");
const handleValidation = require("./validation.middleware");

module.exports = {
  otpRules,
  loginRules,
  errorHandler,
  registerRules,
  handleValidation,
  generateForgotPasswordTokenRules,
  resetPasswordBrokenLogicRules,
  resetSecurePasswordBrokenLogicRules,
  requireAuthSession,
  resolveCookieByBase64,
  resolveCookieIdentity,
  requirePendingOtpSession,
  requireAuthSessionOrCookie,
  requireAuthSessionIgnoreStage,
};
