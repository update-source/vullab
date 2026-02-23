const {
  registerRules,
  loginRules,
  otpRules,
  generateForgotPasswordTokenRules,
  resetPasswordBrokenLogicRules,
  resetSecurePasswordBrokenLogicRules,
  changePasswordRules,
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
const { requireTrustedHost } = require("./host.middleware");
const handleValidation = require("./validation.middleware");

module.exports = {
  otpRules,
  loginRules,
  errorHandler,
  registerRules,
  handleValidation,
  requireTrustedHost,
  generateForgotPasswordTokenRules,
  resetPasswordBrokenLogicRules,
  resetSecurePasswordBrokenLogicRules,
  changePasswordRules,
  requireAuthSession,
  resolveCookieByBase64,
  resolveCookieIdentity,
  requirePendingOtpSession,
  requireAuthSessionOrCookie,
  requireAuthSessionIgnoreStage,
};
