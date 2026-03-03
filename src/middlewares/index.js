const {
  changePasswordBruteForceRules,
  changePasswordRules,
  generateForgotPasswordTokenRules,
  loginRules,
  otpRules,
  registerRules,
  resetPasswordBrokenLogicRules,
  resetSecurePasswordBrokenLogicRules,
} = require("./auth-validation.middleware");

const {
  requireAuthJwt,
  requireAuthJwtButFlawedSignatureVerification,
  requireAuthJwtButJwkHeaderInjection,
  requireAuthJwtButUnverifiedSignature,
  requireAuthJwtButWeakSigningKey,
} = require("./auth-jwt.middleware");

const {
  requireAuthSession,
  requireAuthSessionIgnoreStage,
  requireAuthSessionOrCookie,
  requirePendingOtpSession,
  resolveCookieByBase64,
  resolveCookieIdentity,
} = require("./auth-session.middleware");
const errorHandler = require("./error.middleware");
const { requireTrustedHost } = require("./host.middleware");
const handleValidation = require("./validation.middleware");

module.exports = {
  otpRules,
  loginRules,
  errorHandler,
  requireAuthJwt,
  registerRules,
  handleValidation,
  requireTrustedHost,
  requireAuthJwtButWeakSigningKey,
  requireAuthJwtButJwkHeaderInjection,
  requireAuthJwtButFlawedSignatureVerification,
  requireAuthJwtButUnverifiedSignature,
  generateForgotPasswordTokenRules,
  resetPasswordBrokenLogicRules,
  resetSecurePasswordBrokenLogicRules,
  changePasswordRules,
  changePasswordBruteForceRules,
  requireAuthSession,
  resolveCookieByBase64,
  resolveCookieIdentity,
  requirePendingOtpSession,
  requireAuthSessionOrCookie,
  requireAuthSessionIgnoreStage,
};
