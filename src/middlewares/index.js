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
  requireAuthJwtButAlgorithmConfusion,
  requireAuthJwtButFlawedSignatureVerification,
  requireAuthJwtButJkuHeaderInjection,
  requireAuthJwtButJwkHeaderInjection,
  requireAuthJwtButKidHeaderInjection,
  requireAuthJwtButUnverifiedSignature,
  requireAuthJwtButWeakSigningKey,
  requireAuthJwtWithHS256Alg,
  requireAuthJwtWithRS256Alg,
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
  registerRules,
  handleValidation,
  requireTrustedHost,
  requireAuthJwtWithHS256Alg,
  requireAuthJwtWithRS256Alg,
  requireAuthJwtButAlgorithmConfusion,
  requireAuthJwtButKidHeaderInjection,
  requireAuthJwtButJkuHeaderInjection,
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
