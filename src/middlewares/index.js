const { registerRules, loginRules, otpRules } = require('./auth-validation.middleware');
const { requireAuthSession,
        resolveCookieByBase64,
        resolveCookieIdentity,
        requirePendingOtpSession,
        requireAuthSessionOrCookie,
        requireAuthSessionIgnoreStage } = require('./auth-session.middleware');
const errorHandler = require('./error.middleware');
const handleValidation = require('./validation.middleware');

module.exports = {
    otpRules,
    loginRules,
    errorHandler,
    registerRules,
    handleValidation,
    requireAuthSession,
    resolveCookieByBase64,
    resolveCookieIdentity,
    requirePendingOtpSession,
    requireAuthSessionOrCookie,
    requireAuthSessionIgnoreStage,
};
