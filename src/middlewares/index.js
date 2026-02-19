const { registerRules, loginRules, otpRules } = require('./auth-validation.middleware');
const { requireAuthSession, 
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
    requirePendingOtpSession,
    requireAuthSessionOrCookie,
    requireAuthSessionIgnoreStage
};
