const { registerRules, loginRules, otpRules } = require('./auth-validation.middleware');
const { requireAuthSession, 
        requirePendingOtpSession,
        requireAuthSessionIgnoreStage } = require('./auth-session.middleware');
const errorHandler = require('./error.middleware');
const handleValidation = require('./validation.middleware');

module.exports = {
    registerRules,
    loginRules,
    otpRules,
    requireAuthSession,
    errorHandler,
    handleValidation,
    requireAuthSessionIgnoreStage,
    requirePendingOtpSession
};
