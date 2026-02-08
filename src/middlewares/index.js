const { registerRules, loginRules } = require('./auth-validation.middleware');
const { requireAuthSession } = require('./auth-session.middleware');
const errorHandler = require('./error.middleware');
const handleValidation = require('./validation.middleware');

module.exports = {
    registerRules,
    loginRules,
    requireAuthSession,
    errorHandler,
    handleValidation
};
