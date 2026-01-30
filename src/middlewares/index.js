const { registerRules, loginRules } = require('./auth-validation.middleware');
const errorHandler = require('./error.middleware');
const handleValidation = require('./validation.middleware');

module.exports = {
    registerRules,
    loginRules,
    errorHandler,
    handleValidation
};
