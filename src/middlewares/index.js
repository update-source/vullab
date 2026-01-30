const { validateRegister, validateLogin } = require('./auth-validation.middleware');
const errorHandler = require('./error.middleware');
const validate = require('./validation.middleware');

module.exports = {
    validateRegister,
    validateLogin,
    errorHandler,
    validate
};
