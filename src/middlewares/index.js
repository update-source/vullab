const { validateRegister, validateLogin } = require('./auth.validator');
const errorHandler = require('./error.middleware');
const validate = require('./validate.middleware');

module.exports = {
    validateRegister,
    validateLogin,
    errorHandler,
    validate
};
