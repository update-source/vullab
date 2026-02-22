const { body } = require('express-validator');
/*
    Best Practices for Basic Validation
    Sanitize before validating - Remove unwanted characters first, then check if the data is valid
    Use descriptive error messages - Help users understand what went wrong
    Handle all validation errors - Always check validationResult before proceeding
    Combine validators - Chain multiple validators for complex validation rules
    Use optional() for optional fields - This clearly indicates fields that aren't required
    Prevent XSS attacks - Use escape() for user-generated content displayed in HTML
    Use matchedData() when convenient - Get a clean object with just the validated fields
*/
const registerRules = [
    body('username')
        .trim()
        .notEmpty().withMessage('Username is required')
        .isLength({ min: 3, max: 30 }).withMessage('Username must be between 3 and 30 characters')
        .matches(/^[a-zA-Z0-9_-]+$/).withMessage('Username can only contain letters, numbers, underscore and hyphen')
        .matches(/^[a-zA-Z0-9]/).withMessage('Username must start with a letter or number')
        .matches(/[a-zA-Z0-9]$/).withMessage('Username must end with a letter or number')
        .not().matches(/[-_]{2,}/).withMessage('Username cannot contain consecutive special characters')
        .toLowerCase(),

    body('email')
        .trim()
        .notEmpty().withMessage('Email is required')
        .isEmail().withMessage('Invalid email address')
        .normalizeEmail(),
    
    body('password')
        .isStrongPassword({
            minLength: 8,
            minLowercase: 1,
            minUppercase: 1,
            minNumbers: 1,
            minSymbols: 1
        })
        .withMessage('Password must be at least 8 characters with uppercase and number')
];

const loginRules = [
    body('username')
        .trim()
        .notEmpty().withMessage('Username is required')
        .isLength({ min: 3, max: 50 }).withMessage('Username must be between 3 and 50 characters'),

    body('password')
        .trim()
        .notEmpty().withMessage('Password is required')
        .isLength({ min: 8 }).withMessage('Password must be at least 8 characters'),
];

const otpRules = [
    body('otp')
        .exists().withMessage('OTP is required')
        .isLength({ min: 6, max: 6 }).withMessage('OTP must be 6 digits')
    .isNumeric().withMessage('OTP must contain only numbers')
    .toInt()
];

const forgotPasswordRules = [
    body('username')
        .trim()
        .notEmpty().withMessage('Username is required')
        .isLength({ min: 3, max: 50 }).withMessage('Username must be between 3 and 50 characters'),

    body('email')
        .trim()
        .notEmpty().withMessage('Email is required')
        .isEmail().withMessage('Invalid email address')
        .normalizeEmail(),

    body().custom((value, { req }) => {
        const { username, email } = req.body;
        if (!username && !email) {
            throw new Error('Username or email is required');
        }
        return true;
    }),

    body('forgot-password')
        .exists().withMessage('Forgot password is required')
        .isBoolean().withMessage('Forgot password must be a boolean')
        .toBoolean()
];
module.exports = {
    registerRules,
    loginRules,
    otpRules,
    forgotPasswordRules
};
