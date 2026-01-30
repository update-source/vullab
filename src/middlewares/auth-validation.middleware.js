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
        .isLength({ min: 3, max: 50 }).withMessage('Username must be between 3 and 50 characters')
        .toLowerCase(),

    body('email')
        .trim()
        .notEmpty().withMessage('Email is required')
        .isEmail().withMessage('Invalid email address')
        .normalizeEmail(),
    
    body('password')
        .isLength({ min: 8 }).withMessage('Password must be at least 8 characters')
        .matches(/[A-Z]/).withMessage("Password must contain at least one uppercase letter")
        .matches(/[0-9]/).withMessage("Password must contain at least one number")
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

module.exports = {
    registerRules,
    loginRules
};
