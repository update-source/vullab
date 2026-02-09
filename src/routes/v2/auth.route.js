const express = require('express');
const router = express.Router();
const { authController } = require('../../controllers/v2');
const { otpRules,
        loginRules, 
        registerRules, 
        handleValidation,
        requirePendingOtpSession } = require('../../middlewares');

/**
 * @swagger
 * /api/v2/auth/register:
 *   post:
 *     tags: [V2 - Authentication (Secure)]
 *     summary: Register a new user
 *     description: |
 *       Register a new user account. Since SMTP is not configured, you can set 
 *       `isEmailVerified: true` to bypass email verification for testing.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/RegisterRequest'
 *     responses:
 *       201:
 *         description: User registered successfully
 *       400:
 *         description: Validation error
 */
router.post('/register', registerRules, handleValidation, authController.register);

/**
 * @swagger
 * /api/v2/auth/enum/different-responses:
 *   post:
 *     tags: [V2 - Authentication (Secure)]
 *     summary: Secure login (fixed enumeration)
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/LoginRequest'
 *     responses:
 *       302:
 *         description: Redirect to profile on success
 */
router.post('/enum/different-responses', loginRules, handleValidation, authController.loginEnumDifferentFix);

/**
 * @swagger
 * /api/v2/auth/enum/subtle-responses:
 *   post:
 *     tags: [V2 - Authentication (Secure)]
 *     summary: Secure login (fixed subtle enumeration)
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/LoginRequest'
 *     responses:
 *       302:
 *         description: Redirect to profile on success
 */
router.post('/enum/subtle-responses', loginRules, handleValidation, authController.loginEnumSubtleFix);

/**
 * @swagger
 * /api/v2/auth/enum/timing-responses:
 *   post:
 *     tags: [V2 - Authentication (Secure)]
 *     summary: Secure login (fixed timing attack)
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/LoginRequest'
 *     responses:
 *       302:
 *         description: Redirect to profile on success
 */
router.post('/enum/timing-responses', loginRules, handleValidation, authController.loginEnumTimingFix);

/**
 * @swagger
 * /api/v2/auth/enum/account-lock:
 *   post:
 *     tags: [V2 - Authentication (Secure)]
 *     summary: Secure login with proper account locking
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/LoginRequest'
 *     responses:
 *       302:
 *         description: Redirect to profile on success
 */
router.post('/enum/account-lock', loginRules, handleValidation, authController.loginSecureAccountLock);

/**
 * @swagger
 * /api/v2/auth/brute-force/broken-ip-block:
 *   post:
 *     tags: [V2 - Authentication (Secure)]
 *     summary: Secure login with proper IP blocking
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/LoginRequest'
 *     responses:
 *       302:
 *         description: Redirect to profile on success
 */
router.post('/brute-force/broken-ip-block', loginRules, handleValidation, authController.loginSecureIpBlock);

/**
 * @swagger
 * /api/v2/auth/brute-force/multiple-credentials-per-request:
 *   post:
 *     tags: [V2 - Authentication (Secure)]
 *     summary: Secure login (reject multiple credentials)
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/LoginRequest'
 *     responses:
 *       302:
 *         description: Redirect to profile on success
 */
router.post('/brute-force/multiple-credentials-per-request', loginRules, handleValidation, authController.loginSecureMultipleCredsPerRequest);

/**
 * @swagger
 * /api/v2/auth/2FA/simple-bypass:
 *   post:
 *     tags: [V2 - Authentication (Secure)]
 *     summary: Secure 2FA login (no bypass)
 *     description: After this step, call /api/v2/auth/2FA/verify-otp with the OTP.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/LoginRequest'
 *     responses:
 *       200:
 *         description: OTP sent to email
 */
router.post('/2FA/simple-bypass', loginRules, handleValidation, authController.loginSecure2FASimpleBypass);

/**
 * @swagger
 * /api/v2/auth/2FA/verify-otp:
 *   post:
 *     tags: [V2 - Authentication (Secure)]
 *     summary: Verify OTP code (secure)
 *     description: Call this after /api/v2/auth/2FA/simple-bypass to complete login.
 *     security:
 *       - cookieAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/OTPRequest'
 *     responses:
 *       302:
 *         description: Redirect to profile on success
 */
router.post('/2FA/verify-otp', requirePendingOtpSession, otpRules, handleValidation, authController.verify2WOtp);

/**
 * @swagger
 * /api/v2/auth/logout:
 *   post:
 *     tags: [V2 - Authentication (Secure)]
 *     summary: Logout (secure session cleanup)
 *     security:
 *       - cookieAuth: []
 *     responses:
 *       200:
 *         description: Logged out successfully
 */
router.post('/logout', authController.logout);

module.exports = router;
    