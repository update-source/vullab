const express = require('express');
const router = express.Router();
const { authController } = require('../../controllers/v1');
const { otpRules,
        loginRules, 
        registerRules, 
        handleValidation,
        requirePendingOtpSession } = require('../../middlewares');

// Vulnerabilities in password-based login
router.post('/enum/different-responses', loginRules, handleValidation, authController.loginEnumDifferent);
router.post('/enum/subtle-responses', loginRules, handleValidation, authController.loginEnumSubtle);
router.post('/enum/timing-responses', loginRules, handleValidation, authController.loginEnumTiming);
router.post('/enum/account-lock', loginRules, handleValidation, authController.loginEnumViaAccountLock)
router.post('/brute-force/broken-ip-block', loginRules, handleValidation, authController.loginBrokenIpBlock);
router.post('/brute-force/multiple-credentials-per-request', loginRules, handleValidation, authController.loginMultipleCredsPerRequest);
//Vulnerabilities in multi-factor authentication
router.post('/2FA/simple-bypass', loginRules, handleValidation, authController.login2FASimpleBypass);
router.post('/2FA/simple-bypass-ver2', loginRules, handleValidation, authController.login2FASimpleBypassVer2);
router.post('/2FA/verify-otp', requirePendingOtpSession, otpRules, handleValidation, authController.verify2WOtp);
module.exports = router;
