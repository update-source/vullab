const express = require('express');
const router = express.Router();
const { authController } = require('../../controllers/v2');
const { loginRules, registerRules, handleValidation } = require('../../middlewares');
    
router.post('/register', registerRules, handleValidation, authController.register);
router.post('/enum/different-responses', loginRules, handleValidation, authController.loginEnumDifferentFix);
router.post('/enum/subtle-responses', loginRules, handleValidation, authController.loginEnumSubtleFix);
router.post('/enum/timing-responses', loginRules, handleValidation, authController.loginEnumTimingFix);
router.post('/enum/account-lock', loginRules, handleValidation, authController.loginSecureAccountLock);
router.post('/brute-force/broken-ip-block', loginRules, handleValidation, authController.loginSecureIpBlock);
router.post('/brute-force/multiple-credentials-per-request', loginRules, handleValidation, authController.loginSecureMultipleCredsPerRequest);

module.exports = router;
