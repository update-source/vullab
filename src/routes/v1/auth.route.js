const express = require('express');
const router = express.Router();
const { authController } = require('../../controllers/v1');
const { loginRules, handleValidation } = require('../../middlewares');

// Vulnerabilities in password-based login
router.post('/enum/different-responses', loginRules, handleValidation, authController.loginEnumDifferent);
router.post('/enum/subtle-responses', loginRules, handleValidation, authController.loginEnumSubtle);
router.post('/enum/timing-responses', loginRules, handleValidation, authController.loginEnumTiming);
router.post('/brute-force/broken-ip-block', loginRules, handleValidation, authController.loginBrokenIpBlock);
    
module.exports = router;
