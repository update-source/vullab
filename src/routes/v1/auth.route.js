const express = require('express');
const router = express.Router();
const { authController } = require('../../controllers/v1');
const { loginRules, handleValidation } = require('../../middlewares');

// POST /api/v1/auth/enum/different-responses - Lab: Username enumeration via different responses
router.post('/enum/different-responses', loginRules, handleValidation, authController.loginEnumDifferent);

// POST /api/v1/auth/enum/subtle-responses - Lab: Username enumeration via subtly different responses
router.post('/enum/subtle-responses', loginRules, handleValidation, authController.loginEnumSubtle);

// POST /api/v1/auth/enum/timing-responses - Lab: Username enumeration via response timing
router.post('/enum/timing-responses', loginRules, handleValidation, authController.loginEnumTiming);

    
module.exports = router;
