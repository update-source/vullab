const express = require('express');
const router = express.Router();
const { authController } = require('../../controllers/v1');

// POST /api/v1/auth/enum/different-responses - Lab: Username enumeration via different responses
router.post('/enum/different-responses', authController.loginEnumDifferent);

// POST /api/v1/auth/enum/subtle-responses - Lab: Username enumeration via subtly different responses
router.post('/enum/subtle-responses', authController.loginEnumSubtle);

// POST /api/v1/auth/enum/timing-responses - Lab: Username enumeration via response timing
router.post('/enum/timing-responses', authController.loginEnumTiming);

module.exports = router;
