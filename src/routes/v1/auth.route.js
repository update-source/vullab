const express = require('express');
const router = express.Router();
const { authController } = require('../../controllers/v1');
const { validateLogin, validate } = require('../../middlewares');
// POST /api/v1/auth/enum/different-responses - Lab: Username enumeration via different responses
router.post('/enum/different-responses', validateLogin, validate, authController.loginEnumDifferent);

// POST /api/v1/auth/enum/subtle-responses - Lab: Username enumeration via subtly different responses
router.post('/enum/subtle-responses', validateLogin, validate, authController.loginEnumSubtle);

// POST /api/v1/auth/enum/timing-responses - Lab: Username enumeration via response timing
router.post('/enum/timing-responses', validateLogin, validate, authController.loginEnumTiming);


module.exports = router;
