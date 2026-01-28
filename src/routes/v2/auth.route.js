const express = require('express');
const router = express.Router();
const { authController } = require('../../controllers/v2');
const { validateLogin, validateRegister, validate } = require('../../middlewares');

router.post('/register', validateRegister, validate, authController.register);
router.post('/enum/different-responses', validateLogin, validate, authController.loginEnumDifferentFix);
router.post('/enum/subtle-responses', validateLogin, validate, authController.loginEnumSubtleFix);
router.post('/enum/timing-responses', validateLogin, validate, authController.loginEnumTimingFix);

module.exports = router;
