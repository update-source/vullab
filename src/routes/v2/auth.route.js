const express = require('express');
const router = express.Router();
const { authController } = require('../../controllers/v2');
const { validateRegister } = require('../../middlewares/auth.validator');

router.post('/register', validateRegister, authController.register);
router.post('/enum/different-responses', authController.loginEnumDifferentFix);
router.post('/enum/subtle-responses', authController.loginEnumSubtleFix);
router.post('/enum/timing-responses', authController.loginEnumTimingFix);


module.exports = router;
