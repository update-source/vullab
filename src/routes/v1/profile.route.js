const express = require('express');
const router = express.Router();
const { profileController } = require('../../controllers/v1');
const { requireAuthSession, requireAuthSessionIgnoreStage } = require('../../middlewares');

router.get('/', requireAuthSession, profileController.getProfile);
router.get('/ignored-stage', requireAuthSessionIgnoreStage, profileController.getProfile);

module.exports = router;
