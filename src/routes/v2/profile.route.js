const express = require('express');
const router = express.Router();
const { profileController } = require('../../controllers/v2');
const { requireAuthSession } = require('../../middlewares');

router.get('/', requireAuthSession, profileController.getProfile);

module.exports = router;
