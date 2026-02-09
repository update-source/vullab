const express = require('express');
const router = express.Router();
const { profileController } = require('../../controllers/v1');
const { requireAuthSession, requireAuthSessionIgnoreStage } = require('../../middlewares');

/**
 * @swagger
 * /api/v1/profile:
 *   get:
 *     tags: [Profile]
 *     summary: Get user profile (requires logged_in stage)
 *     security:
 *       - cookieAuth: []
 *     responses:
 *       200:
 *         description: User profile data
 *       401:
 *         description: Unauthorized
 */
router.get('/', requireAuthSession, profileController.getProfile);

/**
 * @swagger
 * /api/v1/profile/ignored-stage:
 *   get:
 *     tags: [Profile]
 *     summary: Get profile (ignores session stage - vulnerable)
 *     security:
 *       - cookieAuth: []
 *     responses:
 *       200:
 *         description: User profile data
 *       401:
 *         description: Unauthorized
 */
router.get('/ignored-stage', requireAuthSessionIgnoreStage, profileController.getProfile);

module.exports = router;
