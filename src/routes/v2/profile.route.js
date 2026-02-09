const express = require('express');
const router = express.Router();
const { profileController } = require('../../controllers/v2');
const { requireAuthSession } = require('../../middlewares');

/**
 * @swagger
 * /api/v2/profile:
 *   get:
 *     tags: [V2 - Profile (Secure)]
 *     summary: Get user profile (secure - requires logged_in stage)
 *     description: Securely retrieves user profile data. Properly validates session stage.
 *     security:
 *       - cookieAuth: []
 *     responses:
 *       200:
 *         description: User profile data
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 data:
 *                   type: object
 *       401:
 *         description: Unauthorized - missing or invalid session
 *       403:
 *         description: Forbidden - session stage not valid
 */
router.get('/', requireAuthSession, profileController.getProfile);

module.exports = router;
