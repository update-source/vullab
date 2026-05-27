const express = require("express");
const router = express.Router();
const { xmlController } = require("../../controllers/v1");

const { handleValidation } = require("../../middlewares");

router.post(
  "/retrieve-file/check-stock",
  handleValidation,
  xmlController.exploitingXXEUsingExternalEntitiesToRetrieveFile,
);

router.post(
  "/perform-SSRF-attacks/check-stock",
  handleValidation,
  xmlController.exploitingXXEToPerformSSRFAttacks,
)
module.exports = router;
