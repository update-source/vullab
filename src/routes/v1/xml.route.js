const express = require("express");
const router = express.Router();
const { xmlController } = require("../../controllers/v1");

const { handleValidation } = require("../../middlewares");

router.post(
  "/external-entities-to-retrieve-file",
  handleValidation,
  xmlController.exploitingXXEUsingExternalEntitiesToRetrieveFile,
);

module.exports = router;
