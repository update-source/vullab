const { xmlService } = require("../../services/v1");
const { successResponse } = require("../../utils/response");

const xmlController = {
  async exploitingXXEUsingExternalEntitiesToRetrieveFile(req, res, next) {
    try {
      const result =
        await xmlService.exploitingXXEUsingExternalEntitiesToRetrieveFile(
          req.body,
        );
      return successResponse(res, result);
    } catch (error) {
      next(error);
    }
  },
  //o perform SSRF attacks
  async exploitingXXEToPerformSSRFAttacks(req, res, next) {
    try {
      const result =
        await xmlService.exploitingXXEToPerformSSRFAttacks(
          req.body,
        );
      return successResponse(res, result);
    } catch (error) {
      next(error);
    }
  },
};

module.exports = xmlController;
