const { xmlService } = require("../../services/v1");

const xmlController = {
  async exploitingXXEUsingExternalEntitiesToRetrieveFile(req, res, next) {
    try {
      const result =
        await xmlService.exploitingXXEUsingExternalEntitiesToRetrieveFile(
          req.body,
        );
      res.json(result);
    } catch (error) {
      next(error);
    }
  },
};

module.exports = xmlController;
