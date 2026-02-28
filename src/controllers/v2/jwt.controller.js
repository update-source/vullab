const { jwtService } = require("../../services/v2");
const { successResponse } = require("../../utils/response");
const { generateAccessToken } = require("../../utils/jwt");
const AppError = require("../../utils/AppError");

const jwtController = {
  async jwtSecureAuthenticationBypassViaUnverifiedSignature(req, res, next) {
    try {
      const user =
        await jwtService.jwtSecureAuthenticationBypassViaUnverifiedSignature(
          req.body,
        );
      const token = generateAccessToken(user);
      return successResponse(res, token, "Login successfully");
    } catch (error) {
      next(error);
    }
  },

  async jwtSecureAuthenticationBypassViaFlawedSignatureVerification(req, res, next) {
    try {
      const user =
        await jwtService.jwtSecureAuthenticationBypassViaFlawedSignatureVerification(
          req.body,
        );
      const token = generateAccessToken(user);
      return successResponse(res, token, "Login successfully");
    } catch (error) {
      next(error);
    }
  },
};

module.exports = jwtController;
