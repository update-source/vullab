const { jwtService } = require("../../services/v1");
const { successResponse } = require("../../utils/response");
const { generateAccessToken, generateAccessTokenWithWeakSecret } = require("../../utils/jwt");
const AppError = require("../../utils/AppError");

const jwtController = {
  async jwtAuthenticationBypassViaUnverifiedSignature(req, res, next) {
    try {
      const user =
        await jwtService.jwtAuthenticationBypassViaUnverifiedSignature(
          req.body,
        );
      const token = generateAccessToken(user);
      return successResponse(res, token, "Login successfully");
    } catch (error) {
      next(error);
    }
  },

  async jwtAuthenticationBypassViaFlawedSignatureVerification(req, res, next) {
    try {
      const user =
        await jwtService.jwtAuthenticationBypassViaFlawedSignatureVerification(
          req.body,
        );
      const token = generateAccessToken(user);
      return successResponse(res, token, "Login successfully");
    } catch (error) {
      next(error);
    }
  },

  async jwtAuthenticationBypassViaWeakSigningKey(req, res, next) {
    try {
      const user = await jwtService.jwtAuthenticationBypassViaWeakSigningKey(
        req.body,
      );
      const token = generateAccessTokenWithWeakSecret(user);
      return successResponse(res, token, "Login successfully");
    } catch (error) {
      next(error);
    }
  },
};

module.exports = jwtController;
