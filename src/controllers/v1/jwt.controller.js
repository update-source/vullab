const { jwtService } = require("../../services/v1");
const { successResponse } = require("../../utils/response");
const {
  generateAccessToken,
  generateAccessTokenWithRS256Alg,
  generateAccessTokenWithWeakSecret,
} = require("../../utils/jwt");
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

  async jwtAuthenticationBypassViaJwkHeaderInjection(req, res, next) {
    try {
      const user =
        await jwtService.jwtAuthenticationBypassViaJwkHeaderInjection(req.body);
      const token = generateAccessTokenWithRS256Alg(user);
      return successResponse(res, token, "Login successfully");
    } catch (error) {
      next(error);
    }
  },

  async jwtAuthenticationBypassViaJkuHeaderInjection(req, res, next) {
    try {
      const user =
        await jwtService.jwtAuthenticationBypassViaJkuHeaderInjection(req.body);
      const token = generateAccessTokenWithRS256Alg(user);
      return successResponse(res, token, "Login successfully");
    } catch (error) {
      next(error);
    }
  },
};

module.exports = jwtController;
