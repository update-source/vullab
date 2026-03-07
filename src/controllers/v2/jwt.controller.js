const { jwtService } = require("../../services/v2");
const { successResponse } = require("../../utils/response");
const {
  generateAccessToken,
  generateAccessTokenWithRS256Alg,
} = require("../../utils/jwt");
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

  async jwtSecureAuthenticationBypassViaFlawedSignatureVerification(
    req,
    res,
    next,
  ) {
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

  async jwtSecureAuthenticationBypassViaWeakSigningKey(req, res, next) {
    try {
      const user =
        await jwtService.jwtSecureAuthenticationBypassViaWeakSigningKey(
          req.body,
        );
      const token = generateAccessToken(user);
      return successResponse(res, token, "Login successfully");
    } catch (error) {
      next(error);
    }
  },

  async jwtSecureAuthenticationBypassViaJwkHeaderInjection(req, res, next) {
    try {
      const user =
        await jwtService.jwtSecureAuthenticationBypassViaJwkHeaderInjection(
          req.body,
        );
      const token = generateAccessTokenWithRS256Alg(user);
      return successResponse(res, token, "Login successfully");
    } catch (error) {
      next(error);
    }
  },

  async jwtSecureAuthenticationBypassViaJkuHeaderInjection(req, res, next) {
    try {
      const user =
        await jwtService.jwtSecureAuthenticationBypassViaJkuHeaderInjection(req.body);
      const token = generateAccessTokenWithRS256Alg(user);
      return successResponse(res, token, "Login successfully");
    } catch (error) {
      next(error);
    }
  },

  async jwtSecureAuthenticationBypassViaKidHeaderInjection(req, res, next) {
    try {
      const user =
        await jwtService.jwtSecureAuthenticationBypassViaKidHeaderInjection(req.body);
      const token = generateAccessToken(user);
      return successResponse(res, token, "Login successfully");
    } catch (error) {
      next(error);
    }
  },
};

module.exports = jwtController;
