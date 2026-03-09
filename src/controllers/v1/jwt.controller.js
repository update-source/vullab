const { jwtService } = require("../../services/v1");
const { successResponse } = require("../../utils/response");
const {
  generateAccessToken,
  generateAccessTokenWithRS256Alg,
  generateAccessTokenWithWeakSecret,
} = require("../../utils/jwt");

const jwtController = {
  async loginUnverifiedSignature(req, res, next) {
    try {
      const user = await jwtService.validateCredentials(req.body);
      const token = generateAccessToken(user);
      return successResponse(res, token, "Login successfully");
    } catch (error) {
      next(error);
    }
  },

  async loginFlawedSignatureVerification(req, res, next) {
    try {
      const user = await jwtService.validateCredentials(req.body);
      const token = generateAccessToken(user);
      return successResponse(res, token, "Login successfully");
    } catch (error) {
      next(error);
    }
  },

  async loginWeakSigningKey(req, res, next) {
    try {
      const user = await jwtService.validateCredentials(req.body);
      const token = generateAccessTokenWithWeakSecret(user);
      return successResponse(res, token, "Login successfully");
    } catch (error) {
      next(error);
    }
  },

  async loginJwkHeaderInjection(req, res, next) {
    try {
      const user = await jwtService.validateCredentials(req.body);
      const token = generateAccessTokenWithRS256Alg(user);
      return successResponse(res, token, "Login successfully");
    } catch (error) {
      next(error);
    }
  },

  async loginJkuHeaderInjection(req, res, next) {
    try {
      const user = await jwtService.validateCredentials(req.body);
      const token = generateAccessTokenWithRS256Alg(user);
      return successResponse(res, token, "Login successfully");
    } catch (error) {
      next(error);
    }
  },

  async loginKidHeaderInjection(req, res, next) {
    try {
      const user = await jwtService.validateCredentials(req.body);
      const token = generateAccessToken(user);
      return successResponse(res, token, "Login successfully");
    } catch (error) {
      next(error);
    }
  },

  async loginAlgorithmConfusion(req, res, next) {
    try {
      const user = await jwtService.validateCredentials(req.body);
      const token = generateAccessTokenWithRS256Alg(user);
      return successResponse(res, token, "Login successfully");
    } catch (error) {
      next(error);
    }
  },
};

module.exports = jwtController;
