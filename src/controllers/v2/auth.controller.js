const { authService } = require('../../services/v2');
const { successResponse } = require('../../utils/response');

const authController = {

    async register(req, res, next) {
        try {
            const result = await authService.register(req.body);
            return successResponse(res, result, 'User registered successfully', 201);
        } catch (error) {
            next(error);
        }
    },

    async loginEnumDifferentFix(req, res, next) {
        try {
            const result = await authService.loginSecure(req.body);
            return successResponse(res, result, 'Login successful');
        } catch (error) {
            next(error);
        }
    },

    async loginEnumSubtleFix(req, res, next) {
        try {
            const result = await authService.loginSecure(req.body);
            return successResponse(res, result, 'Login successful');
        } catch (error) {
            next(error);
        }
    },

    async loginEnumTimingFix(req, res, next) {
        try {
            const result = await authService.loginSecure(req.body);
            return successResponse(res, result, 'Login successful');
        } catch (error) {
            next(error);
        }
    },

    async loginSecureIpBlock(req, res, next) {
        try {
            const result = await authService.loginSecureIpBlock(req.body, req.ip, req.useragent);
            return successResponse(res, result, 'Login successful');
        } catch (error) {
            next(error);
        }
    },

    async loginSecureAccountLock(req, res, next) {
        try {
            const result = await authService.loginSecureAccountLock(req.body);
            return successResponse(res, result, 'Login successful');
        } catch (error) {
            next(error);
        }
    },
    
    async loginSecureMultipleCredsPerRequest(req, res, next) {
        try {
            const result = await authService.loginSecureMultipleCredsPerRequest(req.body, req.ip, req.useragent);
            return successResponse(res, result, 'Login successful');
        } catch (error) {
            next(error);
        }
    },

};

module.exports = authController;
