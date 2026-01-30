const { authService } = require('../../services/v1');
const { successResponse } = require('../../utils/response');

const authController = {

    async loginEnumDifferent(req, res, next) {
        try {
            const result = await authService.loginEnumDifferent(req.body);
            return successResponse(res, result, 'Login successful');
        } catch (error) {
            next(error);
        }
    },

    async loginEnumSubtle(req, res, next) {
        try {
            const result = await authService.loginEnumSubtle(req.body);
            return successResponse(res, result, 'Login successful');
        } catch (error) {
            next(error);
        }
    },

    async loginEnumTiming(req, res, next) {
        try {
            const result = await authService.loginEnumTiming(req.body);
            return successResponse(res, result, 'Login successful');
        } catch (error) {
            next(error);
        }
    },
};

module.exports = authController;
