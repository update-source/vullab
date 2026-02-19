const { userService } = require('../../services/v1');
const { successResponse } = require('../../utils/response');
const AppError = require('../../utils/AppError');

const profileController = {
    async getProfile(req, res, next) {
        try {
            const result = await userService.getUserById(req.authUserId);
            return successResponse(res, result, 'Profile fetched successfully');
        } catch (error) {
            next(error);
        }
    },

    async getProfileByCookie(req, res, next) {
        try {
            const stayLoggedInCookie = req.stayLoggedInCookie;
            const username = Buffer.from(stayLoggedInCookie, 'base64').toString('utf-8').split(':')[0];
            const result = await userService.getUserByUsername(username);
            return successResponse(res, result, 'Profile fetched successfully');
        } catch (error) {
            next(error);
        }
    },

    async getProfileFlexible(req, res, next) {
        if (req.authUserId) {
            return profileController.getProfile(req, res, next);
        }

        if (req.stayLoggedInCookie) {
            return profileController.getProfileByCookie(req, res, next);
        }
        return next(new AppError(401, 'Unauthorized'));
    }
};

module.exports = profileController;
