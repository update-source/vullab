const { userService } = require('../../services/v2');
const { successResponse } = require('../../utils/response');

const profileController = {
    async getProfile(req, res, next) {
        try {
            const result = await userService.getUserById(req.authUserId);
            return successResponse(res, result, 'Profile fetched successfully');
        } catch (error) {
            next(error);
        }
    }
};

module.exports = profileController;
