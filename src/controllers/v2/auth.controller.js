const { authService } = require('../../services/v2');
const { successResponse } = require('../../utils/response');
const AppError = require('../../utils/AppError');
const { regenerateSession, destroySession } = require('../../utils/session');
const authController = {

    async register(req, res, next) {
        try {
            const result = await authService.register(req.body);
            const { message, ...user } = result;
            return successResponse(res, user, message, 201);
        } catch (error) {
            next(error);
        }
    },

    async loginEnumDifferentFix(req, res, next) {
        try {
            const user = await authService.loginSecure(req.body);
            
            await regenerateSession(req.session);
            
            req.session.userId = user.id;
            req.session.stage = 'logged_in';
            await req.session.save();

            return res.redirect(302, '/api/v1/profile');
        } catch (error) {
            next(error);
        }
    },

    async loginEnumSubtleFix(req, res, next) {
        try {
            const user = await authService.loginSecure(req.body);
            
            await regenerateSession(req.session);
            
            req.session.userId = user.id;
            req.session.stage = 'logged_in';
            await req.session.save();

            return res.redirect(302, '/api/v1/profile');
        } catch (error) {
            next(error);
        }
    },

    async loginEnumTimingFix(req, res, next) {
        try {
            const user = await authService.loginSecure(req.body);
            
            await regenerateSession(req.session);
            
            req.session.userId = user.id;
            req.session.stage = 'logged_in';
            await req.session.save();

            return res.redirect(302, '/api/v1/profile');
        } catch (error) {
            next(error);
        }
    },

    async loginSecureIpBlock(req, res, next) {
        try {
            const user = await authService.loginSecureIpBlock(req.body, req.ip, req.useragent);
            
            await regenerateSession(req.session);
            
            req.session.userId = user.id;
            req.session.stage = 'logged_in';
            await req.session.save();

            return res.redirect(302, '/api/v1/profile');
        } catch (error) {
            next(error);
        }
    },

    async loginSecureAccountLock(req, res, next) {
        try {
            const user = await authService.loginSecureAccountLock(req.body);
            
            await regenerateSession(req.session);
            
            req.session.userId = user.id;
            req.session.stage = 'logged_in';
            await req.session.save();

            return res.redirect(302, '/api/v1/profile');
        } catch (error) {
            next(error);
        }
    },

    async loginSecureMultipleCredsPerRequest(req, res, next) {
        try {
            const user = await authService.loginSecureMultipleCredsPerRequest(req.body, req.ip, req.useragent);
            
            await regenerateSession(req.session);
            
            req.session.userId = user.id;
            req.session.stage = 'logged_in';
            await req.session.save();

            return res.redirect(302, '/api/v1/profile');
        } catch (error) {
            next(error);
        }
    },
    async loginSecureIpLocAccountTracking(req, res, next) {
        try {
            const user = await authService.loginSecureIpLocAccountTracking(req.body, req.ip, req.useragent);
            
            await regenerateSession(req.session);
            
            req.session.userId = user.id;
            req.session.stage = 'logged_in';
            await req.session.save();
            
            return res.redirect(302, '/api/v1/profile');
        } catch (error) {
            next(error);
        }
    },

    async loginSecure2FASimpleBypass(req, res, next) {
        try {
            const result = await authService.loginSecure2FASimpleBypass(req.body);

            await regenerateSession(req.session);

            req.session.userId = result.id;
            req.session.stage = 'pending';
            await req.session.save();

            return successResponse(res, null, 'We have sent an OTP to your registered email. Please verify to complete login.');
        } catch (error) {
            next(error);
        }
    },

    async verify2WOtp(req, res, next) {
        try {
            const { otp } = req.body;
            const userId = req.session.userId;
            const result = await authService.verify2WOtp(userId, otp);

            const oldUserId = req.session.userId;
            await regenerateSession(req.session);

            req.session.userId = oldUserId;
            req.session.stage = 'logged_in';
            await req.session.save();

            return res.redirect(302, '/api/v1/profile');
        } catch (error) {
            next(error);
        }
    },

    async logout(req, res, next) {
        try {
            await destroySession(req.session);
            res.clearCookie('session');
            return successResponse(res, null, 'Logged out successfully');

        } catch (error) {
            next(error);
        }
    }
};


module.exports = authController;
