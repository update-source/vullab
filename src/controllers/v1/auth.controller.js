const { authService } = require('../../services/v1');
const { successResponse } = require('../../utils/response');

const authController = {

    async loginEnumDifferent(req, res, next) {
        try {
            const result = await authService.loginEnumDifferent(req.body);
            req.session.userId = result.id;
            req.session.stage = 'logged_in';
            await req.session.save();

            return res.redirect(302, '/api/v1/profile');
        } catch (error) {
            next(error);
        }
    },

    async loginEnumSubtle(req, res, next) {
        try {
            const result = await authService.loginEnumSubtle(req.body);
            req.session.userId = result.id;
            req.session.stage = 'logged_in';
            await req.session.save();

            return res.redirect(302, '/api/v1/profile');
        } catch (error) {
            next(error);
        }
    },

    async loginEnumTiming(req, res, next) {
        try {
            const result = await authService.loginEnumTiming(req.body);
            req.session.userId = result.id;
            req.session.stage = 'logged_in';
            await req.session.save();

            return res.redirect(302, '/api/v1/profile');
        } catch (error) {
            next(error);
        }
    },

    async loginBrokenIpBlock(req, res, next) {
        try {
            const result = await authService.loginBrokenIpBlock(req.body, req.ip, req.useragent);
            req.session.userId = result.id;
            req.session.stage = 'logged_in';
            await req.session.save();

            return res.redirect(302, '/api/v1/profile');
        } catch (error) {
            next(error);
        }
    },

    async loginEnumViaAccountLock(req, res, next) {
        try {
            const result = await authService.loginEnumViaAccountLock(req.body);
            req.session.userId = result.id;
            req.session.stage = 'logged_in';
            await req.session.save();

            return res.redirect(302, '/api/v1/profile');
        } catch (error) {
            next(error);
        }
    },

    async loginMultipleCredsPerRequest(req, res, next) {
        try {
            const result = await authService.loginMultipleCredsPerRequest(req.body, req.ip, req.useragent);
            req.session.userId = result.id;
            req.session.stage = 'logged_in';
            await req.session.save();

            return res.redirect(302, '/api/v1/profile');
        } catch (error) {
            next(error);
        }
    },

    async login2FASimpleBypass(req, res, next) {
        try {
            const result = await authService.login2FASimpleBypass(req.body);
            // This vulnerability occurs when the stage is assigned login before performing the OTP verification step.
            req.session.userId = result.id;
            req.session.stage = 'logged_in'; //vul
            await req.session.save();

            return res.redirect(302, '/api/v1/profile'); // also instend of redirect user to the checking page it redirect user to profile
        } catch (error) {
            next(error);
        }
    },

    async login2FASimpleBypassVer2(req, res, next) {
        try {
            const result = await authService.login2FASimpleBypass(req.body);
            // This is ok function it use pending stage but the vun happend in the session middleware
            req.session.userId = result.id;
            req.session.stage = 'pending';
            await req.session.save();

            return res.redirect(302, '/api/v1/profile');
        } catch (error) {
            next(error);
        }
    },
    // Todo(Done): Write version 2 function, function has a vulnerability same ideal as login2FASimpleBypass
    // But this time the vulnerability occurred in the requireAuthSession middleware, it doesn't check the stage. It only checks the user ID in the session
    // requireAuthSessionIgnoreStage at auth-session.middleware.js
    async verify2WOtp(req, res, next) {
        try {
            const { otp } = req.body;
            const userId = req.session.userId;
            const result = await authService.verify2WOtp(userId, otp);

            req.session.stage = 'logged_in';
            await req.session.save();

            return res.redirect(302, '/api/v1/profile');
        } catch (error) {
            next(error);
        }
    }
};

module.exports = authController;
