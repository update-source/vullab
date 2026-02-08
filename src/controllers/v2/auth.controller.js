const { authService } = require('../../services/v2');
const { successResponse } = require('../../utils/response');
const AppError = require('../../utils/AppError');
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
            return successResponse(res, user, 'Login successful');
        } catch (error) {
            next(error);
        }
    },

    async loginEnumSubtleFix(req, res, next) {
        try {
            const user = await authService.loginSecure(req.body);
            return successResponse(res, user, 'Login successful');
        } catch (error) {
            next(error);
        }
    },

    async loginEnumTimingFix(req, res, next) {
        try {
            const user = await authService.loginSecure(req.body);
            return successResponse(res, user, 'Login successful');
        } catch (error) {
            next(error);
        }
    },

    async loginSecureIpBlock(req, res, next) {
        try {
            const user = await authService.loginSecureIpBlock(req.body, req.ip, req.useragent); // Reverse proxy is not exist in this case so i used req.ip
            return successResponse(res, user, 'Login successful');
        } catch (error) {
            next(error);
        }
    },

    async loginSecureAccountLock(req, res, next) {
        try {
            const user = await authService.loginSecureAccountLock(req.body);
            return successResponse(res, user, 'Login successful');
        } catch (error) {
            next(error);
        }
    },

    async loginSecureMultipleCredsPerRequest(req, res, next) {
        try {
            const user = await authService.loginSecureMultipleCredsPerRequest(req.body, req.ip, req.useragent); // Reverse proxy is not exist in this case so i used req.ip
            return successResponse(res, user, 'Login successful');
        } catch (error) {
            next(error);
        }
    },
    // FIXED: Redis-like flow to prevent DoS vulnerability
    // 1. Check if IP is blocked, return 429 if blocked
    // 2. Verify password (with timing attack protection)
    // 3. IF authentication fails:
    //    - Check username rate limit ONLY if user exists (prevents DoS)
    //    - Increment IP counter
    //    - Track failed attempt for audit
    // 4. IF authentication succeeds:
    //    - Reset IP counter
    //    - Keep audit logs (don't destroy)
    // Note: Username check AFTER password verification prevents attacker from blocking legitimate users

    async loginSecureIpLocAccountTracking(req, res, next) {
        try {
            const user = await authService.loginSecureIpLocAccountTracking(req.body, req.ip, req.useragent); // Reverse proxy is not exist in this case so i used req.ip
            return successResponse(res, user, 'Login successful');
        } catch (error) {
            next(error);
        }
    },

    async loginSecure2FASimpleBypass(req, res, next) {
        try {
            const result = await authService.loginSecure2FASimpleBypass(req.body);

            req.session.userId = result.id;
            req.session.stage = 'pending'; // Fixed: Set stage to 'pending' until OTP is verified
            await req.session.save();

            //return res.redirect(302, '/api/v1/profile');
            //Cause i haven't created the otp verification page yet so instead of redirecting user to otp verification page i just send success response
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

            req.session.stage = 'logged_in';
            await req.session.save();

            return res.redirect(302, '/api/v1/profile');
        } catch (error) {
            next(error);
        }
    }
};


module.exports = authController;
