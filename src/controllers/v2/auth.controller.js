const { authService } = require('../../services/v2');
const { successResponse } = require('../../utils/response');
const AppError = require('../../utils/AppError');
const { regenerateSession, destroySession } = require('../../utils/session');
const { AuthToken } = require('../../models');
const crypto = require('crypto');
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

            return res.redirect(302, '/api/v2/profile');
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

            return res.redirect(302, '/api/v2/profile');
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

            return res.redirect(302, '/api/v2/profile');
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

            return res.redirect(302, '/api/v2/profile');
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

            return res.redirect(302, '/api/v2/profile');
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

            return res.redirect(302, '/api/v2/profile');
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

            return res.redirect(302, '/api/v2/profile');
        } catch (error) {
            next(error);
        }
    },

    async loginSecure2FASimpleBypass(req, res, next) {
        try {
            const user = await authService.loginSecure2FASimpleBypass(req.body);

            await regenerateSession(req.session);

            req.session.userId = user.id;
            req.session.stage = 'pending';
            await req.session.save();

            return successResponse(res, null, 'We have sent an OTP to your registered email. Please verify to complete login.');
        } catch (error) {
            next(error);
        }
    },

    async loginSecure2FABrokenLogic(req, res, next) {
        try {
            const user = await authService.loginSecure2FABrokenLogic(req.body);

            await regenerateSession(req.session);

            req.session.userId = user.id;
            req.session.stage = 'pending';
            req.session.otpAttempt = 0; // enhancement to track OTP attempts
            await req.session.save();

            return successResponse(res, null, 'We have sent an OTP to your registered email. Please verify to complete login.');
        } catch (error) {
            next(error);
        }
    },

    async verifySecure2FAOtp(req, res, next) {
        try {
            const MAX_OTP_ATTEMPTS = 3;

            if (req.session.otpAttempt >= MAX_OTP_ATTEMPTS) {
                await destroySession(req.session);
                throw new AppError(403, 'Maximum OTP attempts exceeded. Please login again.');
            }
            const { otp } = req.body;
            const userId = req.session.userId;
            try {
                const _user = await authService.verifySecure2FAOtp(userId, otp); 
            } catch (error) {
                req.session.otpAttempt = (req.session.otpAttempt || 0) + 1;
                await req.session.save();
                throw error;
            }

            const oldUserId = req.session.userId;
            await regenerateSession(req.session);

            req.session.userId = oldUserId;
            req.session.stage = 'logged_in';
            await req.session.save();

            return res.redirect(302, '/api/v2/profile');
        } catch (error) {
            next(error);
        }
    },

    async brokenSecureVerify2FAOtp(req, res, next) {
        try {
            const MAX_OTP_ATTEMPTS = 3;

            if (req.session.otpAttempt >= MAX_OTP_ATTEMPTS) {
                await destroySession(req.session);
                throw new AppError(403, 'Maximum OTP attempts exceeded. Please login again.');
            }
            const { otp } = req.body;
            const userId = req.session.userId;
            try {
                const _user = await authService.brokenSecureVerify2FAOtp(userId, otp);
            } catch (error) {
                req.session.otpAttempt = (req.session.otpAttempt || 0) + 1;
                await req.session.save();
                throw error;
            }

            const oldUserId = req.session.userId;
            await regenerateSession(req.session);

            req.session.userId = oldUserId;
            req.session.stage = 'logged_in';
            await req.session.save();

            return res.redirect(302, '/api/v2/profile');
        } catch (error) {
            next(error);
        }
    },
    // "remember me" cookies
    // https://paragonie.com/blog/2015/04/secure-authentication-php-with-long-term-persistence#title.2
    async loginSecureStayLoggedInCookie(req, res, next) {
        try {
            const REMEMBER_ME_DAYS = 30;
            const REMEMBER_ME_MS = REMEMBER_ME_DAYS * 24 * 60 * 60 * 1000;
            const user = await authService.loginSecureStayLoggedInCookie(req.body);
            await regenerateSession(req.session);

            if (user?.isStayLoggedIn == "on") {
                const selector = crypto.randomBytes(8).toString('hex');
                const validator = crypto.randomBytes(32).toString('hex');
                const hashedValidator = crypto.createHash('sha256').update(validator).digest('hex');

                AuthToken.create({
                    selector: selector,
                    hashedValidator: hashedValidator,
                    userId: user.id,
                    expires: new Date(Date.now() + REMEMBER_ME_MS),
                    ipAddress: req.ip,
                    userAgent: req.useragent?.source
                })

                const stayLoggedInCookie = selector + ':' + validator;

                res.cookie('stay-logged-in', stayLoggedInCookie, {
                    httpOnly: true,
                    sameSite: 'lax',
                    secure: process.env.NODE_ENV === 'production',
                    maxAge: REMEMBER_ME_MS
                });
            }

            req.session.userId = user.id;
            req.session.stage = 'logged_in';
            await req.session.save();

            return res.redirect(302, '/api/v2/profile/cookie');
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
