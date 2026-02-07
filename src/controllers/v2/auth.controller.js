const { authService } = require('../../services/v2');
const { successResponse } = require('../../utils/response');

const authController = {

    async register(req, res, next) {
        try {
            const user = await authService.register(req.body);
            return successResponse(res, user, 'User registered successfully', 201);
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

};

module.exports = authController;
