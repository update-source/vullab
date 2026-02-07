// V1 Service - Will contain vulnerable logic
const { User, LoginAttempt, UserSecurityLog } = require('../../models');
const { Op } = require('sequelize');
const bcrypt = require('bcryptjs');
const AppError = require('../../utils/AppError');
const authService = {

    async loginEnumDifferent(data) {
        const { username, password } = data;
        const existedUser = await User.findOne({ where: { username: username } });

        const dummyHash = '$2a$10$abcdefghijklmnopqrstuvwxyzABC';
        const targetHash = existedUser ? existedUser.password : dummyHash;

        const isMatch = await bcrypt.compare(password, targetHash);
        if (!existedUser) {
            throw new AppError(401, "Invalid username");
        }

        if (!isMatch) {
            throw new AppError(401, "Invalid password");
        }

        return {
            id: existedUser.id,
            username: existedUser.username,
            email: existedUser.email,
            createdAt: existedUser.createdAt
        };
    },

    async loginEnumSubtle(data) {
        const { username, password } = data;
        const existedUser = await User.findOne({ where: { username: username } });

        const dummyHash = '$2a$10$abcdefghijklmnopqrstuvwxyzABC';
        const targetHash = existedUser ? existedUser.password : dummyHash;

        const isMatch = await bcrypt.compare(password, targetHash);
        if (!existedUser) {
            throw new AppError(401, "Invalid username or password");
        }

        if (!isMatch) {
            throw new AppError(401, "Invalid username or password."); // Adding a dot 
        }

        return {
            id: existedUser.id,
            username: existedUser.username,
            email: existedUser.email,
            createdAt: existedUser.createdAt
        };
    },

    async loginEnumTiming(data) {
        const { username, password } = data;
        const existedUser = await User.findOne({ where: { username: username } });

        if (!existedUser) {
            throw new AppError(401, "Invalid username or password");
        }
        if (!await bcrypt.compare(password, existedUser.password)) {
            throw new AppError(401, "Invalid username or password");
        }

        return {
            id: existedUser.id,
            username: existedUser.username,
            email: existedUser.email,
            createdAt: existedUser.createdAt
        };
    },

    async loginEnumViaAccountLock(data) {
        const { username, password } = data;
        const existedUser = await User.findOne({ where: { username: username }});
        const userId = existedUser ? existedUser.id : null;

        const dummyHash = '$2a$10$abcdefghijklmnopqrstuvwxyzABC';
        const targetHash = existedUser ? existedUser.password : dummyHash;

        const isMatch = await bcrypt.compare(password, targetHash);

        if (existedUser && isMatch) {
            await UserSecurityLog.destroy({ where: {
                userId: userId,
                eventType: 'login_failed'
            }});

            return {
                id: existedUser.id,
                username: existedUser.username,
                email: existedUser.email,
                createdAt: existedUser.createdAt
            };
        };

        if (existedUser && !isMatch) {
            const failedAttempts = await UserSecurityLog.count({
                where: {
                    userId: userId,
                    eventType: 'login_failed',
                    createdAt: {
                        [Op.gte]: new Date(Date.now() - 3 * 60 * 1000)
                    }
                }
            });
            const MAX_ATTEMPTS = 3;

            if (failedAttempts >= MAX_ATTEMPTS) {
                throw new AppError(429, "You have made too many incorrect login attempts. Please try again in 1 minute(s).");
            }
            
            await UserSecurityLog.create({
                userId: userId,
                eventType: 'login_failed',
                createdAt: new Date(Date.now())
            });
            throw new AppError(401, "Invalid username or password");
        }
        throw new AppError(401, "Invalid username or password");
    },

    async loginBrokenIpBlock(data, ip, metadata) {
        const { username, password } = data;
        const existedUser = await User.findOne({ where: { username: username }});
        let existedIp = await LoginAttempt.findOne({ where: { ipAddress: ip }});

        const dummyHash = '$2a$10$abcdefghijklmnopqrstuvwxyzABC';
        const targetHash = existedUser ? existedUser.password : dummyHash;

        const isMatch = await bcrypt.compare(password, targetHash);

        if (!existedIp) {
            existedIp = await LoginAttempt.create({ 
                ipAddress: ip, 
                attemptCount: 0,
                metadata: metadata
            });
        }

        if (existedUser && isMatch) {
            await LoginAttempt.update(
                { 
                    attemptCount: 0,
                    blockedUntil: null,
                    lastAttempt: new Date(),
                    metadata: metadata
                }, 
                { where: { ipAddress: ip }}
            );

            return {
                id: existedUser.id,
                username: existedUser.username,
                email: existedUser.email,
                createdAt: existedUser.createdAt
            };
        }

        if (existedIp.blockedUntil && new Date() < new Date(existedIp.blockedUntil)) {
            throw new AppError(429, 'You have made too many incorrect login attempts. Please try again in 1 minute(s).');
        } 
        
        if (existedIp.blockedUntil && new Date() >= new Date(existedIp.blockedUntil)) {
            await LoginAttempt.update(
                { 
                    attemptCount: 0,
                    blockedUntil: null,
                    metadata: metadata
                }, 
                { where: { ipAddress: ip }}
            );
            existedIp.attemptCount = 0;
            existedIp.blockedUntil = null;
        }

        const newAttemptCount = existedIp.attemptCount + 1;
        const MAX_ATTEMPTS = 3;
        if (newAttemptCount >= MAX_ATTEMPTS) {
            const blockedUntil = new Date(Date.now() + 1 * 60 * 1000);
            await LoginAttempt.update(
                { 
                    attemptCount: newAttemptCount,
                    blockedUntil: blockedUntil,
                    lastAttempt: new Date(),
                    metadata: metadata
                }, 
                { where: { ipAddress: ip }}
            );
            throw new AppError(429, "You have made too many incorrect login attempts. Please try again in 1 minute(s).");
        } else {
            await LoginAttempt.update(
                { 
                    attemptCount: newAttemptCount,
                    lastAttempt: new Date(),
                    metadata: metadata
                }, 
                { where: { ipAddress: ip }}
            );
            throw new AppError(401, "Invalid username or password");
        }
    },

    async loginMultipleCredsPerRequest(data, ip, metadata) {
        // Adding the Ip block, checking the ip first, then check user and password
        let existedIp = await LoginAttempt.findOne({ where: {ipAddress: ip }});

        if (!existedIp) {
            existedIp = await LoginAttempt.create({
                ipAddress: ip,
                attemptCount: 0,
                metadata: metadata
            });
        };

        if (existedIp.blockedUntil && new Date() < new Date(existedIp.blockedUntil)) {
            throw new AppError(429, 'You have made too many incorrect login attempts. Please try again in 1 minute(s).');
        }

        if (existedIp.blockedUntil && new Date() >= new Date(existedIp.blockedUntil)) {
            await LoginAttempt.update(
                { 
                    attemptCount: 0,
                    blockedUntil: null,
                    metadata: metadata
                }, 
                { where: { ipAddress: ip }}
            );
            existedIp.attemptCount = 0;
            existedIp.blockedUntil = null;
        }
        
        const { username, password } = data;
        const existedUser = await User.findOne({ where: {username: username }});
        
        const dummyHash = '$2a$10$abcdefghijklmnopqrstuvwxyzABC';
        const targetHash = existedUser ? existedUser.password : dummyHash;
        let isMatch = false; 

        if (Array.isArray(password)) {
            for (const pass of password) {
                const matchFound = await bcrypt.compare(pass, targetHash);
                
                if (matchFound) {
                    isMatch = true;
                    break;
                }
            }
        } else {
            isMatch = await bcrypt.compare(password, targetHash);
        };

        if (!existedUser || !isMatch) {
            const newAttemptCount = existedIp.attemptCount + 1;
            const MAX_ATTEMPTS = 3;
            if (newAttemptCount >= MAX_ATTEMPTS) {
                const blockedUntil = new Date(Date.now() + 1 * 60 * 1000);
                await LoginAttempt.update(
                    { 
                        attemptCount: newAttemptCount,
                        blockedUntil: blockedUntil,
                        lastAttempt: new Date(),
                        metadata: metadata
                    }, 
                    { where: { ipAddress: ip }}
                );
                throw new AppError(429, "You have made too many incorrect login attempts. Please try again in 1 minute(s).");
            } else {
                await LoginAttempt.update(
                    { 
                        attemptCount: newAttemptCount,
                        lastAttempt: new Date(),
                        metadata: metadata
                    }, 
                    { where: { ipAddress: ip }}
                );
                throw new AppError(401, "Invalid username or password");
            }                    
        }

        await LoginAttempt.update(
            { 
                attemptCount: 0,
                blockedUntil: null,
                lastAttempt: new Date(),
                metadata: metadata
            }, 
            { where: { ipAddress: ip }}
        );

        return {
            id: existedUser.id,
            username: existedUser.username,
            email: existedUser.email,
            createdAt: existedUser.createdAt
        };
    },

    async login2FASimpleBypass(data) {
        const { username, password } = data;
        const existedUser = await User.findOne({ where: { username: username }});
        
        const dummyHash = '$2a$10$abcdefghijklmnopqrstuvwxyzABC';
        const targetHash = existedUser ? existedUser.password : dummyHash;

        const isMatch = await bcrypt.compare(password, targetHash);

        if (!existedUser || !isMatch) {
            throw new AppError(401, "Invalid username or password");
        }

        if (!existedUser.isEmailVerified) {
            throw new AppError(403, "Please verify your email before logging in.");        
        }
        
        
    },
};

module.exports = authService;
