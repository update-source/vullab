const { User, LoginAttempt, UserSecurityLog } = require('../../models');
const { Op } = require('sequelize');
const bcrypt = require('bcryptjs');
const AppError = require('../../utils/AppError');

const authService = {

    async register(data) {
        const { username, email, password } = data;

        const existingUser = await User.findOne({ where: { [Op.or]: [{ username }, { email }] } });
        if (existingUser) {
            throw new AppError(409, 'User already existed');
        }

        const saltRounds = 10;
        const salt = await bcrypt.genSalt(saltRounds);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = await User.create({
            username,
            email,
            password: hashedPassword
        });

        return {
            id: newUser.id,
            username: newUser.username,
            email: newUser.email,
        };
    },

    async loginSecure(data) {
        /*https://github.com/spring-projects/spring-security/blob/c5632ccd838fcb2753a978918561081cff037510/core/src/main/java/org/springframework/security/authentication/dao/DaoAuthenticationProvider.java#L145
        CVE-2025-22234 - This link contain a fix path version It use dummy password like i do
        */
        const { username, password } = data;
        const existedUser = await User.findOne({ where: { [Op.or]: [{ username }, { email: username }] } });

        const dummyHash = '$2a$10$abcdefghijklmnopqrstuvwxyzABC';
        const targetHash = existedUser ? existedUser.password : dummyHash;

        const isMatch = await bcrypt.compare(password, targetHash);

        if (!existedUser || !isMatch) {
            throw new AppError(401, 'Invalid username or password');
        }

        return {
            id: existedUser.id,
            username: existedUser.username,
            email: existedUser.email,
            createdAt: existedUser.createdAt
        };
    },

    async loginSecureAccountLock(data) {
        const { username, password } = data;
        
        // Check failed attempts by username STRING (works for both existing and non-existing users)
        const failedAttempts = await UserSecurityLog.count({
            where: {
                metadata: { username: username },
                eventType: 'login_failed',
                createdAt: {
                    [Op.gte]: new Date(Date.now() - 3 * 60 * 1000)
                }
            }
        });
        
        const MAX_ATTEMPTS = 3;
        if (failedAttempts >= MAX_ATTEMPTS) {
            throw new AppError(401, "Invalid username or password");
        }

        const existedUser = await User.findOne({ where: { username: username }});
        const dummyHash = '$2a$10$abcdefghijklmnopqrstuvwxyzABC';
        const targetHash = existedUser ? existedUser.password : dummyHash;

        const isMatch = await bcrypt.compare(password, targetHash);

        if (existedUser && isMatch) {
            // Clear failed attempts on successful login
            await UserSecurityLog.destroy({ 
                where: {
                    metadata: { username: username },
                    eventType: 'login_failed'
                }
            });

            return {
                id: existedUser.id,
                username: existedUser.username,
                email: existedUser.email,
                createdAt: existedUser.createdAt
            };
        }

        // Track failed attempt for BOTH existing and non-existing users
        await UserSecurityLog.create({
            userId: existedUser ? existedUser.id : null,
            eventType: 'login_failed',
            metadata: { username: username },
            createdAt: new Date()
        });
        
        throw new AppError(401, "Invalid username or password");
    },

    async loginSecureIpBlock(data, ip, metadata) {
        let existedIp = await LoginAttempt.findOne({ where: { ipAddress: ip }});

        if (!existedIp) {
            existedIp = await LoginAttempt.create({ 
                ipAddress: ip, 
                attemptCount: 0,
                metadata: metadata
            });
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

        const { username, password } = data;
        const existedUser = await User.findOne({ where: { username: username }});

        const dummyHash = '$2a$10$abcdefghijklmnopqrstuvwxyzABC';
        const targetHash = existedUser ? existedUser.password : dummyHash;

        const isMatch = await bcrypt.compare(password, targetHash);

        if (!existedUser || !isMatch) {
            const newAttemptCount = existedIp.attemptCount + 1;
            
            if (newAttemptCount >= 3) {
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

    async loginSecureMultipleCredsPerRequest(data, ip, metadata) {
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

        const singlePassword = Array.isArray(password) ? password[0] : password; //only get the first element
        const isMatch = await bcrypt.compare(singlePassword, targetHash);

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

};

module.exports = authService;
