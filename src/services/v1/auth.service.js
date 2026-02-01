// V1 Service - Will contain vulnerable logic
const { User, LoginAttempt } = require('../../models');
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
            const remainingTime = Math.ceil((new Date(existedIp.blockedUntil) - new Date()) / 1000);
            throw new AppError(429, `IP blocked. Try again after ${remainingTime} seconds`);
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
        
        if (newAttemptCount >= 3) {
            const blockedUntil = new Date(Date.now() + 3 * 60 * 1000);
            await LoginAttempt.update(
                { 
                    attemptCount: newAttemptCount,
                    blockedUntil: blockedUntil,
                    lastAttempt: new Date(),
                    metadata: metadata
                }, 
                { where: { ipAddress: ip }}
            );
            throw new AppError(429, "Too many failed attempts. IP blocked for 3 minutes");
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
}

module.exports = authService;
