// V1 Service - Will contain vulnerable logic
const { User } = require('../../models');
const bcrypt = require('bcryptjs');

const authService = {

    async loginEnumDifferent(data) {
        const { username, password } = data;

        if (!username || !password) throw new Error("Please provide required fields!");

        const existedUser = await User.findOne({ where: { username: username } });

        const dummyHash = '$2a$10$abcdefghijklmnopqrstuvwxyzABC';
        const targetHash = existedUser ? existedUser.password : dummyHash;
            
        const isMatch = await bcrypt.compare(password, targetHash);
        if (!existedUser) {
            throw new Error("Invalid username");
        }

        if (!isMatch) {
            throw new Error("Invalid password");
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

        if (!username || !password) throw new Error("Please provide required fields!");

        const existedUser = await User.findOne({ where: { username: username } });

        const dummyHash = '$2a$10$abcdefghijklmnopqrstuvwxyzABC';
        const targetHash = existedUser ? existedUser.password : dummyHash;
            
        const isMatch = await bcrypt.compare(password, targetHash);
        if (!existedUser) {
            throw new Error("Invalid username or password");
        }

        if (!isMatch) {
            throw new Error("Invalid username or password."); // Adding a dot 
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

        if (!username, !password) throw new Error("Please provide required fields!");

        const existedUser = await User.findOne({ where: { username: username } });

        if (!existedUser) {
            throw new Error("Invalid username or password");
        }
        if (!await bcrypt.compare(password, existedUser.password)) {
            throw new Error("Invalid username or password");
        }

        return {
            id: existedUser.id,
            username: existedUser.username,
            email: existedUser.email,
            createdAt: existedUser.createdAt
        };
    }
}

module.exports = authService;
