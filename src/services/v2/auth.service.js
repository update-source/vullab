const { User } = require('../../models');
const bcrypt = require('bcryptjs');
const AppError = require('../../utils/AppError');

const authService = {

    async register(data) {
        const { username, email, password } = data;

        const existingUser = await User.findOne({ where: { username } });
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

        const userResponse = newUser.toJSON();
        delete userResponse.password;

        return userResponse;
    },

    async loginSecure(data) {
        const { username, password } = data;
        const existedUser = await User.findOne({ where: { username: username } });

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
    }

};

module.exports = authService;
