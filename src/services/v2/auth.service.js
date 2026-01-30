const { User } = require('../../models');
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
    }

};

module.exports = authService;
