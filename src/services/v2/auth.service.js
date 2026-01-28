const { User } = require('../../models');
const bcrypt = require('bcryptjs');

/**
 * Service xử lý logic liên quan đến Auth (V2 - Secure)
 */
const authService = {

    async register(data) {

        try {
            const { username, email, password } = data

            const existingUser = await User.findOne({ where: { username } })
            if (existingUser) {
                throw new Error("User already existed")
            }

            const saltRounds = 10
            const salt = await bcrypt.genSalt(saltRounds)
            const hashedPassword = await bcrypt.hash(password, salt)

            const newUser = await User.create({
                username,
                email,
                password: hashedPassword
            })

            const userRespone = newUser.toJSON()
            delete userRespone.password

            return userRespone
        } catch (error) {
            throw error;
        }
    },

    async loginSecure(data) {
        const { username, password } = data;

        if (!username || !password) throw new Error("Please provide required fields!");

        const existedUser = await User.findOne({ where: { username: username } });

        const dummyHash = '$2a$10$abcdefghijklmnopqrstuvwxyzABC';
        const targetHash = existedUser ? existedUser.password : dummyHash;

        const isMatch = await bcrypt.compare(password, targetHash);

        if (!existedUser || !isMatch) {
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

module.exports = authService
