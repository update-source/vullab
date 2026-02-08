const { User } = require('../../models');

const userService = {
    async getUserById(id) {
        return await User.findByPk(id, {
            attributes: { exclude: ['password'] }
        });
    },

    async getUserByUsername(username) {
        return await User.findOne({
            where: { username },
            attributes: { exclude: ['password'] }
        });
    },

    async getUserByEmail(email) {
        return await User.findOne({
            where: { email },
            attributes: { exclude: ['password'] }
        });
    }
};

module.exports = userService;
