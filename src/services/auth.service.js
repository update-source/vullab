const { User } = require('../models/user.model');
const bcrypt = require('bcrypt');

/**
 * Service xử lý logic liên quan đến Auth
 */
const authService = {

    async register(userData) {
        
        try {
            const { firstname, lastname, username, email, password } = userData

            const existingUser = await User.findOne({where: {username}})
            if (existingUser) {
                throw new Error("User already existed")
            }
            
            const saltRounds = 10
            const salt = await bcrypt.genSalt(saltRounds)
            const hashedPassword = await bcrypt.hash(password, salt)

            const newUser = await User.create({
                firstname,
                lastname,
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
    }
}