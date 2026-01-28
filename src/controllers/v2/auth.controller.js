const { authService } = require('../../services/v2');
const { validationResult } = require('express-validator');
const { loginEnumTiming } = require('../v1/auth.controller');

const authController = {
    async register(req, res) {
        try {

            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({ errors: errors.array() });
            }

            const result = await authService.register(req.body);

            return res.status(201).json({
                message: 'User registered successfully',
                data: result
            });

        } catch (error) {
            if (error.message === "User already existed") {
                return res.status(409).json({ message: error.message });
            }
            console.error(error);
            return res.status(500).json({ message: 'Internal Server Error' });
        }
    },

    async loginEnumDifferentFix(req, res) {
        try {
            const result = await authService.loginSecure(req.body);
            return res.status(200).json({ message: "Login success", data: result })
        } catch (error) {
            return res.status(401).json({ message: error.message });
        }
    },

    async loginEnumSubtleFix(req, res) {
        try {
            const result = await authService.loginSecure(req.body);
            return res.status(200).json({ message: "Login success", data: result })
        } catch (error) {
            return res.status(401).json({ message: error.message });
        }
    },

    async loginEnumTimingFix(req, res) {
        try {
            const result = await authService.loginSecure(req.body);
            return res.status(200).json({ message: "Login success", data: result })
        } catch (error) {
            return res.status(401).json({ message: error.message });
        }
    },


};

module.exports = authController;
