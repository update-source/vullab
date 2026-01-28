// V1 Controller - Will contain vulnerabilities
const { authService } = require('../../services/v1');
const { loginEnumTiming } = require('../../services/v1/auth.service');

const authController = {

    async loginEnumDifferent(req, res) {
        try {
            const result = await authService.loginEnumDifferent(req.body);
            return res.status(200).json({ message: "Login success", data: result })
        } catch (error) {
            return res.status(401).json({ message: error.message });
        }
    },

    async loginEnumSubtle(req, res) {
        try {
            const result = await authService.loginEnumSubtle(req.body);
            return res.status(200).json({ message: "Login success", data: result })
        } catch (error) {
            return res.status(401).json({ message: error.message });
        }
    },
    
    async loginEnumTiming(req, res) {
        try {
            const result = await authService.loginEnumTiming(req.body);
            return res.status(200).json({ message: "Login success", data: result })
        } catch (error) {
            return res.status(401).json({ message: error.message });
        }
    },
};

module.exports = authController;
