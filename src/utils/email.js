const { transporter } = require('../config/email.config');

const sendEmail = async (to, subject, text) => {
    try {
        await transporter.sendMail({
            from: process.env.EMAIL_USERNAME,
            to,
            subject,
            text
        });
    } catch (error) {
        throw error;
    }
};

module.exports = { sendEmail };