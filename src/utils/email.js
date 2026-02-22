const { transporter } = require("../config/email.config");

const sendEmail = async (to, subject, text) => {
  await transporter.sendMail({
    from: process.env.EMAIL_USERNAME,
    to,
    subject,
    text,
  });
};

module.exports = { sendEmail };
