require('dotenv').config({ path: require('path').resolve(__dirname, '../../.env') });
const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
  host: "smtp.ethereal.email",
  port: 587,
  secure: false, // Use true for port 465, false for port 587
  auth: {
    user: "isabell.schimmel39@ethereal.email",
    pass: "s5Dq2FEGWvT5vy394x",
  },
});

// Send an email using async/await
(async () => {
  const info = await transporter.sendMail({
    from: '"Isabell Schimmel" <isabell.schimmel39@ethereal.email>',
    to: "isabell.schimmel39@ethereal.email",
    subject: "Hello ✔",
    text: "Hello world?", // Plain-text version of the message
    html: "<b>Hello world?</b>", // HTML version of the message
  });

  console.log("Message sent:", info.messageId);
})();