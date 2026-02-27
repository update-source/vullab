const { User } = require("../../models");
const bcrypt = require("bcryptjs");
const AppError = require("../../utils/AppError");

require("dotenv").config({
  path: require("path").resolve(__dirname, "../../.env"),
});

const BCRYPT_SALT_ROUNDS = parseInt(process.env.BCRYPT_SALT_ROUNDS, 10);
const BCRYPT_DUMMY_PASSWORD = process.env.BCRYPT_DUMMY_PASSWORD;

const jwtService = {
  async jwtSecureAuthenticationBypassViaUnverifiedSignature(data) {
    const { password, username } = data;
    const existedUser = await User.findOne({ where: { username: username } });

    const salt = await bcrypt.genSalt(BCRYPT_SALT_ROUNDS);
    const dummyHash = await bcrypt.hash(BCRYPT_DUMMY_PASSWORD, salt);
    const targetHash = existedUser ? existedUser.password : dummyHash;

    const isMatch = await bcrypt.compare(password, targetHash);

    if (!existedUser || !isMatch) {
      throw new AppError(401, "Invalid username or password");
    }

    return {
      id: existedUser.id,
      username: existedUser.username,
      role: existedUser.role,
      createdAt: existedUser.createdAt,
    };
  },
};

module.exports = jwtService;
