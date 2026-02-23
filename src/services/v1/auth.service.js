const {
  User,
  LoginAttempt,
  UserSecurityLog,
  UserToken,
} = require("../../models");
const { Op } = require("sequelize");
const bcrypt = require("bcryptjs");
const AppError = require("../../utils/AppError");
const { sendEmail } = require("../../utils/email");
const { redisClient } = require("../../config/redis.config");
const crypto = require("crypto");
const authService = {
  async loginEnumDifferent(data) {
    const { username, password } = data;
    const existedUser = await User.findOne({ where: { username: username } });

    const dummyHash = "$2a$10$abcdefghijklmnopqrstuvwxyzABC";
    const targetHash = existedUser ? existedUser.password : dummyHash;

    const isMatch = await bcrypt.compare(password, targetHash);
    if (!existedUser) {
      throw new AppError(401, "Invalid username");
    }

    if (!isMatch) {
      throw new AppError(401, "Invalid password");
    }

    return {
      id: existedUser.id,
      username: existedUser.username,
      email: existedUser.email,
      createdAt: existedUser.createdAt,
    };
  },

  async loginEnumSubtle(data) {
    const { username, password } = data;
    const existedUser = await User.findOne({ where: { username: username } });

    const dummyHash = "$2a$10$abcdefghijklmnopqrstuvwxyzABC";
    const targetHash = existedUser ? existedUser.password : dummyHash;

    const isMatch = await bcrypt.compare(password, targetHash);
    if (!existedUser) {
      throw new AppError(401, "Invalid username or password");
    }

    if (!isMatch) {
      throw new AppError(401, "Invalid username or password."); // Adding a dot
    }

    return {
      id: existedUser.id,
      username: existedUser.username,
      email: existedUser.email,
      createdAt: existedUser.createdAt,
    };
  },

  async loginEnumTiming(data) {
    const { username, password } = data;
    const existedUser = await User.findOne({ where: { username: username } });

    if (!existedUser) {
      throw new AppError(401, "Invalid username or password");
    }
    if (!(await bcrypt.compare(password, existedUser.password))) {
      throw new AppError(401, "Invalid username or password");
    }

    return {
      id: existedUser.id,
      username: existedUser.username,
      email: existedUser.email,
      createdAt: existedUser.createdAt,
    };
  },

  async loginEnumViaAccountLock(data) {
    const { username, password } = data;
    const existedUser = await User.findOne({ where: { username: username } });
    const userId = existedUser ? existedUser.id : null;

    const dummyHash = "$2a$10$abcdefghijklmnopqrstuvwxyzABC";
    const targetHash = existedUser ? existedUser.password : dummyHash;

    const isMatch = await bcrypt.compare(password, targetHash);

    if (existedUser && isMatch) {
      await UserSecurityLog.destroy({
        where: {
          userId: userId,
          eventType: "login_failed",
        },
      });

      return {
        id: existedUser.id,
        username: existedUser.username,
        email: existedUser.email,
        createdAt: existedUser.createdAt,
      };
    }

    if (existedUser && !isMatch) {
      const failedAttempts = await UserSecurityLog.count({
        where: {
          userId: userId,
          eventType: "login_failed",
          createdAt: {
            [Op.gte]: new Date(Date.now() - 3 * 60 * 1000),
          },
        },
      });
      const MAX_ATTEMPTS = 3;

      if (failedAttempts >= MAX_ATTEMPTS) {
        throw new AppError(
          429,
          "You have made too many incorrect login attempts. Please try again in 1 minute(s).",
        );
      }

      await UserSecurityLog.create({
        userId: userId,
        eventType: "login_failed",
        createdAt: new Date(Date.now()),
      });
      throw new AppError(401, "Invalid username or password");
    }
    throw new AppError(401, "Invalid username or password");
  },

  async loginBrokenIpBlock(data, ip, metadata) {
    const { username, password } = data;
    const existedUser = await User.findOne({ where: { username: username } });
    let existedIp = await LoginAttempt.findOne({ where: { ipAddress: ip } });

    const dummyHash = "$2a$10$abcdefghijklmnopqrstuvwxyzABC";
    const targetHash = existedUser ? existedUser.password : dummyHash;

    const isMatch = await bcrypt.compare(password, targetHash);

    if (!existedIp) {
      existedIp = await LoginAttempt.create({
        ipAddress: ip,
        attemptCount: 0,
        metadata: metadata,
      });
    }

    if (existedUser && isMatch) {
      await LoginAttempt.update(
        {
          attemptCount: 0,
          blockedUntil: null,
          lastAttempt: new Date(),
          metadata: metadata,
        },
        { where: { ipAddress: ip } },
      );

      return {
        id: existedUser.id,
        username: existedUser.username,
        email: existedUser.email,
        createdAt: existedUser.createdAt,
      };
    }

    if (
      existedIp.blockedUntil &&
      new Date() < new Date(existedIp.blockedUntil)
    ) {
      throw new AppError(
        429,
        "You have made too many incorrect login attempts. Please try again in 1 minute(s).",
      );
    }

    if (
      existedIp.blockedUntil &&
      new Date() >= new Date(existedIp.blockedUntil)
    ) {
      await LoginAttempt.update(
        {
          attemptCount: 0,
          blockedUntil: null,
          metadata: metadata,
        },
        { where: { ipAddress: ip } },
      );
      existedIp.attemptCount = 0;
      existedIp.blockedUntil = null;
    }

    const newAttemptCount = existedIp.attemptCount + 1;
    const MAX_ATTEMPTS = 3;
    if (newAttemptCount >= MAX_ATTEMPTS) {
      const blockedUntil = new Date(Date.now() + 1 * 60 * 1000);
      await LoginAttempt.update(
        {
          attemptCount: newAttemptCount,
          blockedUntil: blockedUntil,
          lastAttempt: new Date(),
          metadata: metadata,
        },
        { where: { ipAddress: ip } },
      );
      throw new AppError(
        429,
        "You have made too many incorrect login attempts. Please try again in 1 minute(s).",
      );
    } else {
      await LoginAttempt.update(
        {
          attemptCount: newAttemptCount,
          lastAttempt: new Date(),
          metadata: metadata,
        },
        { where: { ipAddress: ip } },
      );
      throw new AppError(401, "Invalid username or password");
    }
  },

  async loginMultipleCredsPerRequest(data, ip, metadata) {
    // Adding the Ip block, checking the ip first, then check user and password
    let existedIp = await LoginAttempt.findOne({ where: { ipAddress: ip } });

    if (!existedIp) {
      existedIp = await LoginAttempt.create({
        ipAddress: ip,
        attemptCount: 0,
        metadata: metadata,
      });
    }

    if (
      existedIp.blockedUntil &&
      new Date() < new Date(existedIp.blockedUntil)
    ) {
      throw new AppError(
        429,
        "You have made too many incorrect login attempts. Please try again in 1 minute(s).",
      );
    }

    if (
      existedIp.blockedUntil &&
      new Date() >= new Date(existedIp.blockedUntil)
    ) {
      await LoginAttempt.update(
        {
          attemptCount: 0,
          blockedUntil: null,
          metadata: metadata,
        },
        { where: { ipAddress: ip } },
      );
      existedIp.attemptCount = 0;
      existedIp.blockedUntil = null;
    }

    const { username, password } = data;
    const existedUser = await User.findOne({ where: { username: username } });

    const dummyHash = "$2a$10$abcdefghijklmnopqrstuvwxyzABC";
    const targetHash = existedUser ? existedUser.password : dummyHash;
    let isMatch = false;

    if (Array.isArray(password)) {
      for (const pass of password) {
        const matchFound = await bcrypt.compare(pass, targetHash);

        if (matchFound) {
          isMatch = true;
          break;
        }
      }
    } else {
      isMatch = await bcrypt.compare(password, targetHash);
    }

    if (!existedUser || !isMatch) {
      const newAttemptCount = existedIp.attemptCount + 1;
      const MAX_ATTEMPTS = 3;
      if (newAttemptCount >= MAX_ATTEMPTS) {
        const blockedUntil = new Date(Date.now() + 1 * 60 * 1000);
        await LoginAttempt.update(
          {
            attemptCount: newAttemptCount,
            blockedUntil: blockedUntil,
            lastAttempt: new Date(),
            metadata: metadata,
          },
          { where: { ipAddress: ip } },
        );
        throw new AppError(
          429,
          "You have made too many incorrect login attempts. Please try again in 1 minute(s).",
        );
      } else {
        await LoginAttempt.update(
          {
            attemptCount: newAttemptCount,
            lastAttempt: new Date(),
            metadata: metadata,
          },
          { where: { ipAddress: ip } },
        );
        throw new AppError(401, "Invalid username or password");
      }
    }

    await LoginAttempt.update(
      {
        attemptCount: 0,
        blockedUntil: null,
        lastAttempt: new Date(),
        metadata: metadata,
      },
      { where: { ipAddress: ip } },
    );

    return {
      id: existedUser.id,
      username: existedUser.username,
      email: existedUser.email,
      createdAt: existedUser.createdAt,
    };
  },

  async loginStayLoggedInCookie(data) {
    const { username, password, "stay-logged-in": isStayLoggedIn } = data;
    const existedUser = await User.findOne({ where: { username: username } });

    const dummyHash = "$2a$10$abcdefghijklmnopqrstuvwxyzABC";
    const targetHash = existedUser ? existedUser.password : dummyHash;

    const isMatch = await bcrypt.compare(password, targetHash);

    if (!existedUser || !isMatch) {
      throw new AppError(401, "Invalid username or password");
    }

    return {
      id: existedUser.id,
      username: existedUser.username,
      password: existedUser.password, // return password to create StayLoggedIn cookie
      email: existedUser.email,
      isStayLoggedIn: isStayLoggedIn,
    };
  },

  async generateFogotPasswordToken(data) {
    const { username, email } = data;

    const existedUser = username
      ? await User.findOne({ where: { username } })
      : await User.findOne({ where: { email } });

    if (!existedUser) {
      return;
    }

    const token = crypto.randomBytes(32).toString("hex");
    const tokenValue = crypto.createHash("sha256").update(token).digest("hex");

    await UserToken.create({
      userId: existedUser.id,
      tokenValue: tokenValue,
      tokenType: "password_reset",
      expiresAt: new Date(Date.now() + 5 * 60 * 1000), // 5 minutes
    });

    await sendEmail(
      existedUser.email,
      "Password Reset",
      `Your password reset token is: ${token}`,
    );
  },

  async resetPasswordBrokenLogic(data) {
    const {
      username,
      "new-password": newPassword,
      "confirm-password": confirmPassword,
      "temp-forgot-password-token": token,
    } = data;

    const existedUser = await User.findOne({ where: { username: username } });
    // I delete this bc the token is not used in the lab
    // const tokenValue = crypto.createHash("sha256").update(token).digest("hex");

    // const existedToken = await UserToken.findOne({
    //   where: { tokenValue: tokenValue, tokenType: "password_reset" },
    // });

    // if (existedToken && existedToken.expiresAt <= Date.now()) {
    //   await UserToken.destroy({ where: { tokenValue: tokenValue } });
    //   throw new AppError(401, "Token is invalid or expired");
    // }

    // if (!existedUser || !existedToken) {
    //   throw new AppError(401, "Token is invalid or expired");
    // }

    const saltRounds = 10;
    const salt = await bcrypt.genSalt(saltRounds);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    existedUser.password = hashedPassword;
    await existedUser.save();
    // await UserToken.destroy({ where: { tokenValue: tokenValue } });
  },

  async generatePasswordResetPoisoning(hostname, data) {
    const { username, email } = data;

    const existedUser = username
      ? await User.findOne({ where: { username } })
      : await User.findOne({ where: { email } });

    if (!existedUser) {
      return;
    }

    const token = crypto.randomBytes(32).toString("hex");
    const tokenValue = crypto.createHash("sha256").update(token).digest("hex");

    await UserToken.create({
      userId: existedUser.id,
      tokenValue: tokenValue,
      tokenType: "password_reset",
      expiresAt: new Date(Date.now() + 5 * 60 * 1000), // 5 minutes
    });
    const resetURL = `http://${hostname}/api/v1/auth/password-reset-poisoning?temp-forgot-password-token=${token}`;
    await sendEmail(
      existedUser.email,
      "Password Reset",
      `Your password reset token is: ${resetURL}`,
    );
  },

  async resetPasswordViaPoison(data) {
    const { "new-password": newPassword, "temp-forgot-password-token": token } =
      data;

    const tokenValue = crypto.createHash("sha256").update(token).digest("hex");

    const existedToken = await UserToken.findOne({
      where: { tokenValue: tokenValue, tokenType: "password_reset" },
    });

    if (!existedToken) {
      throw new AppError(401, "Token is invalid or expired");
    }

    if (new Date(existedToken.expiresAt) <= new Date()) {
      await UserToken.destroy({ where: { tokenValue: tokenValue } });
      throw new AppError(401, "Token is invalid or expired");
    }

    const saltRounds = 10;
    const salt = await bcrypt.genSalt(saltRounds);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    await User.update(
      { password: hashedPassword },
      { where: { id: existedToken.userId } },
    );
    await UserToken.destroy({ where: { tokenValue: tokenValue } });
  },

  async login2FASimpleBypass(data) {
    const { username, password } = data;
    const existedUser = await User.findOne({ where: { username: username } });

    const dummyHash = "$2a$10$abcdefghijklmnopqrstuvwxyzABC";
    const targetHash = existedUser ? existedUser.password : dummyHash;

    const isMatch = await bcrypt.compare(password, targetHash);

    if (!existedUser || !isMatch) {
      throw new AppError(401, "Invalid username or password");
    }

    if (!existedUser.isEmailVerified) {
      throw new AppError(403, "Please verify your email before logging in.");
    }

    const otp = crypto.randomInt(100000, 999999);
    const key = `otp:${existedUser.id}`;

    await redisClient.set(key, otp, { EX: 60 });

    await sendEmail(
      existedUser.email,
      "OTP Verification",
      `Your OTP is: ${otp}`,
    );

    return {
      id: existedUser.id,
      username: existedUser.username,
      email: existedUser.email,
    };
  },

  async login2FABrokenLogic(data) {
    const { username, password } = data;
    const existedUser = await User.findOne({ where: { username: username } });

    const dummyHash = "$2a$10$abcdefghijklmnopqrstuvwxyzABC";
    const targetHash = existedUser ? existedUser.password : dummyHash;

    const isMatch = await bcrypt.compare(password, targetHash);

    if (!existedUser || !isMatch) {
      throw new AppError(401, "Invalid username or password");
    }

    if (!existedUser.isEmailVerified) {
      throw new AppError(403, "Please verify your email before logging in.");
    }

    return {
      id: existedUser.id,
      username: existedUser.username,
      email: existedUser.email,
    };
  },

  async verify2FAOtp(userId, otp) {
    const storedOtp = await redisClient.get(`otp:${userId}`);

    if (!storedOtp) {
      throw new AppError(400, "OTP has expired");
    }

    if (otp !== Number(storedOtp)) {
      throw new AppError(400, "Invalid OTP");
    }

    const user = await User.findByPk(userId);
    if (!user) {
      throw new AppError(404, "User not found");
    }

    await redisClient.del(`otp:${userId}`);

    return {
      id: user.id,
      username: user.username,
      email: user.email,
      createdAt: user.createdAt,
    };
  },

  async brokenVerify2FAOtp(username, otp) {
    const storedOtp = await redisClient.get(`otp:${username}`);

    if (!storedOtp) {
      throw new AppError(400, "OTP has expired");
    }

    if (otp !== Number(storedOtp)) {
      throw new AppError(400, "Invalid OTP");
    }

    const user = await User.findOne({ where: { username: username } });
    if (!user) {
      throw new AppError(404, "User not found");
    }

    await redisClient.del(`otp:${username}`);

    return {
      id: user.id,
      username: user.username,
      email: user.email,
      createdAt: user.createdAt,
    };
  },
};

module.exports = authService;
