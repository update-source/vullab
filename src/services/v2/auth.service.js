const {
  User,
  LoginAttempt,
  UserSecurityLog,
  AuthToken,
} = require("../../models");
const { Op } = require("sequelize");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const { redisClient } = require("../../config/redis.config");
const AppError = require("../../utils/AppError");

const authService = {
  /* 
        WARNING: EDUCATIONAL PURPOSE ONLY - NOT FOR PRODUCTION
        
        This file demonstrates security vulnerabilities and basic patches for learning.
        In production, use battle-tested libraries (rate-limiter-flexible, Redis) instead.
        
        Known issues: Race conditions, no distributed support, poor performance, 
        missing audit trails, no proper rate limiting algorithms.
    */
  async register(data) {
    // This is the function for register user in vulab
    const { username, email, password, isEmailVerified } = data;

    const existingUser = await User.findOne({
      where: { [Op.or]: [{ username }, { email }] },
    });

    const saltRounds = 10;
    const salt = await bcrypt.genSalt(saltRounds);
    const hashedPassword = await bcrypt.hash(password, salt);

    if (existingUser) {
      await User.update(
        {
          username: username,
          email: email,
          password: hashedPassword,
          isEmailVerified: isEmailVerified,
        },
        { where: { username: username } },
      );
      return {
        id: existingUser.id,
        username: existingUser.username,
        email: existingUser.email,
        isEmailVerified: existingUser.isEmailVerified,
        message: "User state has been RESET for lab testing",
      };
    }

    const newUser = await User.create({
      username,
      email,
      password: hashedPassword,
      isEmailVerified: isEmailVerified || false,
    });

    return {
      id: newUser.id,
      username: newUser.username,
      email: newUser.email,
      isEmailVerified: newUser.isEmailVerified,
      message: "User registered successfully",
    };
  },
  /*
    async register2FA(data) {
        const { username, email, password } = data;
        
        const existingUser = await User.findOne({ where: { [Op.or]: [{ username }, { email }] } });

        const saltRounds = 10;
        const salt = await bcrypt.genSalt(saltRounds);
        const hashedPassword = await bcrypt.hash(password, salt);

        if (existingUser) {
            return new AppError(200, 'If this email is not already registered, we have sent an activation link to your inbox. Please check your email.');
        }
        
        
    }
    */

  async loginSecure(data) {
    /*https://github.com/spring-projects/spring-security/blob/c5632ccd838fcb2753a978918561081cff037510/core/src/main/java/org/springframework/security/authentication/dao/DaoAuthenticationProvider.java#L145
        CVE-2025-22234 - This link contain a fix path version It use dummy password like i do
        */
    const { username, password } = data;
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
      email: existedUser.email,
      createdAt: existedUser.createdAt,
    };
  },

  async loginSecureAccountLock(data) {
    const { username, password } = data;
    //https://github.com/animir/node-rate-limiter-flexible/wiki/Overall-example#minimal-protection-against-password-brute-force
    // I assume that if the user does not exist, there must be a place to save it, so metadata would be reasonable in this case.
    // Note, this approach may be an issue for your users, if somebody knows your service applies it.
    // It can be scheduled to send 5 password tries every 15 minutes and block user account for infinity.
    // It should not be a problem for MVP or early stages of a startup.

    // Check failed attempts by username STRING (works for both existing and non-existing users)
    const failedAttempts = await UserSecurityLog.count({
      where: {
        metadata: { username: username },
        eventType: "login_failed",
        createdAt: {
          [Op.gte]: new Date(Date.now() - 3 * 60 * 1000),
        },
      },
    });

    const MAX_ATTEMPTS = 3;
    if (failedAttempts >= MAX_ATTEMPTS) {
      throw new AppError(401, "Invalid username or password");
    }

    const existedUser = await User.findOne({ where: { username: username } });
    const dummyHash = "$2a$10$abcdefghijklmnopqrstuvwxyzABC";
    const targetHash = existedUser ? existedUser.password : dummyHash;

    const isMatch = await bcrypt.compare(password, targetHash);

    if (existedUser && isMatch) {
      // Clear failed attempts on successful login
      await UserSecurityLog.destroy({
        where: {
          metadata: { username: username },
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

    // Track failed attempt for BOTH existing and non-existing users
    await UserSecurityLog.create({
      userId: existedUser ? existedUser.id : null,
      eventType: "login_failed",
      metadata: { username: username },
      createdAt: new Date(),
    });

    throw new AppError(401, "Invalid username or password");
  },

  async loginSecureIpBlock(data, ip, metadata) {
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

    const isMatch = await bcrypt.compare(password, targetHash);

    if (!existedUser || !isMatch) {
      const newAttemptCount = existedIp.attemptCount + 1;

      if (newAttemptCount >= 3) {
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

  async loginSecureMultipleCredsPerRequest(data, ip, metadata) {
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

    const singlePassword = Array.isArray(password) ? password[0] : password; //only get the first element
    const isMatch = await bcrypt.compare(singlePassword, targetHash);

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

  async loginSecureIpLocAccountTracking(data, ip, metadata) {
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

    const singlePassword = Array.isArray(password) ? password[0] : password;
    const isMatch = await bcrypt.compare(singlePassword, targetHash);

    if (!existedUser || !isMatch) {
      const MAX_ATTEMPTS = 3;

      // if existedUser and password is wrong
      if (existedUser) {
        const userFailedAttempts = await UserSecurityLog.count({
          where: {
            userId: existedUser.id,
            eventType: "login_failed",
            createdAt: {
              [Op.gte]: new Date(Date.now() - 3 * 60 * 1000),
            },
          },
        });

        if (userFailedAttempts >= MAX_ATTEMPTS) {
          await UserSecurityLog.create({
            userId: existedUser.id,
            eventType: "account_under_attack",
            metadata: { username: username, ip: ip },
            createdAt: new Date(),
          });
        }
      }

      const newAttemptCount = existedIp.attemptCount + 1;
      await UserSecurityLog.create({
        userId: existedUser ? existedUser.id : null,
        eventType: "login_failed",
        metadata: { username: username, ip: ip },
        createdAt: new Date(),
      });

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

  async loginSecureStayLoggedInCookie(data) {
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
      email: existedUser.email,
      isStayLoggedIn: isStayLoggedIn,
    };
  },

  async validateStayLoggedInCookie(cookieValue) {
    const selector = cookieValue.split(":")[0];
    const validator = cookieValue.split(":")[1];
    const hashedValidator = crypto
      .createHash("sha256")
      .update(validator)
      .digest("hex");

    const existedToken = await AuthToken.findOne({
      where: { selector: selector },
    });

    const dummyHash = "a".repeat(64);
    const dbHash = existedToken?.hashedValidator ?? dummyHash;
    const isValidatorMatch = crypto.timingSafeEqual(
      Buffer.from(hashedValidator, "hex"),
      Buffer.from(dbHash, "hex"),
    );

    if (existedToken && !isValidatorMatch) {
      await AuthToken.destroy({ where: { selector: selector } });
      throw new AppError(401, "Invalid or expired remember-me cookie");
    }

    if (!existedToken) {
      throw new AppError(401, "Invalid or expired remember-me cookie");
    }

    if (existedToken.expiredAt < new Date()) {
      await AuthToken.destroy({ where: { selector: selector } });
      throw new AppError(401, "Invalid or expired remember-me cookie");
    }

    return existedToken?.userId;
  },

  async loginSecure2FASimpleBypass(data) {
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

    await redisClient.set(key, otp, { EX: 60 }); // 60

    return {
      id: existedUser.id,
      username: existedUser.username,
      email: existedUser.email,
    };
  },

  async loginSecure2FABrokenLogic(data) {
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

    return {
      id: existedUser.id,
      username: existedUser.username,
      email: existedUser.email,
    };
  },

  async verifySecure2FAOtp(userId, otp) {
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

  async brokenSecureVerify2FAOtp(userId, otp) {
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
};

module.exports = authService;
