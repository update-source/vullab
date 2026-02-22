const { authService } = require("../../services/v1");
const AppError = require("../../utils/AppError");
const { successResponse } = require("../../utils/response");
const { regenerateSession, destroySession } = require("../../utils/session");
const { sendEmail } = require("../../utils/email");
const { redisClient } = require("../../config/redis.config");
const crypto = require("crypto");
const authController = {
  async loginEnumDifferent(req, res, next) {
    try {
      const user = await authService.loginEnumDifferent(req.body);

      await regenerateSession(req.session);

      req.session.userId = user.id;
      req.session.stage = "logged_in";
      await req.session.save();

      return res.redirect(302, "/api/v1/profile");
    } catch (error) {
      next(error);
    }
  },

  async loginEnumSubtle(req, res, next) {
    try {
      const user = await authService.loginEnumSubtle(req.body);

      await regenerateSession(req.session);

      req.session.userId = user.id;
      req.session.stage = "logged_in";
      await req.session.save();

      return res.redirect(302, "/api/v1/profile");
    } catch (error) {
      next(error);
    }
  },

  async loginEnumTiming(req, res, next) {
    try {
      const user = await authService.loginEnumTiming(req.body);

      await regenerateSession(req.session);

      req.session.userId = user.id;
      req.session.stage = "logged_in";
      await req.session.save();

      return res.redirect(302, "/api/v1/profile");
    } catch (error) {
      next(error);
    }
  },

  async loginBrokenIpBlock(req, res, next) {
    try {
      const user = await authService.loginBrokenIpBlock(
        req.body,
        req.ip,
        req.useragent,
      );

      await regenerateSession(req.session);

      req.session.userId = user.id;
      req.session.stage = "logged_in";
      await req.session.save();

      return res.redirect(302, "/api/v1/profile");
    } catch (error) {
      next(error);
    }
  },

  async loginEnumViaAccountLock(req, res, next) {
    try {
      const user = await authService.loginEnumViaAccountLock(req.body);

      await regenerateSession(req.session);

      req.session.userId = user.id;
      req.session.stage = "logged_in";
      await req.session.save();

      return res.redirect(302, "/api/v1/profile");
    } catch (error) {
      next(error);
    }
  },

  async loginMultipleCredsPerRequest(req, res, next) {
    try {
      const user = await authService.loginMultipleCredsPerRequest(
        req.body,
        req.ip,
        req.useragent,
      );

      await regenerateSession(req.session);

      req.session.userId = user.id;
      req.session.stage = "logged_in";
      await req.session.save();

      return res.redirect(302, "/api/v1/profile");
    } catch (error) {
      next(error);
    }
  },

  async loginStayLoggedInCookie(req, res, next) {
    try {
      const user = await authService.loginStayLoggedInCookie(req.body);

      await regenerateSession(req.session);

      if (user?.isStayLoggedIn === "on") {
        const { username, password } = user;
        const md5HashOfPassword = crypto
          .createHash("md5")
          .update(password, "utf-8")
          .digest("hex");
        const stayLoggedInCookie = Buffer.from(
          username + ":" + md5HashOfPassword,
          "utf-8",
        ).toString("base64");

        res.cookie("stay-logged-in", stayLoggedInCookie, {
          httpOnly: true,
          sameSite: "lax",
          secure: process.env.NODE_ENV === "production",
          maxAge: 5 * 60 * 1000, // 5 mins
        });
      }

      req.session.userId = user.id;
      req.session.stage = "logged_in";
      await req.session.save();

      return res.redirect(302, "/api/v1/profile/cookie");
    } catch (error) {
      next(error);
    }
  },

  async generateFogotPasswordToken(req, res, next) {
    try {
      await authService.generateFogotPasswordToken(req.body);
      return successResponse(
        res,
        null,
        "Please check your email for a reset password link.",
      );
    } catch (error) {
      next(error);
    }
  },

  async resetPasswordBrokenLogic(req, res, next) {
    try {
      await authService.resetPasswordBrokenLogic(req.body);
      return successResponse(res, null, "Password reset successfully");
    } catch (error) {
      next(error);
    }
  },

  async login2FASimpleBypass(req, res, next) {
    try {
      const user = await authService.login2FASimpleBypass(req.body);
      // This vulnerability occurs when the stage is assigned login before performing the OTP verification step.
      await regenerateSession(req.session);

      req.session.userId = user.id;
      req.session.stage = "logged_in"; //vul
      await req.session.save();

      return res.redirect(302, "/api/v1/profile"); // also instend of redirect user to the checking page it redirect user to profile
    } catch (error) {
      next(error);
    }
  },

  async login2FASimpleBypassVer2(req, res, next) {
    try {
      const user = await authService.login2FASimpleBypass(req.body);
      // This is ok function it use pending stage but the vun happend in the session middleware
      await regenerateSession(req.session);

      req.session.userId = user.id;
      req.session.stage = "pending";
      await req.session.save();

      return res.redirect(302, "/api/v1/profile");
    } catch (error) {
      next(error);
    }
  },

  async login2FABrokenLogic(req, res, next) {
    // Although it still create a pending session, but it make the cookie which is used later during OTP verification
    try {
      const user = await authService.login2FABrokenLogic(req.body);

      await regenerateSession(req.session);

      const verifyUser = req.cookies.verify || user.username;
      res.cookie("verify", verifyUser, {
        // Vulnerable cookie storing username for OTP verification
        httpOnly: true,
        sameSite: "lax",
        secure: process.env.NODE_ENV === "production",
        maxAge: 5 * 60 * 1000, // 5 mins
      });

      // Vulnerable: OTP is generated for verifyUser (from cookie) instead of authenticated user
      const otp = crypto.randomInt(100000, 999999);
      await redisClient.set(`otp:${verifyUser}`, otp, { EX: 60 }); // Overwritten previous otp if any
      await sendEmail(user.email, "OTP Verification", `Your OTP is: ${otp}`);
      req.session.userId = user.id;
      req.session.stage = "pending";
      await req.session.save();

      return successResponse(
        res,
        null,
        "We have sent an OTP to your registered email. Please verify to complete login.",
      );
    } catch (error) {
      next(error);
    }
  },

  // Todo(Done): Write version 2 function, function has a vulnerability same ideal as login2FASimpleBypass
  // But this time the vulnerability occurred in the requireAuthSession middleware, it doesn't check the stage. It only checks the user ID in the session
  // requireAuthSessionIgnoreStage at auth-session.middleware.js
  async verify2FAOtp(req, res, next) {
    try {
      const { otp } = req.body;
      const userId = req.session.userId;
      const _user = await authService.verify2FAOtp(userId, otp);

      const oldUserId = req.session.userId;
      await regenerateSession(req.session);

      req.session.userId = oldUserId;
      req.session.stage = "logged_in";
      await req.session.save();

      return res.redirect(302, "/api/v1/profile");
    } catch (error) {
      next(error);
    }
  },

  async brokenVerify2FAOtp(req, res, next) {
    try {
      const { otp } = req.body;
      const username = req.cookies.verify; // Vulnerable: relying on "verify cookie" to identify user
      if (!username) {
        throw new AppError(400, "Verification cookie is missing");
      }
      const user = await authService.brokenVerify2FAOtp(username, otp);

      await regenerateSession(req.session);
      req.session.userId = user.id;
      req.session.stage = "logged_in";
      await req.session.save();

      return res.redirect(302, "/api/v1/profile");
    } catch (error) {
      next(error);
    }
  },

  async logout(req, res, next) {
    try {
      await destroySession(req.session);
      res.clearCookie("session");
      return successResponse(res, null, "Logged out successfully");
    } catch (error) {
      next(error);
    }
  },
};

module.exports = authController;
