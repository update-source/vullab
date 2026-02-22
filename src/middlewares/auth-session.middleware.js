const AppError = require("../utils/AppError");
const { authService: authServiceV2 } = require("../services/v2");
const { userService: userServiceV1 } = require("../services/v1");
const requireAuthSession = (req, res, next) => {
  const { session } = req;
  if (!session || session.stage !== "logged_in" || !session.userId) {
    return next(new AppError(401, "Unauthorized"));
  }

  req.authUserId = session.userId;
  return next();
};

const requireAuthSessionOrCookie = (req, res, next) => {
  const { session } = req;
  const stayLoggedInCookie = req.cookies["stay-logged-in"];
  const hasValidSession =
    session && session.stage === "logged_in" && session.userId;
  const hasStayLoggedInCookie = !!stayLoggedInCookie;

  if (!hasValidSession && !hasStayLoggedInCookie) {
    return next(new AppError(401, "Unauthorized"));
  }

  if (hasValidSession) {
    req.authUserId = session.userId;
  } else if (hasStayLoggedInCookie) {
    req.authViaCookie = true;
    req.stayLoggedInCookie = stayLoggedInCookie;
  }

  return next();
};

const resolveCookieByBase64 = async (req, res, next) => {
  if (!req.authViaCookie) return next();
  try {
    const decoded = Buffer.from(req.stayLoggedInCookie, "base64").toString(
      "utf-8",
    );
    const username = decoded.split(":")[0];
    const user = await userServiceV1.getUserByUsername(username);
    if (!user) return next(new AppError(401, "Unauthorized"));
    req.authUserId = user.id;
    return next();
  } catch (err) {
    return next(new AppError(401, "Unauthorized"));
  }
};

const resolveCookieIdentity = async (req, res, next) => {
  if (!req.authViaCookie) return next();
  try {
    const userId = await authServiceV2.validateStayLoggedInCookie(
      req.stayLoggedInCookie,
    );
    req.authUserId = userId;
    return next();
  } catch (err) {
    return next(new AppError(401, "Invalid or expired remember-me cookie"));
  }
};

const requirePendingOtpSession = (req, res, next) => {
  const { session } = req;
  if (!session || !session.userId) {
    return next(new AppError(401, "Unauthorized"));
  }
  if (session.stage !== "pending") {
    return next(new AppError(401, "OTP verification not pending"));
  }
  req.authUserId = session.userId;
  return next();
};

const requireAuthSessionIgnoreStage = (req, res, next) => {
  const { session } = req;
  if (!session || !session.userId) {
    return next(new AppError(401, "Unauthorized"));
  }

  req.authUserId = session.userId;
  return next();
};

module.exports = {
  requireAuthSession,
  requireAuthSessionOrCookie,
  resolveCookieByBase64,
  resolveCookieIdentity,
  requirePendingOtpSession,
  requireAuthSessionIgnoreStage,
};
