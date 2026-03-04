const AppError = require("../utils/AppError");
const { userService } = require("../services/v1");
const {
  decodeToken,
  verifyAccessTokenViaHS256Alg,
  verifyAccessTokenViaJwk,
  verifyAccessTokenViaRS256Alg,
  verifyAccessTokenWithWeakSecret,
  verifyUnsignedAccessToken,
} = require("../utils/jwt");

const requireAuthJwtButUnverifiedSignature = async (req, res, next) => {
  const token = req.get("Authorization")?.split(" ")[1];
  if (!token) {
    return next(new AppError(401, "Unauthorized"));
  }

  const payload = decodeToken(token);

  if (payload?.username) {
    //Use the same username field as portswigger lab
    try {
      const user = await userService.getUserByUsername(payload.username);
      if (!user) {
        return next(new AppError(401, "Unauthorized"));
      }
      req.authUserId = user.id;
      return next();
    } catch {
      return next(new AppError(401, "Unauthorized"));
    }
  }

  if (payload?.id) {
    req.authUserId = payload.id;
    return next();
  }
  return next(new AppError(401, "Unauthorized"));
};

const requireAuthJwtButFlawedSignatureVerification = async (req, res, next) => {
  const token = req.get("Authorization")?.split(" ")[1];
  if (!token) {
    return next(new AppError(401, "Unauthorized"));
  }

  const payload = verifyUnsignedAccessToken(token);

  if (payload?.username) {
    //Use the same username field as portswigger lab
    try {
      const user = await userService.getUserByUsername(payload.username);
      if (!user) {
        return next(new AppError(401, "Unauthorized"));
      }
      req.authUserId = user.id;
      return next();
    } catch {
      return next(new AppError(401, "Unauthorized"));
    }
  }

  if (payload?.id) {
    req.authUserId = payload.id;
    return next();
  }
  return next(new AppError(401, "Unauthorized"));
};

const requireAuthJwtButWeakSigningKey = async (req, res, next) => {
  const token = req.get("Authorization")?.split(" ")[1];
  if (!token) {
    return next(new AppError(401, "Unauthorized"));
  }

  const payload = verifyAccessTokenWithWeakSecret(token);

  if (payload?.username) {
    //Use the same username field as portswigger lab
    try {
      const user = await userService.getUserByUsername(payload.username);
      if (!user) {
        return next(new AppError(401, "Unauthorized"));
      }
      req.authUserId = user.id;
      return next();
    } catch {
      return next(new AppError(401, "Unauthorized"));
    }
  }

  if (payload?.id) {
    req.authUserId = payload.id;
    return next();
  }
  return next(new AppError(401, "Unauthorized"));
};

const requireAuthJwtButJwkHeaderInjection = async (req, res, next) => {
  const token = req.get("Authorization")?.split(" ")[1];
  if (!token) {
    return next(new AppError(401, "Unauthorized"));
  }

  const payload = verifyAccessTokenViaJwk(token);

  if (payload?.username) {
    //Use the same username field as portswigger lab
    try {
      const user = await userService.getUserByUsername(payload.username);
      if (!user) {
        return next(new AppError(401, "Unauthorized"));
      }
      req.authUserId = user.id;
      return next();
    } catch {
      return next(new AppError(401, "Unauthorized"));
    }
  }

  if (payload?.id) {
    req.authUserId = payload.id;
    return next();
  }
  return next(new AppError(401, "Unauthorized"));
};

const requireAuthJwtWithHS256Alg = (req, res, next) => {
  const token = req.get("Authorization")?.split(" ")[1];
  if (!token) {
    return next(new AppError(401, "Unauthorized"));
  }

  try {
    const payload = verifyAccessTokenViaHS256Alg(token);
    req.authUserId = payload?.id; // only use id
  } catch (error) {
    console.log(error.message);
    return next(new AppError(401, "Unauthorized"));
  }

  return next();
};

const requireAuthJwtWithRS256Alg = (req, res, next) => {
  const token = req.get("Authorization")?.split(" ")[1];
  if (!token) {
    return next(new AppError(401, "Unauthorized"));
  }

  try {
    const payload = verifyAccessTokenViaRS256Alg(token);
    req.authUserId = payload?.id; // only use id
  } catch (error) {
    console.log(error.message);
    return next(new AppError(401, "Unauthorized"));
  }

  return next();
};

module.exports = {
  requireAuthJwtWithHS256Alg,
  requireAuthJwtWithRS256Alg,
  requireAuthJwtButWeakSigningKey,
  requireAuthJwtButJwkHeaderInjection,
  requireAuthJwtButFlawedSignatureVerification,
  requireAuthJwtButUnverifiedSignature,
};
