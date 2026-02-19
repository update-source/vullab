const AppError = require('../utils/AppError');
const requireAuthSession = (req, res, next) => {
    const { session } = req;
    if (!session || session.stage !== 'logged_in' || !session.userId) {
        return next(new AppError(401, 'Unauthorized'));
    }

    req.authUserId = session.userId;
    return next();
};

const requireAuthSessionOrCookie = (req, res, next) => {
    const { session } = req;
    const stayLoggedInCookie = req.cookies['stay-logged-in'];
    const hasValidSession = session && session.stage === 'logged_in' && session.userId;
    const hasStayLoggedInCookie = !!stayLoggedInCookie;

    if (!hasValidSession && !hasStayLoggedInCookie) {
        return next(new AppError(401, 'Unauthorized'));
    }

    if (hasValidSession) {
        req.authUserId = session.userId;
    } else if (hasStayLoggedInCookie) {
        req.authViaCookie = true;
        req.stayLoggedInCookie = stayLoggedInCookie;
    }

    return next();
};

const requirePendingOtpSession = (req, res, next) => {
    const { session } = req;
    if (!session || !session.userId) {
        return next(new AppError(401, 'Unauthorized'));
    }
    if (session.stage !== 'pending') {
        return next(new AppError(401, 'OTP verification not pending'));
    }
    req.authUserId = session.userId;
    return next();
};


const requireAuthSessionIgnoreStage = (req, res, next) => {
    const { session } = req;
    if (!session || !session.userId) {
        return next(new AppError(401, 'Unauthorized'));
    }

    req.authUserId = session.userId;
    return next();
};

module.exports = {
    requireAuthSession,
    requireAuthSessionOrCookie,
    requirePendingOtpSession,
    requireAuthSessionIgnoreStage,
};
