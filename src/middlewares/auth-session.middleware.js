const AppError = require('../utils/AppError');

const requireAuthSession = (req, res, next) => {
    const { session } = req;
    if (!session || session.stage !== 'logged_in' || !session.userId) {
        return next(new AppError(401, 'Unauthorized'));
    }

    req.authUserId = session.userId;
    return next();
};

module.exports = {
    requireAuthSession
};
