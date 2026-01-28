
class AppError extends Error {
    constructor(statusCode, message) {
        super(message);
        this.statusCode = statusCode;
        this.status = statusCode;
        this.isOperational = true;

        Error.captureStackTrace(this, this.constructor);
    }
}

AppError.badRequest = (message = 'Bad Request') => new AppError(400, message);
AppError.unauthorized = (message = 'Unauthorized') => new AppError(401, message);
AppError.forbidden = (message = 'Forbidden') => new AppError(403, message);
AppError.notFound = (message = 'Not Found') => new AppError(404, message);
AppError.conflict = (message = 'Conflict') => new AppError(409, message);
AppError.internal = (message = 'Internal Server Error') => new AppError(500, message);

module.exports = AppError;
