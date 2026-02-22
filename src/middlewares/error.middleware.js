const { errorResponse } = require("../utils/response");
const AppError = require("../utils/AppError");

const errorHandler = (err, req, res, next) => {
  console.error(`[ERROR] ${new Date().toISOString()}:`, err);

  if (err instanceof SyntaxError && err.status === 400 && "body" in err) {
    return errorResponse(res, 400, "Invalid JSON payload");
  }

  let statusCode = err.statusCode || err.status || 500;
  let message = err.message || "Internal Server Error";

  if (process.env.NODE_ENV === "production") {
    if (statusCode >= 500) {
      message = "Internal Server Error";
    }
    if (!(err instanceof AppError) && !err.isOperational) {
      statusCode = 500;
      message = "Internal Server Error";
    }
  }

  return errorResponse(res, statusCode, message);
};

module.exports = errorHandler;
