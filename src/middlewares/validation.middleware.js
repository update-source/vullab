const { validationResult } = require("express-validator");
const { errorResponse } = require("../utils/response");

const handleValidation = (req, res, next) => {
  const errors = validationResult(req);
  if (errors.isEmpty()) {
    return next();
  }

  const extractedErrors = errors.array().map((err) => ({
    field: err.path,
    message: err.msg,
  }));

  return errorResponse(res, 400, "Validation Error", extractedErrors);
};

module.exports = handleValidation;
