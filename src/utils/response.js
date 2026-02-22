const successResponse = (res, data, message = "Success", statusCode = 200) => {
  const payload = {
    success: true,
    message,
  };

  if (data !== null && data !== undefined) {
    payload.data = data;
  }
  // I dont want to include data field when data is null or undefined
  return res.status(statusCode).json(payload);
};

const errorResponse = (res, statusCode, message, errors = []) => {
  const response = {
    success: false,
    message,
  };

  if (errors.length > 0) {
    response.errors = errors.map((err) => ({
      field: err.field || err.path || null,
      message: err.message || err.msg,
    }));
  }

  return res.status(statusCode).json(response);
};

module.exports = {
  successResponse,
  errorResponse,
};
