
const successResponse = (res, data, message = 'Success', statusCode = 200) => {
    return res.status(statusCode).json({
        success: true,
        message,
        data
    });
};

const errorResponse = (res, statusCode, message, errors = []) => {
    const response = {
        success: false,
        message
    };

    if (errors.length > 0) {
        response.errors = errors.map(err => ({
            field: err.field || err.path || null,
            message: err.message || err.msg
        }));
    }

    return res.status(statusCode).json(response);
};

module.exports = {
    successResponse,
    errorResponse
};
