/**
 * Custom Application Error
 * Carries an HTTP status code alongside the message.
 */
class AppError extends Error {
    constructor(message, statusCode = 500) {
        super(message);
        this.statusCode = statusCode;
        this.isOperational = true; // distinguishes expected errors from bugs
        Error.captureStackTrace(this, this.constructor);
    }
}

module.exports = AppError;
