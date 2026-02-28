const AppError = require('./AppError');
const config = require('../config');

/**
 * Global Express error handler middleware.
 * Must be registered last in server.js (4-argument function).
 */
const errorHandler = (err, req, res, next) => {
    // Default to 500 if not set
    err.statusCode = err.statusCode || 500;

    const isDev = config.server.nodeEnv === 'development';

    if (err.isOperational) {
        // Known, safe error — send message to client
        return res.status(err.statusCode).json({
            status: 'error',
            message: err.message,
        });
    }

    // Unknown / programmer error — don't leak details in production
    console.error('[ERROR] 💥 Unhandled exception:', err);

    return res.status(500).json({
        status: 'error',
        message: isDev ? err.message : 'Something went wrong on our end.',
        ...(isDev && { stack: err.stack }),
    });
};

module.exports = errorHandler;
