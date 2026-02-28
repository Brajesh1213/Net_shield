const jwt = require('jsonwebtoken');
const config = require('../config');
const AppError = require('../errors/AppError');

/**
 * Middleware: Verify JWT from Authorization header.
 * Attaches decoded user payload to req.user.
 */
const protect = (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return next(new AppError('No token provided. Please log in.', 401));
    }

    const token = authHeader.split(' ')[1];

    try {
        const decoded = jwt.verify(token, config.jwt.secret);
        req.user = decoded; // { id, email, role }
        next();
    } catch (err) {
        return next(new AppError('Invalid or expired token. Please log in again.', 401));
    }
};

/**
 * Middleware: Restrict route to admin role only.
 * Must be used AFTER protect().
 */
const adminOnly = (req, res, next) => {
    if (req.user && req.user.role === 'admin') {
        return next();
    }
    return next(new AppError('Access denied. Admins only.', 403));
};

module.exports = { protect, adminOnly };
