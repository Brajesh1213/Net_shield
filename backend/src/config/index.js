require('dotenv').config();

const config = {
    server: {
        port: process.env.PORT || 5000,
        nodeEnv: process.env.NODE_ENV || 'development',
    },
    jwt: {
        secret: process.env.JWT_SECRET || 'asthak_dev_secret_change_in_prod',
        expiresIn: process.env.JWT_EXPIRES_IN || '24h',
    },
    db: {
        path: process.env.DB_PATH || './asthak.db',
    },
};

module.exports = config;
