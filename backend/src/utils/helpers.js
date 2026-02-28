/**
 * Utility: Send a structured API success response.
 * @param {object} res   - Express response object
 * @param {any}    data  - Payload to send
 * @param {number} code  - HTTP status code (default 200)
 * @param {string} msg   - Optional message
 */
const sendSuccess = (res, data = {}, code = 200, msg = 'Success') => {
    res.status(code).json({ status: 'success', message: msg, data });
};

/**
 * Utility: Promisify SQLite db.get
 */
const dbGet = (db, sql, params = []) =>
    new Promise((resolve, reject) =>
        db.get(sql, params, (err, row) => (err ? reject(err) : resolve(row)))
    );

/**
 * Utility: Promisify SQLite db.all
 */
const dbAll = (db, sql, params = []) =>
    new Promise((resolve, reject) =>
        db.all(sql, params, (err, rows) => (err ? reject(err) : resolve(rows)))
    );

/**
 * Utility: Promisify SQLite db.run
 */
const dbRun = (db, sql, params = []) =>
    new Promise((resolve, reject) =>
        db.run(sql, params, function (err) {
            err ? reject(err) : resolve({ lastID: this.lastID, changes: this.changes });
        })
    );

module.exports = { sendSuccess, dbGet, dbAll, dbRun };
