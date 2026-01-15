const logger = require('../utils/logger');

exports.errorHandler = (err, req, res, next) => {
  logger.error(err);
  const status = err.status || 500;
  const payload = {
    success: false,
    message: err.message || 'Internal Server Error'
  };
  if (process.env.NODE_ENV !== 'production') {
    payload.stack = err.stack;
  }
  res.status(status).json(payload);
};