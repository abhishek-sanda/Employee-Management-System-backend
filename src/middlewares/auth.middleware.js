const jwt = require('jsonwebtoken');
const User = require('../models/user.model');
const logger = require('../utils/logger');

const JWT_SECRET = process.env.JWT_SECRET || 'secret';

exports.authenticate = async (req, res, next) => {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ success: false, message: 'Unauthorized' });

  const token = auth.split(' ')[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(payload.sub).select('-password');
    if (!user) return res.status(401).json({ success: false, message: 'Unauthorized' });
    req.user = user;

    // small server log to show who hit a protected route (id, email, role)
    logger.info('Authenticated request: userId=%s email=%s role=%s path=%s method=%s', user._id, user.email, user.role, req.path, req.method);

    next();
  } catch (err) {
    logger.warn('Auth failure: %o', err.message);
    return res.status(401).json({ success: false, message: 'Invalid token' });
  }
};

exports.authorize = (roles = []) => {
  if (typeof roles === 'string') roles = [roles];
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ success: false, message: 'Unauthorized' });
    if (roles.length && !roles.includes(req.user.role)) {
      logger.warn('Forbidden: user %s with role %s tried to access %s %s requiring roles %o', req.user._id, req.user.role, req.method, req.path, roles);
      return res.status(403).json({
        success: false,
        message: `Forbidden: requires one of roles [${roles.join(', ')}], your role: ${req.user.role}`
      });
    }
    next();
  };
};