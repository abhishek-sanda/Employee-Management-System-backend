const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const User = require('../models/user.model');
const logger = require('../utils/logger');
const {
  signAccessToken,
  signRefreshToken,
  hashToken,
  decodeToken,
  verifyToken,
  newJti,
  tokenExpiryDate
} = require('../utils/token.util');

const COOKIE_SECURE = process.env.COOKIE_SECURE === 'true';
const COOKIE_NAME = 'refreshToken';

// Helper to set refresh cookie
function setRefreshCookie(res, token, expiresAt) {
  const maxAge = expiresAt ? expiresAt.getTime() - Date.now() : undefined;
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    secure: COOKIE_SECURE,
    sameSite: 'lax',
    maxAge
  });
}

// Register (unchanged semantics)
exports.register = async (req, res) => {
  const { email, password } = req.body;
  // Force role = 'employee' for public sign-ups
  const role = 'employee';

  const exists = await User.findOne({ email });
  if (exists) return res.status(409).json({ success: false, message: 'Email already registered' });

  const hashed = await bcrypt.hash(password, 12);
  const user = await User.create({ email, password: hashed, role });
  res.status(201).json({ success: true, data: { id: user._id, email: user.email, role: user.role } });
};

/**
 * Admin-only user creation (allows specifying role)
 * - Use route protected by authenticate + authorize('admin')
 * - Does NOT create an Employee record
 */
exports.createUserByAdmin = async (req, res) => {
  const { email, password, role } = req.body;

  // role should be validated by the route / middleware; still guard here
  const allowedRoles = ['admin', 'hr', 'manager', 'employee'];
  const assignedRole = allowedRoles.includes(role) ? role : 'employee';

  const exists = await User.findOne({ email });
  if (exists) return res.status(409).json({ success: false, message: 'Email already registered' });

  const hashed = await bcrypt.hash(password, 12);
  const user = await User.create({ email, password: hashed, role: assignedRole });
  res.status(201).json({ success: true, data: { id: user._id, email: user.email, role: user.role } });
};

// Login: create access token and a refresh token entry (hashed)
exports.login = async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(401).json({ success: false, message: 'Invalid credentials' });

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(401).json({ success: false, message: 'Invalid credentials' });

  // create access token
  const accessToken = signAccessToken(user);

  // create refresh token with jti and store hashed
  const jti = newJti();
  const refreshToken = signRefreshToken(user._id, jti);
  const tokenHash = hashToken(refreshToken);
  const expiresAt = tokenExpiryDate(refreshToken);

  // persist refresh token in DB (rotate list)
  user.refreshTokens.push({ jti, tokenHash, expiresAt });
  await user.save();

  // set httpOnly cookie
  setRefreshCookie(res, refreshToken, expiresAt);

  res.json({
    success: true,
    data: { accessToken, user: { id: user._id, email: user.email, role: user.role } }
  });
};

// Refresh: rotate refresh token
exports.refresh = async (req, res) => {
  const token = req.cookies[COOKIE_NAME];
  if (!token) return res.status(401).json({ success: false, message: 'No refresh token' });

  // Try verify token first
  try {
    const payload = verifyToken(token); // throws if invalid/expired
    if (!payload || !payload.sub || !payload.jti) {
      return res.status(401).json({ success: false, message: 'Invalid refresh token' });
    }

    const user = await User.findById(payload.sub);
    if (!user) return res.status(401).json({ success: false, message: 'Invalid token subject' });

    const tokenHash = hashToken(token);
    const stored = user.refreshTokens.find((rt) => rt.jti === payload.jti && rt.tokenHash === tokenHash);

    // Token verified but not in DB -> reuse attempt
    if (!stored) {
      // clear all refresh tokens for this user (compromise)
      user.refreshTokens = [];
      await user.save();
      logger.warn('Refresh token reuse detected for user %s', user._id);
      return res.status(401).json({ success: false, message: 'Refresh token reuse detected. Re-authentication required.' });
    }

    // Valid and present: rotate -> remove old token record and insert new one
    user.refreshTokens = user.refreshTokens.filter((rt) => rt.jti !== payload.jti);

    const newJti = newJti();
    const newRefreshToken = signRefreshToken(user._id, newJti);
    const newHash = hashToken(newRefreshToken);
    const newExpiresAt = tokenExpiryDate(newRefreshToken);
    user.refreshTokens.push({ jti: newJti, tokenHash: newHash, expiresAt: newExpiresAt });

    await user.save();

    // issue new access token
    const accessToken = signAccessToken({ _id: user._id, role: user.role });

    // set cookie with rotated refresh token
    setRefreshCookie(res, newRefreshToken, newExpiresAt);

    return res.json({
      success: true,
      data: { accessToken, user: { id: user._id, email: user.email, role: user.role } }
    });
  } catch (err) {
    // If token expired or invalid signature, try to determine subject to clean up stored expired token if possible
    const decoded = decodeToken(token);
    if (decoded && decoded.sub && decoded.jti) {
      try {
        const user = await User.findById(decoded.sub);
        if (user) {
          // remove the expired token entry if it exists
          user.refreshTokens = user.refreshTokens.filter((rt) => rt.jti !== decoded.jti);
          await user.save();
        }
      } catch (e) {
        logger.error('Error cleaning expired refresh token entry: %o', e);
      }
    }
    // Return unauthorized for expired/invalid tokens
    return res.status(401).json({ success: false, message: 'Invalid or expired refresh token' });
  }
};

// Logout: remove the refresh token presented (so it cannot be reused)
exports.logout = async (req, res) => {
  const token = req.cookies[COOKIE_NAME];
  if (token) {
    const decoded = decodeToken(token);
    if (decoded && decoded.sub && decoded.jti) {
      try {
        const user = await User.findById(decoded.sub);
        if (user) {
          user.refreshTokens = user.refreshTokens.filter((rt) => rt.jti !== decoded.jti);
          await user.save();
        }
      } catch (err) {
        logger.error('Error removing refresh token on logout: %o', err);
      }
    }
  }
  res.clearCookie(COOKIE_NAME);
  res.json({ success: true });
};

// Revoke all refresh tokens for the calling user (optional)
exports.revokeAll = async (req, res) => {
  // This endpoint is unauthenticated in this file; ideally require authentication and roles
  // For now we expect a JSON body: { email } or use cookie subject. Implement basic protection: use cookie subject if present
  const token = req.cookies[COOKIE_NAME];
  if (token) {
    const decoded = decodeToken(token);
    if (decoded && decoded.sub) {
      const user = await User.findById(decoded.sub);
      if (user) {
        user.refreshTokens = [];
        await user.save();
        res.clearCookie(COOKIE_NAME);
        return res.json({ success: true });
      }
    }
  }
  // Fallback: require email body (admin action)
  const { email } = req.body || {};
  if (email) {
    const user = await User.findOne({ email });
    if (user) {
      user.refreshTokens = [];
      await user.save();
      return res.json({ success: true });
    }
  }
  return res.status(400).json({ success: false, message: 'Unable to determine user to revoke tokens' });
};