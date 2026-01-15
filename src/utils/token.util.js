const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

const JWT_SECRET = process.env.JWT_SECRET || 'secret';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '15m';
const REFRESH_TOKEN_EXPIRES_IN = process.env.REFRESH_TOKEN_EXPIRES_IN || '7d';

// Sign access token (short lived)
function signAccessToken(user) {
  // accepts either user object or userId + role object
  const payload = {
    sub: typeof user === 'object' && user._id ? user._id.toString() : user.sub,
    role: user.role || ''
  };
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

// Sign refresh token with a jti (unique id)
function signRefreshToken(userId, jti) {
  const payload = {
    sub: userId.toString(),
    jti,
    type: 'refresh'
  };
  return jwt.sign(payload, JWT_SECRET, { expiresIn: REFRESH_TOKEN_EXPIRES_IN });
}

// Hash a token string for storage/comparison
function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

// Decode token payload without verifying signature
function decodeToken(token) {
  return jwt.decode(token);
}

// Verify token signature & expiration
function verifyToken(token) {
  return jwt.verify(token, JWT_SECRET);
}

// Generate a new UUID jti
function newJti() {
  return uuidv4();
}

// Compute expiry Date from a JWT string by decoding exp
function tokenExpiryDate(token) {
  const decoded = jwt.decode(token);
  if (!decoded || !decoded.exp) return null;
  return new Date(decoded.exp * 1000);
}

module.exports = {
  signAccessToken,
  signRefreshToken,
  hashToken,
  decodeToken,
  verifyToken,
  newJti,
  tokenExpiryDate
};