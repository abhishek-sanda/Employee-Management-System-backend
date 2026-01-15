const mongoose = require('mongoose');

const RefreshTokenSchema = new mongoose.Schema(
  {
    jti: { type: String, required: true },
    tokenHash: { type: String, required: true },
    createdAt: { type: Date, default: Date.now },
    expiresAt: { type: Date, required: true }
  },
  { _id: false }
);

const UserSchema = new mongoose.Schema(
  {
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['admin', 'hr', 'manager', 'employee'], default: 'employee' },
    refreshTokens: { type: [RefreshTokenSchema], default: [] } // rotating refresh tokens (hashed)
  },
  { timestamps: true }
);

// Helper to remove a refresh token by jti
UserSchema.methods.removeRefreshTokenByJti = function (jti) {
  this.refreshTokens = this.refreshTokens.filter((rt) => rt.jti !== jti);
};

module.exports = mongoose.model('User', UserSchema);