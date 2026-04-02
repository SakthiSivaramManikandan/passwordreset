/**
 * User model for MongoDB
 * Handles user authentication, password reset, and account lockout
 */

const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const { hashToken } = require("../utils/tokenUtils");

const userSchema = new mongoose.Schema(
  {
    // Basic information
    email: {
      type: String,
      required: [true, "Email is required"],
      unique: true,
      lowercase: true,
      match: [
        /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/,
        "Please provide a valid email address",
      ],
    },
    firstName: {
      type: String,
      default: "",
    },
    lastName: {
      type: String,
      default: "",
    },

    // Password management
    password: {
      type: String,
      required: [true, "Password is required"],
      minlength: 8,
      select: false, // Don't return password by default in queries
    },
    passwordHistory: [
      {
        hash: String,
        changedAt: Date,
      },
    ], // Store last 3 password hashes to prevent reuse

    // Password reset
    resetToken: String, // Hashed reset token
    resetTokenExpiry: Date,
    resetAttempts: {
      type: Number,
      default: 0,
    },
    lastResetAttempt: Date,

    // OTP for alternative reset method
    otp: String,
    otpExpiry: Date,
    otpAttempts: {
      type: Number,
      default: 0,
    },

    // Account lockout (security feature)
    locked: {
      type: Boolean,
      default: false,
    },
    lockUntil: Date, // Timestamp when account will auto-unlock
    lockReason: String, // Reason for lock (e.g., "max_reset_attempts")

    // Last password change
    lastPasswordChange: {
      type: Date,
      default: Date.now,
    },

    // Account status
    isActive: {
      type: Boolean,
      default: true,
    },
    emailVerified: {
      type: Boolean,
      default: false,
    },

    // Metadata
    createdAt: {
      type: Date,
      default: Date.now,
    },
    updatedAt: {
      type: Date,
      default: Date.now,
    },
  },
  {
    timestamps: true,
  }
);

/**
 * Hash password before saving (only if modified)
 */
userSchema.pre("save", async function (next) {
  // Only hash the password if it has been modified (or is new)
  if (!this.isModified("password")) return next();

  try {
    // Generate salt and hash password
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);

    // Maintain password history (keep last 3)
    if (!this.passwordHistory) {
      this.passwordHistory = [];
    }
    this.passwordHistory.push({
      hash: this.password,
      changedAt: new Date(),
    });
    if (this.passwordHistory.length > 3) {
      this.passwordHistory = this.passwordHistory.slice(-3);
    }

    // Update last password change timestamp
    this.lastPasswordChange = new Date();

    next();
  } catch (error) {
    next(error);
  }
});

/**
 * Compare provided password with stored hash
 * @param {string} enteredPassword - Password to verify
 * @returns {Promise<boolean>} - true if password matches
 */
userSchema.methods.comparePassword = async function (enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

/**
 * Check if password was used before (prevent reuse)
 * @param {string} newPassword - New password to check
 * @returns {Promise<boolean>} - true if password was used before
 */
userSchema.methods.wasPasswordUsedBefore = async function (newPassword) {
  if (!this.passwordHistory || this.passwordHistory.length === 0) {
    return false;
  }

  for (const oldPassword of this.passwordHistory) {
    const isMatch = await bcrypt.compare(newPassword, oldPassword.hash);
    if (isMatch) {
      return true;
    }
  }

  return false;
};

/**
 * Set password reset token
 * @param {string} token - Plain text token
 * @returns {string} - Hashed token
 */
userSchema.methods.setResetToken = function (token) {
  // Hash token and set expiry (1 hour by default)
  this.resetToken = hashToken(token);
  this.resetTokenExpiry = new Date(Date.now() + parseInt(process.env.RESET_TOKEN_EXPIRY || 3600000));
  return token; // Return plain token to send in email
};

/**
 * Clear reset token after successful password change
 */
userSchema.methods.clearResetToken = function () {
  this.resetToken = undefined;
  this.resetTokenExpiry = undefined;
  this.resetAttempts = 0;
  this.lastResetAttempt = undefined;
};

/**
 * Check if reset token has expired
 * @returns {boolean} - true if expired
 */
userSchema.methods.isResetTokenExpired = function () {
  if (!this.resetTokenExpiry) return true;
  return new Date() > this.resetTokenExpiry;
};

/**
 * Set OTP for alternative reset method
 * @param {string} otp - One-Time Password
 */
userSchema.methods.setOTP = function (otp) {
  this.otp = otp;
  this.otpExpiry = new Date(Date.now() + parseInt(process.env.OTP_EXPIRY || 600000)); // 10 minutes
  this.otpAttempts = 0;
};

/**
 * Clear OTP
 */
userSchema.methods.clearOTP = function () {
  this.otp = undefined;
  this.otpExpiry = undefined;
  this.otpAttempts = 0;
};

/**
 * Check if OTP has expired
 * @returns {boolean} - true if expired
 */
userSchema.methods.isOTPExpired = function () {
  if (!this.otpExpiry) return true;
  return new Date() > this.otpExpiry;
};

/**
 * Increment reset attempts and check for lockout
 * @returns {boolean} - true if account should be locked
 */
userSchema.methods.incrementResetAttempts = function () {
  const now = new Date();
  const maxAttempts = parseInt(process.env.MAX_RESET_ATTEMPTS || 5);
  const attemptWindow = parseInt(process.env.RESET_ATTEMPT_WINDOW || 900000); // 15 minutes

  // Reset attempts if window has passed
  if (
    !this.lastResetAttempt ||
    now - this.lastResetAttempt > attemptWindow
  ) {
    this.resetAttempts = 1;
    this.lastResetAttempt = now;
    return false; // No lockout needed
  }

  // Increment attempts
  this.resetAttempts += 1;
  this.lastResetAttempt = now;

  // Check if should lock account
  if (this.resetAttempts >= maxAttempts) {
    this.locked = true;
    this.lockReason = "max_reset_attempts";
    this.lockUntil = new Date(Date.now() + parseInt(process.env.ACCOUNT_LOCKOUT_TIME || 1800000)); // 30 minutes
    return true;
  }

  return false;
};

/**
 * Check if account is locked and auto-unlock if time has passed
 * @returns {boolean} - true if account is currently locked
 */
userSchema.methods.isAccountLocked = function () {
  if (!this.locked) return false;

  // Auto-unlock if lock duration has passed
  if (this.lockUntil && new Date() > this.lockUntil) {
    this.locked = false;
    this.lockUntil = undefined;
    this.lockReason = undefined;
    this.resetAttempts = 0;
    return false;
  }

  return this.locked;
};

/**
 * Unlock account
 */
userSchema.methods.unlockAccount = function () {
  this.locked = false;
  this.lockUntil = undefined;
  this.lockReason = undefined;
  this.resetAttempts = 0;
  this.lastResetAttempt = undefined;
};

/**
 * Get user info without sensitive data
 * @returns {object} - User info
 */
userSchema.methods.getPublicProfile = function () {
  return {
    id: this._id,
    email: this.email,
    firstName: this.firstName,
    lastName: this.lastName,
    isActive: this.isActive,
    emailVerified: this.emailVerified,
    createdAt: this.createdAt,
  };
};

module.exports = mongoose.model("User", userSchema);
