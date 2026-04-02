/**
 * AuditLog model for MongoDB
 * Tracks all security-related events
 */

const mongoose = require("mongoose");

const auditLogSchema = new mongoose.Schema(
  {
    userId: {
      type: String, // Can be user ID or email
      required: true,
    },
    action: {
      type: String,
      required: true,
      enum: [
        "PASSWORD_RESET_REQUESTED",
        "PASSWORD_RESET_EMAIL_SENT",
        "PASSWORD_RESET_EMAIL_FAILED",
        "RESET_TOKEN_VERIFIED",
        "RESET_TOKEN_INVALID",
        "RESET_TOKEN_EXPIRED",
        "PASSWORD_CHANGED",
        "OTP_REQUESTED",
        "OTP_EMAIL_SENT",
        "OTP_EMAIL_FAILED",
        "OTP_VERIFIED",
        "OTP_INVALID",
        "OTP_EXPIRED",
        "ACCOUNT_LOCKED",
        "ACCOUNT_UNLOCKED",
        "LOGIN_SUCCESS",
        "LOGIN_FAILED",
        "ERROR_DATABASE",
        "ERROR_EMAIL_SERVICE",
        "ERROR_VALIDATION",
      ],
    },
    ipAddress: {
      type: String,
      default: "Unknown",
    },
    userAgent: {
      type: String,
    },
    details: {
      type: mongoose.Schema.Types.Mixed,
      default: {},
    },
    timestamp: {
      type: Date,
      default: Date.now,
      index: true, // Index for faster queries
    },
  },
  {
    timestamps: false,
  }
);

// Compound index for faster user activity queries
auditLogSchema.index({ userId: 1, timestamp: -1 });
auditLogSchema.index({ action: 1, timestamp: -1 });

module.exports = mongoose.model("AuditLog", auditLogSchema);
