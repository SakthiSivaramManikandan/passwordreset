/**
 * Token utility functions for generating and verifying reset tokens
 */

const crypto = require("crypto");

/**
 * Generate a random reset token
 * @returns {string} - Plain text token (40 characters)
 */
const generateResetToken = () => {
  return crypto.randomBytes(20).toString("hex");
};

/**
 * Hash the reset token for storage in database
 * @param {string} token - Plain text token
 * @returns {string} - Hashed token
 */
const hashToken = (token) => {
  return crypto.createHash("sha256").update(token).digest("hex");
};

/**
 * Generate OTP (One-Time Password)
 * @param {number} length - Length of OTP (default 6)
 * @returns {string} - Numeric OTP
 */
const generateOTP = (length = 6) => {
  let otp = "";
  for (let i = 0; i < length; i++) {
    otp += Math.floor(Math.random() * 10);
  }
  return otp;
};

/**
 * Check if token/OTP has expired
 * @param {date} expiryTime - Expiry timestamp
 * @returns {boolean} - true if expired, false if valid
 */
const isExpired = (expiryTime) => {
  return new Date() > new Date(expiryTime);
};

/**
 * Format time remaining until expiry (for user-friendly messages)
 * @param {date} expiryTime - Expiry timestamp
 * @returns {string} - Formatted time remaining
 */
const getTimeRemaining = (expiryTime) => {
  const now = new Date();
  const remaining = expiryTime - now;

  if (remaining <= 0) return "Expired";

  const minutes = Math.floor(remaining / 60000);
  const seconds = Math.floor((remaining % 60000) / 1000);

  if (minutes > 0) {
    return `${minutes}m ${seconds}s`;
  }
  return `${seconds}s`;
};

module.exports = {
  generateResetToken,
  hashToken,
  generateOTP,
  isExpired,
  getTimeRemaining,
};
