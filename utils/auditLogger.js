/**
 * Audit logger for tracking login attempts, password changes, and security events
 */

const fs = require("fs");
const path = require("path");

const LOG_DIR = process.env.LOG_DIR || "./logs";

// Ensure logs directory exists
if (!fs.existsSync(LOG_DIR)) {
  fs.mkdirSync(LOG_DIR, { recursive: true });
}

/**
 * Get client IP address from request
 * @param {object} req - Express request object
 * @returns {string} - IP address
 */
const getClientIP = (req) => {
  return (
    req.headers["x-forwarded-for"]?.split(",")[0] ||
    req.headers["x-real-ip"] ||
    req.socket?.remoteAddress ||
    "Unknown"
  );
};

/**
 * Mask sensitive data in logs
 * @param {object} data - Object to mask
 * @returns {object} - Masked object
 */
const maskSensitiveData = (data) => {
  const masked = { ...data };

  const sensitiveFields = ["password", "token", "otp", "resetToken"];
  sensitiveFields.forEach((field) => {
    if (masked[field]) {
      masked[field] = "***MASKED***";
    }
  });

  return masked;
};

/**
 * Log security event
 * @param {string} action - Action type (e.g., PASSWORD_RESET_REQUESTED)
 * @param {string} userId - User ID or email
 * @param {object} details - Additional details
 * @param {object} req - Express request object (optional)
 */
const log = (action, userId, details = {}, req = null) => {
  const timestamp = new Date().toISOString();
  const ipAddress = req ? getClientIP(req) : "Unknown";
  const userAgent = req?.get("user-agent") || "Unknown";

  const logEntry = {
    timestamp,
    action,
    userId,
    ipAddress,
    userAgent,
    details: maskSensitiveData(details),
  };

  // Print to console in development
  if (process.env.NODE_ENV !== "production") {
    console.log(`[${action}] User: ${userId} | IP: ${ipAddress}`);
  }

  // Write to file
  const logFile = path.join(LOG_DIR, `${action}.log`);
  fs.appendFileSync(logFile, JSON.stringify(logEntry) + "\n", "utf-8");

  // Also write to combined audit log
  const auditFile = path.join(LOG_DIR, "audit.log");
  fs.appendFileSync(auditFile, JSON.stringify(logEntry) + "\n", "utf-8");
};

/**
 * Log error during password reset process
 * @param {string} errorType - Type of error
 * @param {string} userId - User ID or email
 * @param {object} error - Error object
 * @param {object} req - Express request object (optional)
 */
const logError = (errorType, userId, error, req = null) => {
  log(
    `ERROR_${errorType}`,
    userId,
    {
      message: error.message,
      stack: process.env.NODE_ENV === "development" ? error.stack : undefined,
    },
    req
  );
};

/**
 * Get recent logs for a specific action
 * @param {string} action - Action type to filter
 * @param {number} lines - Number of recent lines to retrieve
 * @returns {array} - Array of log entries
 */
const getRecentLogs = (action, lines = 10) => {
  const logFile = path.join(LOG_DIR, `${action}.log`);

  if (!fs.existsSync(logFile)) {
    return [];
  }

  const content = fs.readFileSync(logFile, "utf-8");
  return content
    .split("\n")
    .filter((line) => line.trim())
    .slice(-lines)
    .map((line) => {
      try {
        return JSON.parse(line);
      } catch {
        return null;
      }
    })
    .filter(Boolean);
};

module.exports = {
  log,
  logError,
  getRecentLogs,
  getClientIP,
};
