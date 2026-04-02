/**
 * Middleware for authentication, validation, and error handling
 */

const jwt = require("jsonwebtoken");
const User = require("../models/User");
const auditLogger = require("../utils/auditLogger");

/**
 * Error handling middleware
 */
class AppError extends Error {
  constructor(message, statusCode) {
    super(message);
    this.statusCode = statusCode;
  }
}

/**
 * Async handler to catch errors in route handlers
 */
const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

/**
 * Validate request body against schema
 */
const validateBody = (schema) => {
  return (req, res, next) => {
    const { error, value } = schema.validate(req.body, {
      abortEarly: false,
      stripUnknown: true,
    });

    if (error) {
      return res.status(400).json({
        success: false,
        errors: error.details.map((err) => ({
          field: err.path.join("."),
          message: err.message.replace(/"/g, ""),
        })),
      });
    }

    req.body = value;
    next();
  };
};

/**
 * Verify JWT token
 */
const verifyToken = asyncHandler(async (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({
      success: false,
      message: "No token provided",
    });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: "Invalid or expired token",
    });
  }
});

/**
 * Log security events
 */
const logSecurityEvent = (action) => {
  return (req, res, next) => {
    // Capture the original send method
    const originalSend = res.send;

    res.send = function (data) {
      // Only log after response is sent
      let userId = req.body?.email || req.userId || "unknown";

      if (res.statusCode >= 200 && res.statusCode < 300) {
        // Log successful actions
        auditLogger.log(action, userId, {}, req);
      }

      // Call the original send method
      return originalSend.call(this, data);
    };

    next();
  };
};

/**
 * Rate limiting middleware
 */
const rateLimit = (options = {}) => {
  const {
    windowMs = 15 * 60 * 1000, // 15 minutes
    maxRequests = 5,
    message = "Too many requests, please try again later",
  } = options;

  const requestCounts = new Map();

  return (req, res, next) => {
    const clientIP = auditLogger.getClientIP(req);
    const now = Date.now();

    if (!requestCounts.has(clientIP)) {
      requestCounts.set(clientIP, []);
    }

    const requests = requestCounts.get(clientIP);

    // Remove old requests outside the window
    const recentRequests = requests.filter((time) => now - time < windowMs);
    requestCounts.set(clientIP, recentRequests);

    if (recentRequests.length >= maxRequests) {
      return res.status(429).json({
        success: false,
        message,
      });
    }

    recentRequests.push(now);
    next();
  };
};

/**
 * Check if user account is locked
 */
const checkAccountLock = asyncHandler(async (req, res, next) => {
  const { email } = req.body;

  if (!email) {
    return next();
  }

  const user = await User.findOne({ email: email.toLowerCase() });

  if (user && user.isAccountLocked()) {
    const timeRemaining = Math.ceil(
      (user.lockUntil - Date.now()) / 1000 / 60
    );
    return res.status(423).json({
      success: false,
      message: `Account is locked due to ${user.lockReason}. Try again in ${timeRemaining} minutes`,
      lockUntil: user.lockUntil,
    });
  }

  next();
});

/**
 * Central error handler middleware (must be last)
 */
const errorHandler = (err, req, res, next) => {
  const statusCode = err.statusCode || 500;
  const isDevelopment = process.env.NODE_ENV === "development";

  // Log error
  auditLogger.logError("REQUEST", req.body?.email || "unknown", err, req);

  // Send error response
  res.status(statusCode).json({
    success: false,
    message: err.message || "Internal server error",
    ...(isDevelopment && { stack: err.stack }),
  });
};

module.exports = {
  AppError,
  asyncHandler,
  validateBody,
  verifyToken,
  logSecurityEvent,
  rateLimit,
  checkAccountLock,
  errorHandler,
};
