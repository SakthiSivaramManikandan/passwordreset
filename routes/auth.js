/**
 * Password Reset Routes
 * API endpoints for password reset flow with email verification and OTP
 */

const express = require("express");
const router = express.Router();
const Joi = require("joi");
const User = require("../models/User");
const AuditLog = require("../models/AuditLog");
const {
  asyncHandler,
  validateBody,
  rateLimit,
  checkAccountLock,
  AppError,
} = require("../middleware/auth");
const { sendPasswordResetEmail, sendOTPEmail } = require("../utils/emailService");
const { generateResetToken, hashToken, generateOTP, isExpired } = require("../utils/tokenUtils");
const { validatePasswordStrength } = require("../utils/passwordUtils");
const auditLogger = require("../utils/auditLogger");

// ============================================================================
// 0. USER REGISTRATION
// ============================================================================

/**
 * POST /api/auth/register
 * Create a new user account
 */
router.post(
  "/register",
  rateLimit({ windowMs: 15 * 60 * 1000, maxRequests: 50 }),
  validateBody(
    Joi.object({
      email: Joi.string()
        .email()
        .required()
        .messages({
          "string.email": "Please provide a valid email address",
          "any.required": "Email is required",
        }),
      firstName: Joi.string().max(50).default(""),
      lastName: Joi.string().max(50).default(""),
      password: Joi.string()
        .min(8)
        .required()
        .messages({
          "string.min": "Password must be at least 8 characters",
          "any.required": "Password is required",
        }),
    })
  ),
  asyncHandler(async (req, res) => {
    const { email, firstName, lastName, password } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ email: email.toLowerCase() });

    if (existingUser) {
      auditLogger.log(
        "REGISTRATION_FAILED",
        email,
        { reason: "email_already_exists" },
        req
      );

      return res.status(400).json({
        success: false,
        message: "Email already registered. Please login or use forgot password.",
      });
    }

    // Validate password strength
    const passwordValidation = validatePasswordStrength(password);
    if (!passwordValidation.isValid) {
      auditLogger.log(
        "REGISTRATION_FAILED",
        email,
        { reason: "weak_password", errors: passwordValidation.errors },
        req
      );

      return res.status(400).json({
        success: false,
        message: "Password does not meet complexity requirements",
        errors: passwordValidation.errors,
      });
    }

    try {
      // Create new user
      const newUser = new User({
        email: email.toLowerCase(),
        firstName: firstName || "",
        lastName: lastName || "",
        password: password, // Will be hashed by pre-hook
      });

      // Save user to database
      await newUser.save();

      // Log successful registration
      auditLogger.log(
        "USER_REGISTERED",
        email,
        { firstName, lastName },
        req
      );

      // Registration should still succeed even if audit persistence has an issue.
      try {
        await AuditLog.create({
          userId: email,
          action: "USER_REGISTERED",
          ipAddress: auditLogger.getClientIP(req),
          userAgent: req.get("user-agent"),
          details: { firstName, lastName },
        });
      } catch (auditError) {
        auditLogger.logError(
          "DATABASE",
          email,
          auditError,
          req
        );
      }

      res.status(201).json({
        success: true,
        message: "Account created successfully! You can now login.",
      });
    } catch (error) {
      auditLogger.logError(
        "REGISTRATION_ERROR",
        email,
        error,
        req
      );

      res.status(500).json({
        success: false,
        message: "Failed to create account. Please try again later.",
      });
    }
  })
);

// ============================================================================
// 1. REQUEST PASSWORD RESET LINK
// ============================================================================

/**
 * POST /api/auth/forgot-password
 * User enters email and receives a password reset link
 * Validation: rate-limited to prevent abuse
 */
router.post(
  "/forgot-password",
  rateLimit({ windowMs: 15 * 60 * 1000, maxRequests: 20 }),
  validateBody(
    Joi.object({
      email: Joi.string()
        .email()
        .required()
        .messages({
          "string.email": "Please provide a valid email address",
          "any.required": "Email is required",
        }),
    })
  ),
  asyncHandler(async (req, res) => {
    const { email } = req.body;

    // Check if user exists
    const user = await User.findOne({ email: email.toLowerCase() });

    if (!user) {
      // For security: don't reveal if email exists
      auditLogger.log(
        "PASSWORD_RESET_REQUESTED",
        email,
        { status: "user_not_found" },
        req
      );

      return res.status(200).json({
        success: true,
        message: "If this email exists, you will receive a password reset link",
      });
    }

    // Check if account is locked
    if (user.isAccountLocked()) {
      auditLogger.log(
        "PASSWORD_RESET_REQUESTED",
        email,
        { status: "account_locked" },
        req
      );

      const timeRemaining = Math.ceil((user.lockUntil - Date.now()) / 1000 / 60);
      return res.status(423).json({
        success: false,
        message: `Account is temporarily locked. Try again in ${timeRemaining} minutes`,
        lockUntil: user.lockUntil,
      });
    }

    try {
      // Generate reset token
      const plainToken = generateResetToken();
      user.setResetToken(plainToken);

      // Log the reset request
      auditLogger.log(
        "PASSWORD_RESET_REQUESTED",
        email,
        { method: "email_link" },
        req
      );

      // Send email with reset link
      await sendPasswordResetEmail(
        user.email,
        plainToken,
        user.firstName,
        req
      );

      // Save user with reset token
      await user.save();

      res.status(200).json({
        success: true,
        message:
          "Password reset link has been sent to your email. It will expire in 1 hour.",
      });
    } catch (error) {
      // Increment reset attempts on error
      user.incrementResetAttempts();
      await user.save();

      auditLogger.logError(
        "PASSWORD_RESET_EMAIL",
        email,
        error,
        req
      );

      res.status(500).json({
        success: false,
        message: "Failed to send password reset email. Please try again later.",
      });
    }
  })
);

// ============================================================================
// 2. VERIFY RESET TOKEN
// ============================================================================

/**
 * POST /api/auth/verify-token
 * Frontend calls this to verify token validity before showing reset form
 */
router.post(
  "/verify-token",
  validateBody(
    Joi.object({
      token: Joi.string().required().messages({
        "any.required": "Token is required",
      }),
    })
  ),
  asyncHandler(async (req, res) => {
    const { token } = req.body;

    if (!token || token.length < 20) {
      return res.status(400).json({
        success: false,
        message: "Invalid token format",
      });
    }

    // Hash the token to compare with database
    const hashedToken = hashToken(token);

    // Find user with this token
    const user = await User.findOne({
      resetToken: hashedToken,
    });

    if (!user) {
      auditLogger.log(
        "RESET_TOKEN_INVALID",
        "unknown",
        { token: token.substring(0, 5) + "..." },
        req
      );

      return res.status(400).json({
        success: false,
        message: "Invalid reset token",
      });
    }

    // Check if token has expired
    if (user.isResetTokenExpired()) {
      auditLogger.log(
        "RESET_TOKEN_EXPIRED",
        user.email,
        { token: token.substring(0, 5) + "..." },
        req
      );

      return res.status(400).json({
        success: false,
        message: "Reset link has expired. Please request a new one.",
        expired: true,
      });
    }

    // Token is valid
    auditLogger.log(
      "RESET_TOKEN_VERIFIED",
      user.email,
      {},
      req
    );

    res.status(200).json({
      success: true,
      message: "Token is valid",
      email: user.email, // Send back email for confirmation
    });
  })
);

// ============================================================================
// 2.5. VERIFY OLD PASSWORD (for password reset)
// ============================================================================

/**
 * POST /api/auth/verify-old-password
 * Verify that the old password is correct before allowing reset
 */
router.post(
  "/verify-old-password",
  validateBody(
    Joi.object({
      token: Joi.string().required().messages({
        "any.required": "Token is required",
      }),
      oldPassword: Joi.string().required().messages({
        "any.required": "Old password is required",
      }),
    })
  ),
  asyncHandler(async (req, res) => {
    const { token, oldPassword } = req.body;

    if (!token || token.length < 20) {
      return res.status(400).json({
        success: false,
        message: "Invalid token format",
      });
    }

    // Hash the token to compare with database
    const hashedToken = hashToken(token);

    // Find user with this token
    const user = await User.findOne({
      resetToken: hashedToken,
    }).select("+password");

    if (!user) {
      auditLogger.log(
        "OLD_PASSWORD_VERIFICATION_FAILED",
        "unknown",
        { reason: "invalid_token" },
        req
      );

      return res.status(400).json({
        success: false,
        message: "Invalid reset token",
      });
    }

    // Check if token has expired
    if (user.isResetTokenExpired()) {
      auditLogger.log(
        "OLD_PASSWORD_VERIFICATION_FAILED",
        user.email,
        { reason: "token_expired" },
        req
      );

      return res.status(400).json({
        success: false,
        message: "Reset link has expired. Please request a new one.",
        expired: true,
      });
    }

    // Verify the old password
    const isPasswordCorrect = await user.comparePassword(oldPassword);

    if (!isPasswordCorrect) {
      auditLogger.log(
        "OLD_PASSWORD_VERIFICATION_FAILED",
        user.email,
        { reason: "incorrect_password" },
        req
      );

      return res.status(400).json({
        success: false,
        message: "Old password is incorrect. Please try again.",
      });
    }

    // Old password is correct
    auditLogger.log(
      "OLD_PASSWORD_VERIFIED",
      user.email,
      {},
      req
    );

    res.status(200).json({
      success: true,
      message: "Old password verified. You can now set a new password.",
      email: user.email,
    });
  })
);



/**
 * POST /api/auth/reset-password
 * User submits new password with valid reset token
 */
router.post(
  "/reset-password",
  validateBody(
    Joi.object({
      token: Joi.string().required(),
      newPassword: Joi.string().min(8).required().messages({
        "string.min": "Password must be at least 8 characters long",
        "any.required": "New password is required",
      }),
      confirmPassword: Joi.string()
        .valid(Joi.ref("newPassword"))
        .required()
        .messages({
          "any.only": "Passwords do not match",
          "any.required": "Password confirmation is required",
        }),
    })
  ),
  asyncHandler(async (req, res) => {
    const { token, newPassword } = req.body;

    // Hash the token
    const hashedToken = hashToken(token);

    // Find user with this token
    const user = await User.findOne({
      resetToken: hashedToken,
    });

    if (!user) {
      auditLogger.log(
        "RESET_TOKEN_INVALID",
        "unknown",
        { action: "password_reset" },
        req
      );

      return res.status(400).json({
        success: false,
        message: "Invalid reset token",
      });
    }

    // Check if token has expired
    if (user.isResetTokenExpired()) {
      auditLogger.log(
        "RESET_TOKEN_EXPIRED",
        user.email,
        { action: "password_reset" },
        req
      );

      return res.status(400).json({
        success: false,
        message: "Reset link has expired. Please request a new one.",
        expired: true,
      });
    }

    // Validate password strength
    const passwordValidation = validatePasswordStrength(newPassword);
    if (!passwordValidation.isValid) {
      auditLogger.log(
        "ERROR_VALIDATION",
        user.email,
        { action: "weak_password", errors: passwordValidation.errors },
        req
      );

      return res.status(400).json({
        success: false,
        message: "Password does not meet complexity requirements",
        errors: passwordValidation.errors,
      });
    }

    // Check if password was used before
    const wasUsedBefore = await user.wasPasswordUsedBefore(newPassword);
    if (wasUsedBefore) {
      auditLogger.log(
        "ERROR_VALIDATION",
        user.email,
        { action: "password_reuse" },
        req
      );

      return res.status(400).json({
        success: false,
        message: "Cannot reuse a previous password. Please choose a different one.",
      });
    }

    try {
      // Update password
      user.password = newPassword;
      user.clearResetToken();

      // Save user
      await user.save();

      // Log successful password change
      auditLogger.log(
        "PASSWORD_CHANGED",
        user.email,
        { method: "reset_link" },
        req
      );

      // Also create audit log entry
      await AuditLog.create({
        userId: user.email,
        action: "PASSWORD_CHANGED",
        ipAddress: auditLogger.getClientIP(req),
        userAgent: req.get("user-agent"),
        details: { method: "reset_link" },
      });

      res.status(200).json({
        success: true,
        message: "Password has been reset successfully. You can now login with your new password.",
      });
    } catch (error) {
      auditLogger.logError(
        "PASSWORD_RESET",
        user.email,
        error,
        req
      );

      res.status(500).json({
        success: false,
        message: "Failed to reset password. Please try again later.",
      });
    }
  })
);

// ============================================================================
// 4. REQUEST OTP (Alternative Method)
// ============================================================================

/**
 * POST /api/auth/request-otp
 * User can request OTP instead of reset link
 */
router.post(
  "/request-otp",
  rateLimit({ windowMs: 15 * 60 * 1000, maxRequests: 20 }),
  validateBody(
    Joi.object({
      email: Joi.string()
        .email()
        .required()
        .messages({
          "string.email": "Please provide a valid email address",
          "any.required": "Email is required",
        }),
    })
  ),
  asyncHandler(async (req, res) => {
    const { email } = req.body;

    // Find user
    const user = await User.findOne({ email: email.toLowerCase() });

    if (!user) {
      auditLogger.log(
        "OTP_REQUESTED",
        email,
        { status: "user_not_found" },
        req
      );

      return res.status(200).json({
        success: true,
        message: "If this email exists, you will receive an OTP",
      });
    }

    // Check if account is locked
    if (user.isAccountLocked()) {
      const timeRemaining = Math.ceil((user.lockUntil - Date.now()) / 1000 / 60);
      return res.status(423).json({
        success: false,
        message: `Account is temporarily locked. Try again in ${timeRemaining} minutes`,
      });
    }

    try {
      // Generate OTP
      const otp = generateOTP(6);
      user.setOTP(otp);

      // Log OTP request
      auditLogger.log(
        "OTP_REQUESTED",
        email,
        {},
        req
      );

      // Send OTP email
      await sendOTPEmail(user.email, otp, user.firstName, req);

      // Save user with OTP
      await user.save();

      res.status(200).json({
        success: true,
        message: "OTP has been sent to your email. It will expire in 10 minutes.",
      });
    } catch (error) {
      user.incrementResetAttempts();
      await user.save();

      auditLogger.logError(
        "OTP_EMAIL",
        email,
        error,
        req
      );

      res.status(500).json({
        success: false,
        message: "Failed to send OTP. Please try again later.",
      });
    }
  })
);

// ============================================================================
// 5. VERIFY OTP
// ============================================================================

/**
 * POST /api/auth/verify-otp
 * User submits OTP and new password
 */
router.post(
  "/verify-otp",
  validateBody(
    Joi.object({
      email: Joi.string().email().required(),
      otp: Joi.string().length(6).required().messages({
        "string.length": "OTP must be 6 digits",
        "any.required": "OTP is required",
      }),
      newPassword: Joi.string().min(8).required(),
      confirmPassword: Joi.string()
        .valid(Joi.ref("newPassword"))
        .required()
        .messages({
          "any.only": "Passwords do not match",
        }),
    })
  ),
  asyncHandler(async (req, res) => {
    const { email, otp, newPassword } = req.body;

    // Find user
    const user = await User.findOne({ email: email.toLowerCase() });

    if (!user) {
      return res.status(400).json({
        success: false,
        message: "User not found",
      });
    }

    // Check if OTP exists
    if (!user.otp) {
      auditLogger.log(
        "OTP_INVALID",
        email,
        { status: "no_otp_requested" },
        req
      );

      return res.status(400).json({
        success: false,
        message: "No OTP was requested for this account",
      });
    }

    // Check if OTP has expired
    if (user.isOTPExpired()) {
      auditLogger.log(
        "OTP_EXPIRED",
        email,
        {},
        req
      );

      return res.status(400).json({
        success: false,
        message: "OTP has expired. Please request a new one.",
        expired: true,
      });
    }

    // Verify OTP
    if (user.otp !== otp) {
      user.otpAttempts += 1;

      // Lock account after too many failed attempts
      if (user.otpAttempts >= 3) {
        user.incrementResetAttempts();
      }

      await user.save();

      auditLogger.log(
        "OTP_INVALID",
        email,
        { attempts: user.otpAttempts },
        req
      );

      return res.status(400).json({
        success: false,
        message: "Invalid OTP",
      });
    }

    // Validate password strength
    const passwordValidation = validatePasswordStrength(newPassword);
    if (!passwordValidation.isValid) {
      return res.status(400).json({
        success: false,
        message: "Password does not meet complexity requirements",
        errors: passwordValidation.errors,
      });
    }

    // Check if password was used before
    const wasUsedBefore = await user.wasPasswordUsedBefore(newPassword);
    if (wasUsedBefore) {
      return res.status(400).json({
        success: false,
        message: "Cannot reuse a previous password",
      });
    }

    try {
      // Update password
      user.password = newPassword;
      user.clearOTP();
      user.clearResetToken();

      // Save user
      await user.save();

      // Log password change
      auditLogger.log(
        "PASSWORD_CHANGED",
        user.email,
        { method: "otp" },
        req
      );

      await AuditLog.create({
        userId: user.email,
        action: "PASSWORD_CHANGED",
        ipAddress: auditLogger.getClientIP(req),
        userAgent: req.get("user-agent"),
        details: { method: "otp" },
      });

      res.status(200).json({
        success: true,
        message: "Password has been reset successfully",
      });
    } catch (error) {
      auditLogger.logError(
        "OTP_PASSWORD_RESET",
        email,
        error,
        req
      );

      res.status(500).json({
        success: false,
        message: "Failed to reset password",
      });
    }
  })
);

module.exports = router;
