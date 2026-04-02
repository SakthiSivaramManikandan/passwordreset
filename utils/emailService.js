/**
 * Email service for sending password reset emails using Nodemailer
 */

const nodemailer = require("nodemailer");
const auditLogger = require("./auditLogger");

// Configure transporter based on environment
const transporter = nodemailer.createTransport({
  service: process.env.EMAIL_SERVICE || "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD,
  },
});

/**
 * Send password reset email
 * @param {string} email - Recipient email address
 * @param {string} resetToken - Reset token to include in link
 * @param {string} userName - User's name (optional)
 * @param {object} req - Express request object for IP logging
 * @returns {Promise<boolean>} - true if sent successfully
 */
const sendPasswordResetEmail = async (email, resetToken, userName = "", req) => {
  try {
    const resetLink = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;

    const mailOptions = {
      from: process.env.EMAIL_FROM || process.env.EMAIL_USER,
      to: email,
      subject: "Password Reset Request - Expires in 1 hour",
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <div style="background-color: #f8f9fa; padding: 20px; border-radius: 5px;">
            <h2 style="color: #333;">Password Reset Request</h2>
            
            <p style="color: #666; font-size: 16px;">
              Hello${userName ? " " + userName : ""},
            </p>
            
            <p style="color: #666; font-size: 16px;">
              We received a request to reset your password. Click the link below to proceed:
            </p>
            
            <div style="text-align: center; margin: 30px 0;">
              <a href="${resetLink}" 
                 style="background-color: #007bff; color: white; padding: 12px 30px; 
                        text-decoration: none; border-radius: 5px; font-size: 16px; 
                        display: inline-block;">
                Reset Password
              </a>
            </div>
            
            <p style="color: #999; font-size: 14px;">
              Or copy and paste this link in your browser:<br>
              <code style="background-color: #e9ecef; padding: 10px; display: block; 
                           word-break: break-all; margin: 10px 0;">
                ${resetLink}
              </code>
            </p>
            
            <div style="background-color: #fff3cd; border: 1px solid #ffc107; 
                        padding: 15px; border-radius: 5px; margin: 20px 0;">
              <p style="color: #856404; margin: 0; font-size: 14px;">
                <strong>⏰ Important:</strong> This link will expire in 1 hour for security reasons.
              </p>
            </div>
            
            <p style="color: #666; font-size: 14px;">
              If you didn't request a password reset, please ignore this email and your password will remain unchanged.
            </p>
            
            <hr style="border: none; border-top: 1px solid #ddd; margin: 20px 0;">
            
            <p style="color: #999; font-size: 12px; text-align: center;">
              This is an automated email, please do not reply directly.
            </p>
          </div>
        </div>
      `,
    };

    await transporter.sendMail(mailOptions);
    
    // Log successful email send
    if (req) {
      auditLogger.log(
        "PASSWORD_RESET_EMAIL_SENT",
        email,
        { email },
        req
      );
    }

    return true;
  } catch (error) {
    console.error("Email sending failed:", error);
    
    // Log failed email attempt
    if (req) {
      auditLogger.log(
        "PASSWORD_RESET_EMAIL_FAILED",
        email,
        { email, error: error.message },
        req
      );
    }

    throw new Error("Failed to send password reset email");
  }
};

/**
 * Send OTP via email
 * @param {string} email - Recipient email address
 * @param {string} otp - One-Time Password
 * @param {string} userName - User's name (optional)
 * @param {object} req - Express request object for IP logging
 * @returns {Promise<boolean>} - true if sent successfully
 */
const sendOTPEmail = async (email, otp, userName = "", req) => {
  try {
    const mailOptions = {
      from: process.env.EMAIL_FROM || process.env.EMAIL_USER,
      to: email,
      subject: "Your Password Reset OTP - Expires in 10 minutes",
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <div style="background-color: #f8f9fa; padding: 20px; border-radius: 5px;">
            <h2 style="color: #333;">Password Reset OTP</h2>
            
            <p style="color: #666; font-size: 16px;">
              Hello${userName ? " " + userName : ""},
            </p>
            
            <p style="color: #666; font-size: 16px;">
              Your one-time password (OTP) for password reset is:
            </p>
            
            <div style="text-align: center; margin: 30px 0;">
              <div style="background-color: #007bff; color: white; padding: 20px; 
                          border-radius: 5px; font-size: 32px; font-weight: bold; 
                          letter-spacing: 10px;">
                ${otp}
              </div>
            </div>
            
            <div style="background-color: #fff3cd; border: 1px solid #ffc107; 
                        padding: 15px; border-radius: 5px; margin: 20px 0;">
              <p style="color: #856404; margin: 0; font-size: 14px;">
                <strong>⏰ Important:</strong> This OTP will expire in 10 minutes.
              </p>
            </div>
            
            <p style="color: #666; font-size: 14px;">
              If you didn't request a password reset, please ignore this email.
            </p>
            
            <hr style="border: none; border-top: 1px solid #ddd; margin: 20px 0;">
            
            <p style="color: #999; font-size: 12px; text-align: center;">
              This is an automated email, please do not reply directly.
            </p>
          </div>
        </div>
      `,
    };

    await transporter.sendMail(mailOptions);
    
    if (req) {
      auditLogger.log(
        "OTP_EMAIL_SENT",
        email,
        { email },
        req
      );
    }

    return true;
  } catch (error) {
    console.error("OTP email sending failed:", error);
    
    if (req) {
      auditLogger.log(
        "OTP_EMAIL_FAILED",
        email,
        { email, error: error.message },
        req
      );
    }

    throw new Error("Failed to send OTP email");
  }
};

module.exports = {
  sendPasswordResetEmail,
  sendOTPEmail,
};
