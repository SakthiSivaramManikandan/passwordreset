/**
 * Password utility functions for validation, hashing, and strength checking
 */

const SPECIAL_CHARS_REGEX = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/;

/**
 * Validate password strength according to OWASP standards
 * Requirements: min 8 chars, uppercase, lowercase, number, special character
 * @param {string} password - Password to validate
 * @returns {object} - { isValid: boolean, errors: array }
 */
const validatePasswordStrength = (password) => {
  const errors = [];

  if (!password || password.length < 8) {
    errors.push("Password must be at least 8 characters long");
  }

  if (!/[A-Z]/.test(password)) {
    errors.push("Password must contain at least one uppercase letter");
  }

  if (!/[a-z]/.test(password)) {
    errors.push("Password must contain at least one lowercase letter");
  }

  if (!/[0-9]/.test(password)) {
    errors.push("Password must contain at least one number");
  }

  if (!SPECIAL_CHARS_REGEX.test(password)) {
    errors.push("Password must contain at least one special character (!@#$%^&*)");
  }

  return {
    isValid: errors.length === 0,
    errors,
  };
};

/**
 * Calculate password strength score (0-5)
 * @param {string} password - Password to evaluate
 * @returns {number} - Strength score
 */
const getPasswordStrengthScore = (password) => {
  let score = 0;

  if (!password) return 0;

  if (password.length >= 8) score++;
  if (password.length >= 12) score++;
  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score++;
  if (/[0-9]/.test(password)) score++;
  if (SPECIAL_CHARS_REGEX.test(password)) score++;

  return Math.min(score, 5);
};

module.exports = {
  validatePasswordStrength,
  getPasswordStrengthScore,
};
