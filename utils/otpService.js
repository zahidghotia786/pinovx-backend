const crypto = require('crypto');

// In-memory storage for OTPs (in production, use Redis or database)
const otpStorage = new Map();

// OTP configuration
const OTP_CONFIG = {
  length: 6,
  expiryMinutes: 10,
  maxAttempts: 3
};

/**
 * Generate a random OTP
 * @param {number} length - Length of OTP (default: 6)
 * @returns {string} Generated OTP
 */
const generateOTP = (length = OTP_CONFIG.length) => {
  const digits = '0123456789';
  let otp = '';
  
  for (let i = 0; i < length; i++) {
    otp += digits[Math.floor(Math.random() * digits.length)];
  }
  
  return otp;
};

/**
 * Generate and store OTP for a specific identifier (email, phone, etc.)
 * @param {string} identifier - Unique identifier (email, phone, userId, etc.)
 * @param {string} purpose - Purpose of OTP (order-verification, login, etc.)
 * @returns {string} Generated OTP
 */
const generateAndStoreOTP = (identifier, purpose = 'general') => {
  const otp = generateOTP();
  const key = `${identifier}-${purpose}`;
  const expiryTime = Date.now() + (OTP_CONFIG.expiryMinutes * 60 * 1000);
  
  // Store OTP with metadata
  otpStorage.set(key, {
    otp,
    expiryTime,
    attempts: 0,
    maxAttempts: OTP_CONFIG.maxAttempts,
    createdAt: Date.now()
  });
  
  return otp;
};

/**
 * Verify OTP for a specific identifier
 * @param {string} identifier - Unique identifier
 * @param {string} otp - OTP to verify
 * @param {string} purpose - Purpose of OTP
 * @returns {Object} Verification result
 */
const verifyOTP = (identifier, otp, purpose = 'general') => {
  const key = `${identifier}-${purpose}`;
  const storedOTPData = otpStorage.get(key);
  
  if (!storedOTPData) {
    return {
      success: false,
      message: 'OTP not found or expired'
    };
  }
  
  // Check if OTP has expired
  if (Date.now() > storedOTPData.expiryTime) {
    otpStorage.delete(key);
    return {
      success: false,
      message: 'OTP has expired'
    };
  }
  
  // Check if max attempts exceeded
  if (storedOTPData.attempts >= storedOTPData.maxAttempts) {
    otpStorage.delete(key);
    return {
      success: false,
      message: 'Maximum verification attempts exceeded'
    };
  }
  
  // Increment attempt count
  storedOTPData.attempts++;
  
  // Verify OTP
  if (storedOTPData.otp === otp) {
    // OTP verified successfully, remove from storage
    otpStorage.delete(key);
    return {
      success: true,
      message: 'OTP verified successfully'
    };
  } else {
    // Update attempts count
    otpStorage.set(key, storedOTPData);
    return {
      success: false,
      message: `Invalid OTP. ${storedOTPData.maxAttempts - storedOTPData.attempts} attempts remaining`
    };
  }
};

/**
 * Generate OTP for order verification
 * @param {string} userId - User ID
 * @param {string} orderId - Order ID
 * @returns {string} Generated OTP
 */
const generateOrderOTP = (userId, orderId) => {
  return generateAndStoreOTP(`${userId}-${orderId}`, 'order-verification');
};

/**
 * Verify OTP for order verification
 * @param {string} userId - User ID
 * @param {string} orderId - Order ID
 * @param {string} otp - OTP to verify
 * @returns {Object} Verification result
 */
const verifyOrderOTP = (userId, orderId, otp) => {
  return verifyOTP(`${userId}-${orderId}`, otp, 'order-verification');
};

/**
 * Clean up expired OTPs (should be called periodically)
 */
const cleanupExpiredOTPs = () => {
  const now = Date.now();
  for (const [key, data] of otpStorage.entries()) {
    if (now > data.expiryTime) {
      otpStorage.delete(key);
    }
  }
};

/**
 * Get OTP info (for debugging/testing purposes)
 * @param {string} identifier - Unique identifier
 * @param {string} purpose - Purpose of OTP
 * @returns {Object|null} OTP info or null if not found
 */
const getOTPInfo = (identifier, purpose = 'general') => {
  const key = `${identifier}-${purpose}`;
  const data = otpStorage.get(key);
  
  if (!data) return null;
  
  return {
    hasOTP: true,
    expiryTime: data.expiryTime,
    attempts: data.attempts,
    maxAttempts: data.maxAttempts,
    remainingTime: Math.max(0, data.expiryTime - Date.now()),
    isExpired: Date.now() > data.expiryTime
  };
};

/**
 * Generate secure random OTP using crypto
 * @param {number} length - Length of OTP
 * @returns {string} Cryptographically secure OTP
 */
const generateSecureOTP = (length = OTP_CONFIG.length) => {
  const buffer = crypto.randomBytes(length);
  let otp = '';
  
  for (let i = 0; i < length; i++) {
    otp += (buffer[i] % 10).toString();
  }
  
  return otp;
};

// Set up periodic cleanup (every 5 minutes)
setInterval(cleanupExpiredOTPs, 5 * 60 * 1000);

module.exports = {
  generateOTP,
  generateAndStoreOTP,
  verifyOTP,
  generateOrderOTP,
  verifyOrderOTP,
  cleanupExpiredOTPs,
  getOTPInfo,
  generateSecureOTP,
  OTP_CONFIG
};