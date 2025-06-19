const express = require('express');
const {
  register,
  login,
  getMe,
  forgotPassword,
  resetPassword,
  updateDetails,
  updatePassword,
  logout,
  googleAuthCallback,
  verifyGoogleToken,
  verifyEmail,
  resendVerificationEmail
} = require('../controllers/authController');
const { protect, authorize } = require('../middlewares/auth');
const passport = require('passport');
const router = express.Router();


// Google OAuth routes
router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

router.get('/google/callback', 
  passport.authenticate('google', { failureRedirect: '/login' }), googleAuthCallback);

// New POST endpoint for Google token verification
router.post('/google', verifyGoogleToken);
router.post('/register', register);
router.get('/verify-email/:token', verifyEmail);
router.post('/resend-verification', resendVerificationEmail);
router.post('/login', login);
router.get('/me', protect, getMe);
router.put('/forgotpassword', forgotPassword);
router.put('/resetpassword/:resettoken', resetPassword);
router.put('/updatedetails', protect, authorize('user', 'admin'), updateDetails);
router.put('/updatepassword', protect, authorize('user', 'admin'), updatePassword);
router.get('/logout', protect, logout);

module.exports = router;