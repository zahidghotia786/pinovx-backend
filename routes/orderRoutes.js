const express = require('express');
const router = express.Router();
const { createOrder, verifyOrderOTP, resendOrderOTP, getUserOrders, verifyKYC, gerOrderByAdmin, updateOrderStatus } = require('../controllers/orderController');
const uploadMiddleware = require('../middlewares/uploadMiddleware');
const { protect, authorize } = require('../middlewares/auth');

// Apply auth middleware to all routes
router.use(protect);

// Order routes
// POST /api/orders - Create new order (with KYC verification and file upload)
router.post(
  '/create',
  verifyKYC,
  uploadMiddleware.single('document'), createOrder
);

// POST /api/orders/verify-otp - Verify OTP for order completion
router.post('/verify-otp', verifyOrderOTP);

// POST /api/orders/resend-otp - Resend OTP for order verification
router.post('/resend-otp', resendOrderOTP);

// GET /api/orders - Get user's orders
router.get('/', getUserOrders);
router.get('/admin',authorize('admin'), gerOrderByAdmin);
router.put('/status/:id', protect, authorize('admin'), updateOrderStatus);


module.exports = router;