const Order = require("../models/Order");
const User = require("../models/User");
const { generateOrderOTP, verifyOrderOTP } = require("../utils/otpService");
const { sendEmail, emailTemplates } = require("../utils/sendEmail");

// Verify KYC middleware
exports.verifyKYC = async (req, res, next) => {
  try {
    console.log(req.body)
    console.log(req.user)
    const user = await User.findById(req.user.id);

    // Check if user exists and KYC status is 'verified'
    if (
      !user ||
      !user.kyc ||
      user.kyc.status !== 'verified' ||
      !(
        user.kyc.review?.result === 'GREEN' ||
        user.kyc.frontendReview?.reviewAnswer === 'GREEN'
      )
    ) {
      return res.status(403).json({
        success: false,
        message: "KYC verification required to access this feature",
      });
    }

    next();
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// Create new order
exports.createOrder = async (req, res) => {
  try {
    const {
      currencyToSend,
      currencyToReceive,
      amountToSend,
      destinationCountry,
      recipientName,
      recipientAccount,
      transferMethod,
      purpose,
      notes,
    } = req.body;

    if (
      currencyToSend === "CAD" &&
      ![
        "INR",
        "NGN",
        "USD",
        "GBP",
        "AUD",
        "GHC",
        "USDT",
        "BTC",
        "ETH",
        "BNB",
        "USDC",
      ].includes(currencyToReceive)
    ) {
      return res.status(400).json({
        success: false,
        message: "Invalid receiving currency for CAD",
      });
    }

    if (
      currencyToSend === "AUD" &&
      !["USDT", "BTC", "ETH", "BNB", "USDC"].includes(currencyToReceive)
    ) {
      return res.status(400).json({
        success: false,
        message: "Invalid receiving currency for AUD",
      });
    }

    const user = await User.findById(req.user.id);

    const newOrder = new Order({
      userId: req.user.id,
       fullName: `${user.firstName} ${user.lastName}`,
      email: user.email,
      currencyToSend,
      currencyToReceive,
      amountToSend,
      destinationCountry: destinationCountry || "",
      recipientName,
      recipientAccount,
      transferMethod,
      purpose: purpose || "",
      notes: notes || "",
      documentPath: req.file ? req.file.path : "",
    });

    await newOrder.save();

    // Generate OTP specifically for this order
    const otp = generateOrderOTP(req.user.id, newOrder._id.toString());

    // Send OTP email using template
    await sendEmail({
      to: user.email,
      ...emailTemplates.otpVerification(user, otp),
    });

    res.status(201).json({
      success: true,
      message: "Order created successfully. Please verify with OTP sent to your email.",
      orderId: newOrder._id,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// Verify OTP and complete order
exports.verifyOrderOTP = async (req, res) => {
  try {
    const { orderId, otp } = req.body;

    if (!orderId || !otp) {
      return res.status(400).json({
        success: false,
        message: "Order ID and OTP are required",
      });
    }

    // Find the order first
    const order = await Order.findById(orderId);
    
    if (!order) {
      return res.status(404).json({
        success: false,
        message: "Order not found",
      });
    }

    // Check if order belongs to the authenticated user
    if (order.userId.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: "Unauthorized access to order",
      });
    }

    // Check if order is already verified
    if (order.otpVerified) {
      return res.status(400).json({
        success: false,
        message: "Order is already verified",
      });
    }

    // Verify OTP
    const otpVerification = verifyOrderOTP(req.user.id, orderId, otp);
    
    if (!otpVerification.success) {
      return res.status(400).json({
        success: false,
        message: otpVerification.message,
      });
    }

    // Update order as verified
    const updatedOrder = await Order.findByIdAndUpdate(
      orderId,
      { 
        otpVerified: true,
        verifiedAt: new Date()
      },
      { new: true }
    );

    // Fetch user for the admin template
    const user = await User.findById(order.userId);
    const admins = await User.find({ role: "admin" });

    // Send notifications to all admins
    for (const admin of admins) {
      await sendEmail({
        to: admin.email,
        ...emailTemplates.adminOrderNotification(user, updatedOrder),
      });
    }

    res.status(200).json({
      success: true,
      message: "Order verified successfully. Our team will contact you shortly.",
      order: {
        id: updatedOrder._id,
        status: updatedOrder.status,
        verifiedAt: updatedOrder.verifiedAt
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// Resend OTP for order verification
exports.resendOrderOTP = async (req, res) => {
  try {
    const { orderId } = req.body;

    if (!orderId) {
      return res.status(400).json({
        success: false,
        message: "Order ID is required",
      });
    }

    const order = await Order.findById(orderId);
    
    if (!order) {
      return res.status(404).json({
        success: false,
        message: "Order not found",
      });
    }

    // Check if order belongs to the authenticated user
    if (order.userId.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: "Unauthorized access to order",
      });
    }

    // Check if order is already verified
    if (order.otpVerified) {
      return res.status(400).json({
        success: false,
        message: "Order is already verified",
      });
    }

    const user = await User.findById(req.user.id);

    // Generate new OTP
    const otp = generateOrderOTP(req.user.id, orderId);

    // Send OTP email
    await sendEmail({
      to: user.email,
      ...emailTemplates.otpVerification(user, otp),
    });

    res.status(200).json({
      success: true,
      message: "OTP sent successfully to your email",
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

// Get user's orders
exports.getUserOrders = async (req, res) => {
  try {
    const orders = await Order.find({ userId: req.user.id }).sort({
      createdAt: -1,
    });

    res.status(200).json({
      success: true,
      orders,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

exports.gerOrderByAdmin = async (req, res) => {
  try {
    const orders = await Order.find().sort({
      createdAt: -1,
    });

    res.status(200).json({
      success: true,
      orders,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
};


exports.updateOrderStatus = async (req, res) => {
  try {
    const { status } = req.body;
    const allowedStatuses = ['pending', 'processing', 'completed', 'rejected'];

    if (!allowedStatuses.includes(status)) {
      return res.status(400).json({ success: false, message: 'Invalid status value' });
    }

    const updatedOrder = await Order.findByIdAndUpdate(
      req.params.id,
      { status },
      { new: true }
    );

    if (!updatedOrder) {
      return res.status(404).json({ success: false, message: 'Order not found' });
    }

    res.status(200).json({ success: true, message: 'Status updated', order: updatedOrder });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
};
