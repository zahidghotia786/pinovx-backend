const User = require('../models/User');
// const KYCToken = require('../models/KYCToken');
const ErrorResponse = require('../utils/errorResponse');

// @desc    Get all users
// @route   GET /api/users
// @access  Private/Admin
exports.getUsers = async (req, res, next) => {
  try {
    const users = await User.find().select('-password');

    res.status(200).json({
      success: true,
      count: users.length,
      data: users
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Get single user
// @route   GET /api/users/:id
// @access  Private/Admin
exports.getUser = async (req, res, next) => {
  try {
    const user = await User.findById(req.params.id).select('-password');

    if (!user) {
      return next(
        new ErrorResponse(`User not found with id of ${req.params.id}`, 404)
      );
    }

    res.status(200).json({
      success: true,
      data: user
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Get user KYC tokens
// @route   GET /api/users/:id/kyc
// @access  Private/Admin
// exports.getUserKYCTokens = async (req, res, next) => {
//   try {
//     const kycTokens = await KYCToken.find({ user: req.params.id });

//     res.status(200).json({
//       success: true,
//       count: kycTokens.length,
//       data: kycTokens
//     });
//   } catch (err) {
//     next(err);
//   }
// };

// @desc    Delete user
// @route   DELETE /api/users/:id
// @access  Private/Admin
exports.deleteUser = async (req, res, next) => {
  try {
    const user = await User.findById(req.params.id);

    if (!user) {
      return next(
        new ErrorResponse(`User not found with id of ${req.params.id}`, 404)
      );
    }

    // Prevent admin from deleting themselves
    if (user.role === 'admin' && user._id.toString() === req.user.id) {
      return next(new ErrorResponse('Admins cannot delete themselves', 400));
    }

    await user.remove();

    res.status(200).json({
      success: true,
      data: {}
    });
  } catch (err) {
    next(err);
  }
};