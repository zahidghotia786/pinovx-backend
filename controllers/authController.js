const User = require("../models/User");
const { generateToken, generateResetToken } = require("../utils/generateToken");
const { sendEmail, emailTemplates } = require("../utils/sendEmail");
const ErrorResponse = require("../utils/errorResponse");
const crypto = require("crypto");
require("dotenv").config();
const { OAuth2Client } = require("google-auth-library");
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// Helper function to get user's display name
const getUserDisplayName = (user) => {
  return user.firstName || user.fullName || user.name || "User";
};

const generateVerificationToken = () => {
  return crypto.randomBytes(20).toString("hex");
};

const sendVerificationEmail = async (user, verificationUrl) => {
  const verifyEmail = {
    subject: "Verify Your Email Address",
    text: `Please verify your email by clicking: ${verificationUrl}`,
    html: `
      <h1>Email Verification</h1>
      <p>Please click the link below to verify your email address:</p>
      <p><a href="${verificationUrl}">Verify Email</a></p>
      <p>This link will expire in 24 hours.</p>
    `,
  };
  await sendEmail({
    to: user.email,
    ...verifyEmail,
  });
};

// Helper function to notify all admins
const notifyAdmins = async (subject, message, userData = null) => {
  try {
    const admins = await User.find({ role: "admin" });
    for (const admin of admins) {
      if (admin.email !== userData?.email) {
        // Don't notify if the action was by an admin
        await sendEmail({
          to: admin.email,
          subject,
          text: message,
          html: `<div>${message}</div>`,
        });
      }
    }
  } catch (error) {
    console.error("Error notifying admins:", error);
  }
};

// @desc    Register user
// @route   POST /api/auth/register
// @access  Public
exports.register = async (req, res, next) => {
  try {
    const { firstName, lastName, email, password } = req.body;
    console.log(req.body);
    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return next(new ErrorResponse("Email already registered", 400));
    }
    // Generate verification token
    const verificationToken = generateVerificationToken();
    const verificationTokenExpire = Date.now() + 24 * 60 * 60 * 1000; // 24 hours

    const user = await User.create({
      firstName,
      lastName,
      email,
      password,
      role: email === process.env.ADMIN_EMAIL ? "admin" : "user" || "user",
      verificationToken,
      verificationTokenExpire,
      isVerified: false,
    });

    // Send verification email
    const verificationUrl = `${req.protocol}://${req.get(
      "host"
    )}/api/auth/verify-email/${verificationToken}`;
    await sendVerificationEmail(user, verificationUrl);

    res.status(201).json({
      success: true,
      message:
        "Registration successful. Please check your email to verify your account.",
      data: {
        _id: user._id,
        email: user.email,
      },
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Verify email
// @route   GET /api/auth/verify-email/:token
// @access  Public
exports.verifyEmail = async (req, res, next) => {
  try {
    const user = await User.findOne({
      verificationToken: req.params.token,
      verificationTokenExpire: { $gt: Date.now() },
    });

    if (!user) {
      return next(new ErrorResponse("Invalid or expired token", 400));
    }

    user.isVerified = true;
    user.verificationToken = undefined;
    user.verificationTokenExpire = undefined;
    await user.save();

    res.status(200).json({
      success: true,
      message: "Email verified successfully. You can now login.",
      data: {
        email: user.email,
      },
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Login user
// @route   POST /api/auth/login
// @access  Public
exports.login = async (req, res, next) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "Please provide an email and password"
      });
    }

    const user = await User.findOne({ email }).select("+password");
    
    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Invalid credentials"
      });
    }

    // Check if user uses Google auth
// if (user.authMethod === 'google') {
//   return res.status(401).json({
//     success: false,
//     message: "This account was created with Google login. Please sign in with Google."
//   });
// }

    // Check if user is verified
    if (!user.isVerified) {
      return res.status(401).json({
        success: false,
        message: "Please verify your email first. Check your inbox for the verification link."
      });
    }

    const isMatch = await user.matchPassword(password);
    
    if (!isMatch) {
      return res.status(401).json({
        success: false,
        message: "Invalid credentials"
      });
    }

    const token = generateToken(user._id);

    // Send login notification (non-blocking)
    setImmediate(async () => {
      try {
        const loginEmail = emailTemplates.login(user);
        await sendEmail({
          to: user.email,
          ...loginEmail,
          html: loginEmail.html.replace("${date}", new Date().toLocaleString()),
        });
      } catch (emailError) {
        console.error("Failed to send login notification:", emailError);
      }
    });

    res.status(200).json({
      success: true,
      token,
      user: {
        _id: user._id, // Fix: underscore missing tha
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        role: user.role,
        profile: user.profile,
      },
    });

  } catch (err) {
    console.error("Login error:", err);
    return res.status(500).json({
      success: false,
      message: "Internal server error"
    });
  }
};

// @desc    Resend verification email
// @route   POST /api/auth/resend-verification
// @access  Public
exports.resendVerificationEmail = async (req, res, next) => {
  try {
    const { email } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return next(new ErrorResponse("No user found with this email", 404));
    }

    if (user.isVerified) {
      return next(new ErrorResponse("Email is already verified", 400));
    }

    // Generate new verification token
    const verificationToken = generateVerificationToken();
    user.verificationToken = verificationToken;
    user.verificationTokenExpire = Date.now() + 24 * 60 * 60 * 1000; // 24 hours
    await user.save();

    // Send verification email
    const verificationUrl = `${req.protocol}://${req.get(
      "host"
    )}/api/auth/verify-email/${verificationToken}`;
    await sendVerificationEmail(user, verificationUrl);

    res.status(200).json({
      success: true,
      message: "Verification email resent. Please check your inbox.",
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Google authentication callback
// @route   GET /api/auth/google/callback
// @access  Public
exports.googleAuthCallback = async (req, res, next) => {
  try {
    if (!req.user) {
      return res.redirect("/login?error=authentication_failed");
    }

    const googleUser = req.user;

    let user = await User.findOne({
      $or: [{ email: googleUser.emails[0].value }, { googleId: googleUser.id }],
    });

    const isNewUser = !user;

    if (!user) {
      user = new User({
        firstName: googleUser.name?.givenName || "",
        lastName: googleUser.name?.familyName || "",
        fullName: googleUser.displayName || "",
        email: googleUser.emails[0].value,
        googleId: googleUser.id,
        isVerified: true,
        profilePicture: googleUser.photos?.[0]?.value || "",
        authMethod: "google",
        terms: true,
        role: "user",
      });
    } else {
      if (!user.googleId) {
        user.googleId = googleUser.id;
      }
      user.authMethod = "google";
      user.isVerified = true;
      if (googleUser.photos?.[0]?.value && !user.profilePicture) {
        user.profilePicture = googleUser.photos[0].value;
      }
    }

    await user.save();

    // Send welcome email if new user
    if (isNewUser) {
      try {
        const welcomeEmail = emailTemplates.welcome(user);
        await sendEmail({
          to: user.email,
          ...welcomeEmail,
        });

        // Notify admins about new Google-registered user
        await notifyAdmins(
          "New User Registration (Google)",
          `New user registered via Google: ${getUserDisplayName(user)} (${
            user.email
          })`,
          user
        );
      } catch (emailError) {
        console.error("Failed to send welcome email:", emailError);
      }
    }

    // Send login notification
    try {
      const loginEmail = emailTemplates.login(user);
      await sendEmail({
        to: user.email,
        ...loginEmail,
      });
    } catch (emailError) {
      console.error("Failed to send login notification:", emailError);
    }

    if (req.accepts("json")) {
      const token = generateToken(user._id);
      return res.json({
        success: true,
        token,
        user: {
          _id: user._id,
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email,
          role: user.role,
          profile: user.profile,
        },
      });
    }

    req.login(user, (err) => {
      if (err) return next(err);
      return res.redirect(process.env.FRONTEND_URL || "/");
    });
  } catch (error) {
    next(error);
  }
};

// @desc    Verify Google token
// @route   POST /api/auth/google
// @access  Public
exports.verifyGoogleToken = async (req, res, next) => {
  try {
    const { token, role } = req.body;

    const ticket = await client.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();
    const { name, email, picture, given_name, family_name } = payload;

    let user = await User.findOne({
      $or: [{ email }, { googleId: payload.sub }],
    });

    const isNewUser = !user;

    if (!user) {
      user = new User({
        firstName: given_name || "",
        lastName: family_name || "",
        fullName: name || "",
        email,
        googleId: payload.sub,
        profilePicture: picture || "",
        role: role || "user",
        isVerified: true,
        authMethod: "google",
        terms: true,
      });
    } else {
      if (!user.googleId) {
        user.googleId = payload.sub;
      }
      user.authMethod = "google";
      user.isVerified = true;
      if (picture && !user.profilePicture) {
        user.profilePicture = picture;
      }
    }

    await user.save();

    // Send welcome email if new user
    if (isNewUser) {
      try {
        const welcomeEmail = emailTemplates.welcome(user);
        await sendEmail({
          to: user.email,
          ...welcomeEmail,
        });

        // Notify admins about new Google-registered user
        await notifyAdmins(
          "New User Registration (Google)",
          `New user registered via Google: ${getUserDisplayName(user)} (${
            user.email
          })`,
          user
        );
      } catch (emailError) {
        console.error("Failed to send welcome email:", emailError);
      }
    }

    // Send login notification
    try {
      const loginEmail = emailTemplates.login(user);
      await sendEmail({
        to: user.email,
        ...loginEmail,
      });
    } catch (emailError) {
      console.error("Failed to send login notification:", emailError);
    }

    const jwtToken = generateToken(user._id);

    res.json({
      success: true,
      token: jwtToken,
      user: {
        _id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        role: user.role,
        profile: user.profile,
      },
    });
  } catch (error) {
    next(error);
  }
};

// @desc    Forgot password
// @route   POST /api/auth/forgotpassword
// @access  Public
exports.forgotPassword = async (req, res, next) => {
  console.log(req.body)
  try {
    const user = await User.findOne({ email: req.body.email });

    if (!user) {
      return next(new ErrorResponse("There is no user with that email", 404));
    }

    const resetToken = generateResetToken(user._id);
    user.resetPasswordToken = resetToken;
    user.resetPasswordExpire = Date.now() + 10 * 60 * 1000; // 10 minutes
    await user.save();

    const resetUrl = `${
      process.env.BASE_URL || req.protocol + "://" + req.get("host")
    }/reset-password/${resetToken}`;

    // Send password reset email to user
    try {
      const resetEmail = emailTemplates.passwordReset(user);
      await sendEmail({
        to: user.email,
        ...resetEmail,
        html: `${resetEmail.html}<p>Please click <a href="${resetUrl}">here</a> to reset your password.</p>
               <p>This link will expire in 10 minutes.</p>`,
      });
    } catch (emailError) {
      console.error("Failed to send reset email:", emailError);
    }

    // Notify admins about password reset request
    try {
      await notifyAdmins(
        "Password Reset Requested",
        `User ${getUserDisplayName(user)} (${
          user.email
        }) has requested a password reset.`,
        user
      );
    } catch (notifyError) {
      console.error("Failed to notify admins:", notifyError);
    }

    res.status(200).json({
      success: true,
      data: "Password reset email sent",
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Reset password
// @route   PUT /api/auth/resetpassword/:resettoken
// @access  Public
exports.resetPassword = async (req, res, next) => {
  try {
    const resetPasswordToken = req.params.resettoken;

    const user = await User.findOne({
      resetPasswordToken,
      resetPasswordExpire: { $gt: Date.now() },
    });

    if (!user) {
      return next(new ErrorResponse("Invalid or expired token", 400));
    }

    user.password = req.body.password;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpire = undefined;
    await user.save();

    // Send password reset confirmation to user
    try {
      const passwordUpdateEmail = emailTemplates.passwordUpdate(user);
      await sendEmail({
        to: user.email,
        ...passwordUpdateEmail,
      });
    } catch (emailError) {
      console.error("Failed to send password update email:", emailError);
    }

    // Notify admins about successful password reset
    try {
      await notifyAdmins(
        "Password Reset Completed",
        `User ${getUserDisplayName(user)} (${
          user.email
        }) has successfully reset their password.`,
        user
      );
    } catch (notifyError) {
      console.error("Failed to notify admins:", notifyError);
    }

    const token = generateToken(user._id);

    res.status(200).json({
      success: true,
      token,
      user: {
        _id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        role: user.role,
        profile: user.profile,
      },
    });
    
  } catch (err) {
    next(err);
  }
};

// @desc    Update user details
// @route   PUT /api/auth/updatedetails
// @access  Private
exports.updateDetails = async (req, res, next) => {
  try {
    const fieldsToUpdate = {
      firstName: req.body.firstName,
      lastName: req.body.lastName,
      email: req.body.email,
      profile: req.body.profile,
      phone: req.body.phone,
    };

    // Check if email is being updated and if it's already taken
    if (fieldsToUpdate.email && fieldsToUpdate.email !== req.user.email) {
      const existingUser = await User.findOne({ email: fieldsToUpdate.email });
      if (existingUser) {
        return next(new ErrorResponse("Email is already registered", 400));
      }
    }

    const user = await User.findByIdAndUpdate(req.user.id, fieldsToUpdate, {
      new: true,
      runValidators: true,
    });

    // Send profile update notification to user
    try {
      await sendEmail({
        to: user.email,
        subject: "Profile Updated",
        text: `Your profile has been updated successfully.`,
        html: `<h1>Profile Updated</h1><p>Your profile information was updated at ${new Date().toLocaleString()}.</p>`,
      });
    } catch (emailError) {
      console.error("Failed to send profile update email:", emailError);
    }

    // Notify admins about profile update
    try {
      await notifyAdmins(
        "Profile Update",
        `User ${getUserDisplayName(user)} (${
          user.email
        }) has updated their profile details.`,
        user
      );
    } catch (notifyError) {
      console.error("Failed to notify admins:", notifyError);
    }

    res.status(200).json({
      success: true,
      data: user,
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Update password
// @route   PUT /api/auth/updatepassword
// @access  Private
exports.updatePassword = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id).select("+password");

    if (!(await user.matchPassword(req.body.currentPassword))) {
      return next(new ErrorResponse("Current password is incorrect", 401));
    }

    user.password = req.body.newPassword;
    await user.save();

    // Send password change confirmation to user
    try {
      const passwordUpdateEmail = emailTemplates.passwordUpdate(user);
      await sendEmail({
        to: user.email,
        ...passwordUpdateEmail,
      });
    } catch (emailError) {
      console.error("Failed to send password update email:", emailError);
    }

    // Notify admins about password change
    try {
      await notifyAdmins(
        "Password Changed",
        `User ${getUserDisplayName(user)} (${
          user.email
        }) has changed their password.`,
        user
      );
    } catch (notifyError) {
      console.error("Failed to notify admins:", notifyError);
    }

    const token = generateToken(user._id);

    res.status(200).json({
      success: true,
      token,
      user: {
        _id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        role: user.role,
        profile: user.profile,
      },
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Get current logged in user
// @route   GET /api/auth/me
// @access  Private
exports.getMe = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);

    res.status(200).json({
      success: true,
      data: user,
    });
  } catch (err) {
    next(err);
  }
};

// @desc    Logout user
// @route   GET /api/auth/logout
// @access  Private
exports.logout = async (req, res, next) => {
  try {
    // Optionally send logout notification
    try {
      await sendEmail({
        to: req.user.email,
        subject: "Logout Notification",
        text: `You have been logged out from your account.`,
        html: `<h1>Logout Notification</h1><p>You were logged out at ${new Date().toLocaleString()}.</p>`,
      });
    } catch (emailError) {
      console.error("Failed to send logout email:", emailError);
    }

    res.status(200).json({
      success: true,
      data: {},
    });
  } catch (err) {
    next(err);
  }
};
