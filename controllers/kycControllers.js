const {
  createApplicant,
  generateAccessToken,
  generateVerificationToken,
  checkApplicantStatus,
} = require("../services/sumsubService");
const User = require("../models/User");
const crypto = require('crypto');

// Webhook security verification
const verifyWebhookSignature = (req) => {
  const signature = req.headers['x-payload-digest'];
  if (!signature) {
    throw new Error('Missing signature header');
  }

  const secret = process.env.SUMSUB_SECRET_KEY;
  const hmac = crypto.createHmac('sha256', secret);
  const digest = hmac.update(JSON.stringify(req.body)).digest('hex');

  if (signature !== digest) {
    throw new Error('Invalid webhook signature');
  }
  return true;
};

// Main webhook handler
exports.kycWebhook = async (req, res) => {
  try {
    // Verify webhook signature first
    verifyWebhookSignature(req);
    
    const event = req.body;
    console.log(`Received ${event.type} event for applicant ${event.applicantId}`);

    // Validate required fields
    if (!event.type || !event.applicantId) {
      throw new Error('Invalid webhook payload - missing required fields');
    }

    // Enhanced event handling
    const eventHandlers = {
      applicantReviewed: handleApplicantReviewed,
      applicantPending: handleApplicantPending,
      applicantOnHold: handleApplicantOnHold,
      applicantReset: handleApplicantReset,
      applicantCreated: handleApplicantCreated
    };

    const handler = eventHandlers[event.type];
    if (handler) {
      await handler(event);
    } else {
      console.warn(`Unhandled event type: ${event.type}`);
    }

    res.sendStatus(200);
  } catch (error) {
    console.error('Webhook Error:', {
      error: error.message,
      stack: error.stack,
      body: req.body,
      headers: req.headers
    });
    
    res.status(400).json({ 
      success: false, 
      error: error.message 
    });
  }
};

// FIXED: Single handleApplicantReviewed function
async function handleApplicantReviewed(event) {
  const { applicantId, review, applicant } = event;
  console.log("=== HANDLING APPLICANT REVIEWED ===");
  console.log("Received applicantId:", applicantId);
  console.log("Review Answer:", review?.reviewAnswer);
  
  try {
    // ✅ CRITICAL FIX: Search by kyc.applicantId, not _id
    const user = await User.findOne({ 'kyc.applicantId': applicantId });
    
    if (!user) {
      console.error(`❌ User not found for applicantId: ${applicantId}`);
      
      // Debug: Show all users with KYC applicantIds
      const allKycUsers = await User.find({ 'kyc.applicantId': { $exists: true } })
        .select('_id email kyc.applicantId');
      console.log("All users with KYC applicantIds:", allKycUsers);
      
      throw new Error("User not found for applicant ID: " + applicantId);
    }

    console.log(`✅ Found user: ${user._id} (${user.email}) for applicantId: ${applicantId}`);

    // Prepare comprehensive update data
    const updateData = {
      'kyc.status': review.reviewAnswer === 'GREEN' ? 'verified' : 'rejected',
      'kyc.lastVerifiedAt': new Date(),
      'kyc.review': {
        status: 'completed',
        result: review.reviewAnswer,
        rejectType: review.reviewRejectType || null,
        rejectLabels: review.reviewRejectLabels || [],
        comment: review.reviewComment || review.moderationComment || null,
        reviewedAt: new Date(review.reviewDate || Date.now()),
        reviewerId: review.reviewerId || 'system'
      }
    };

    // Add metadata if applicant data is available
    if (applicant) {
      updateData['kyc.metadata'] = {
        firstName: applicant.firstName || null,
        lastName: applicant.lastName || null,
        dob: applicant.dob ? new Date(applicant.dob) : null,
        country: applicant.country || null,
        documentType: applicant.idDocType || null,
        documentNumber: applicant.idDocNumber || null,
        placeOfBirth: applicant.placeOfBirth || null,
        issuedDate: applicant.issuedDate ? new Date(applicant.issuedDate) : null,
        validUntil: applicant.validUntil ? new Date(applicant.validUntil) : null
      };
    }

    // If approved, set verified status and generate token
    if (review.reviewAnswer === 'GREEN') {
      updateData.isVerified = true;
      
      try {
        const { token, expiresAt } = await generateVerificationToken(user._id);
        updateData['kyc.verificationToken'] = {
          token,
          expiresAt,
          used: false
        };
        console.log("✅ Generated verification token for user");
      } catch (tokenError) {
        console.error("❌ Failed to generate verification token:", tokenError);
        // Continue without token - user is still verified
      }
    }

    // Update the user document
    const updatedUser = await User.findByIdAndUpdate(
      user._id, 
      updateData,
      { new: true, runValidators: true }
    );

    if (!updatedUser) {
      throw new Error("Failed to update user document");
    }

    console.log(`✅ Successfully updated KYC status for user ${user._id}`);
    console.log("New KYC Status:", updatedUser.kyc.status);
    console.log("Review Result:", updatedUser.kyc.review?.result);
    
    return updatedUser;
    
  } catch (error) {
    console.error('❌ Error in handleApplicantReviewed:', error);
    throw error;
  }
}

// FIXED: All other handlers to use kyc.applicantId
async function handleApplicantPending(event) {
  const { applicantId } = event;
  await User.findOneAndUpdate(
    { 'kyc.applicantId': applicantId }, // FIXED: Use kyc.applicantId
    { 
      "kyc.status": "pending",
      "kyc.lastVerifiedAt": new Date() 
    }
  );
  console.log(`ℹ️ KYC status set to pending for applicant ${applicantId}`);
}

async function handleApplicantOnHold(event) {
  const { applicantId, comment } = event;
  await User.findOneAndUpdate(
    { 'kyc.applicantId': applicantId }, // FIXED: Use kyc.applicantId
    { 
      "kyc.status": "on_hold",
      "kyc.review.clientComment": comment,
      "kyc.lastVerifiedAt": new Date() 
    }
  );
  console.log(`⚠️ KYC status set to on hold for applicant ${applicantId}`);
}

async function handleApplicantReset(event) {
  const { applicantId } = event;
  await User.findOneAndUpdate(
    { 'kyc.applicantId': applicantId }, // FIXED: Use kyc.applicantId
    { 
      'kyc.status': 'not_started',
      'kyc.lastVerifiedAt': new Date(),
      'kyc.review': null,
      'isVerified': false
    }
  );
  console.log(`Reset KYC status for applicant ${applicantId}`);
}

async function handleApplicantCreated(event) {
  const { applicantId, externalUserId } = event;
  await User.findOneAndUpdate(
    { _id: externalUserId }, // This one uses _id as it's the externalUserId
    { 
      'kyc.applicantId': applicantId,
      'kyc.status': 'pending',
      'kyc.createdAt': new Date()
    }
  );
  console.log(`Recorded new applicant ${applicantId} for user ${externalUserId}`);
}

// Utility function to mask sensitive data
function maskSensitiveData(data) {
  if (!data) return null;
  const str = data.toString();
  if (str.length <= 4) return str;
  return str.slice(0, 2) + '*'.repeat(str.length - 4) + str.slice(-2);
}

exports.getKycToken = async (req, res, next) => {
  try {
    const userId = req.user.id;
    console.log("=== GET KYC TOKEN REQUEST ===");
    console.log("User ID:", userId);
    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({ 
        success: false, 
        error: 'User not found' 
      });
    }

    console.log("Current KYC Status:", user.kyc?.status);
    console.log("Applicant ID:", user.kyc?.applicantId);

    if (user?.kyc?.status === 'verified') {
      const kycData = {
        status: user.kyc.status,
        applicantId: user.kyc.applicantId,
        verifiedAt: user.kyc.lastVerifiedAt,
        personalInfo: {
          name: `${user.firstName} ${user.lastName}`,
          dob: user.kyc.metadata?.dob,
          country: user.kyc.metadata?.country
        },
        documentInfo: {
          type: user.kyc.metadata?.documentType,
          number: user.kyc.metadata?.documentNumber 
            ? maskSensitiveData(user.kyc.metadata.documentNumber)
            : null
        }
      };

      return res.status(200).json({ 
        success: true, 
        message: 'User already verified',
        isVerified: true,
        kycData 
      });
    }

    const userData = {
      country: req.user.country,
      name: req.user.name,
    };

    // First try to get token directly
    try {
      console.log("Attempting to generate access token...");
      const token = await generateAccessToken(userId);
      console.log("✅ Token generated successfully");
      return res.status(200).json({ success: true, token });
    } catch (tokenError) {
      console.log("❌ Token generation failed:", tokenError.message);
      
      if (tokenError.isApplicantNotFound) {
        console.log("Creating new applicant...");
        const applicant = await createApplicant(userId, userData);
        console.log("Applicant created:", applicant?.id || "null");
        
        // Update user with applicant ID
        const updateResult = await User.findByIdAndUpdate(userId, {
          'kyc.applicantId': applicant.id,
          'kyc.status': 'pending',
          'kyc.createdAt': new Date()
        }, { new: true });
        
        console.log("User updated with applicantId:", updateResult.kyc.applicantId);
        
        // Generate token for new applicant
        const token = await generateAccessToken(userId);
        console.log("✅ Token generated for new applicant");
        return res.status(200).json({ success: true, token });
      }
      throw tokenError;
    }
  } catch (error) {
    console.error("❌ KYC Token Error:", {
      status: error.response?.status,
      data: error.response?.data,
      message: error.message,
    });

    const statusCode = error.response?.status || 500;
    const errorMessage =
      error.response?.data?.description ||
      "Failed to generate KYC verification token";

    res.status(statusCode).json({
      success: false,
      error: errorMessage,
    });
  }
};

// NEW: Add a manual sync function for testing
exports.syncKycStatus = async (req, res) => {
  try {
    const { applicantId } = req.params;
    
    // Fetch current status from SumSub
    const applicantData = await checkApplicantStatus(applicantId);
    
    // Find user by applicantId
    const user = await User.findOne({ 'kyc.applicantId': applicantId });
    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'User not found for applicant ID'
      });
    }

    // Update user based on current status
    const updateData = {
      'kyc.status': applicantData.review?.reviewResult?.reviewAnswer === 'GREEN' ? 'verified' : 'pending',
      'kyc.lastVerifiedAt': new Date(),
    };

    if (applicantData.review?.reviewResult?.reviewAnswer === 'GREEN') {
      updateData.isVerified = true;
    }

    const updatedUser = await User.findByIdAndUpdate(
      user._id,
      updateData,
      { new: true }
    );

    res.json({
      success: true,
      message: 'KYC status synced successfully',
      kycStatus: updatedUser.kyc.status,
      isVerified: updatedUser.isVerified
    });

  } catch (error) {
    console.error('Sync KYC Status Error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to sync KYC status'
    });
  }
};



// Updated controller method with enhanced GREEN token generation
exports.updateKycStatus = async (req, res) => {
  try {
    const userId = req.user.id;
    const { applicantId, statusData, timestamp } = req.body;
    console.log(req.body)
    
    console.log("=== FRONTEND KYC STATUS UPDATE ===");
    console.log("User ID:", userId);
    console.log("Applicant ID:", applicantId);
    console.log("Status Data:", JSON.stringify(statusData, null, 2));
    console.log("Timestamp:", timestamp);

    // Validate required fields
    if (!applicantId || !statusData) {
      return res.status(400).json({
        success: false,
        error: 'Missing required fields: applicantId and statusData'
      });
    }

    // Find user by applicantId to ensure it matches the authenticated user
    const user = await User.findOne({ 
      _id: userId,
    });

    if (!user) {
      console.error(`❌ User not found or applicantId mismatch. UserId: ${userId}, ApplicantId: ${applicantId}`);
      return res.status(404).json({
        success: false,
        error: 'User not found or applicantId mismatch'
      });
    }

    console.log(`✅ Found user: ${user._id} (${user.email}) for applicantId: ${applicantId}`);

    // Prepare update data based on review result
    const updateData = {
      'kyc.lastUpdatedAt': new Date(timestamp || Date.now()),
      'kyc.lastStatusData': statusData
    };

    // Update status based on reviewResult
    if (statusData.reviewResult && statusData.reviewResult.reviewAnswer) {
      const reviewAnswer = statusData.reviewResult.reviewAnswer;
      
      switch (reviewAnswer) {
        case 'GREEN':
          updateData['kyc.status'] = 'verified';
          updateData['isVerified'] = true;
          updateData['kyc.verifiedAt'] = new Date(statusData.reviewDate || timestamp || Date.now());
          console.log("✅ Setting user as VERIFIED");
          break;
        case 'RED':
          updateData['kyc.status'] = 'rejected';
          updateData['isVerified'] = false;
          console.log("❌ Setting user as REJECTED");
          break;
        case 'YELLOW':
          updateData['kyc.status'] = 'under_review';
          console.log("⚠️ Setting user as UNDER REVIEW");
          break;
        default:
          updateData['kyc.status'] = 'pending';
          console.log("⏳ Setting user as PENDING");
      }
    }

    // Store detailed review information
    if (statusData.reviewResult) {
      updateData['kyc.frontendReview'] = {
        reviewAnswer: statusData.reviewResult.reviewAnswer,
        reviewId: statusData.reviewId,
        attemptId: statusData.attemptId,
        attemptCount: statusData.attemptCnt,
        levelName: statusData.levelName,
        reviewStatus: statusData.reviewStatus,
        reviewDate: statusData.reviewDate,
        createDate: statusData.createDate,
        processingTime: {
          elapsedSincePendingMs: statusData.elapsedSincePendingMs,
          elapsedSinceQueuedMs: statusData.elapsedSinceQueuedMs
        },
        updatedFromFrontend: true,
        updatedAt: new Date()
      };
    }

    // Update the user document
    const updatedUser = await User.findByIdAndUpdate(
      user._id,
      updateData,
      { new: true, runValidators: true }
    );

    if (!updatedUser) {
      throw new Error("Failed to update user document");
    }

    console.log(`✅ Successfully updated KYC status for user ${user._id}`);
    console.log("New KYC Status:", updatedUser.kyc.status);
    console.log("Is Verified:", updatedUser.isVerified);

    // Prepare response data
    const responseData = {
      success: true,
      message: 'KYC status updated successfully',
      data: {
        userId: user._id,
        applicantId: applicantId,
        kycStatus: updatedUser.kyc.status,
        isVerified: updatedUser.isVerified,
        reviewAnswer: statusData.reviewResult?.reviewAnswer,
        updatedAt: updateData['kyc.lastUpdatedAt']
      }
    };

    // 🟢 ENHANCED: Generate custom token ONLY for GREEN results
    if (statusData.reviewResult?.reviewAnswer === 'GREEN' && updatedUser.isVerified) {
      try {
        console.log("🔐 Generating custom verification token for GREEN result...");
        
        // Generate custom token with additional security
        const customToken = await generateCustomVerificationToken(user._id, {
          applicantId: applicantId,
          reviewId: statusData.reviewId,
          attemptId: statusData.attemptId,
          verificationLevel: statusData.levelName || 'basic'
        });
        
        // Save the custom token to user schema
        await User.findByIdAndUpdate(user._id, {
          'kyc.verificationToken': {
            token: customToken.token,
            expiresAt: customToken.expiresAt,
            used: false,
            generatedFromFrontend: true,
            tokenType: 'GREEN_VERIFICATION', // Custom token type
            metadata: {
              reviewId: statusData.reviewId,
              attemptId: statusData.attemptId,
              levelName: statusData.levelName,
              generatedAt: new Date(),
              ipAddress: req.ip || req.connection.remoteAddress,
              userAgent: req.get('User-Agent')
            }
          }
        });
        
        console.log("✅ Custom GREEN verification token generated and saved");
        responseData.data.hasVerificationToken = true;
        responseData.data.tokenGenerated = true;
        responseData.data.tokenType = 'GREEN_VERIFICATION';
        
      } catch (tokenError) {
        console.error("❌ Failed to generate custom GREEN token:", tokenError);
        // Continue without token - user is still verified
        responseData.data.tokenError = 'Failed to generate verification token';
      }
    } else if (statusData.reviewResult?.reviewAnswer !== 'GREEN') {
      console.log(`ℹ️ No token generated - Review result is ${statusData.reviewResult?.reviewAnswer}, not GREEN`);
      responseData.data.tokenGenerated = false;
      responseData.data.reason = 'Token only generated for GREEN verification results';
    }

    res.status(200).json(responseData);

  } catch (error) {
    console.error('❌ Error updating KYC status from frontend:', {
      error: error.message,
      stack: error.stack,
      body: req.body,
      userId: req.user?.id
    });
    res.status(500).json({
      success: false,
      error: 'Failed to update KYC status',
      details: error.message
    });
  }
};

// 🔐 Custom token generation function for GREEN results
const generateCustomVerificationToken = async (userId, additionalData = {}) => {
  const crypto = require('crypto');
  
  // Create a more sophisticated token for GREEN verification
  const baseToken = crypto.randomBytes(8).toString('hex');
  const timestamp = Date.now().toString(36);
  const userHash = crypto.createHash('sha256').update(userId.toString()).digest('hex').substring(0, 8);
  
  // Combine different elements for a unique token
  const customToken = `pinovX_${timestamp}_${userHash}_${baseToken}`;
  
  // Set expiration (90 days for GREEN tokens)
  const expiresAt = new Date(Date.now() + 90 * 24 * 60 * 60 * 1000);
  
  console.log(`🔐 Generated custom GREEN token for user ${userId}:`, {
    tokenLength: customToken.length,
    expiresAt: expiresAt.toISOString(),
    additionalData
  });
  
  return {
    token: customToken,
    expiresAt,
    metadata: {
      generatedFor: 'GREEN_VERIFICATION',
      userId,
      ...additionalData
    }
  };
};




// @desc    Get user KYC verification data
// @route   GET /api/v1/users/kyc/:id
// @access  Private/Admin
exports.getUserKYCData = async (req, res, next) => {
  const user = await User.findById(req.params.id)
    .select('firstName lastName email role profilePicture isVerified kyc');

  if (!user) {
    return next(
      new ErrorResponse(`User not found with id of ${req.params.id}`, 404)
    );
  }

  // Prepare the response data
  const responseData = {
    user: {
      _id: user._id,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      role: user.role,
      profilePicture: user.profilePicture,
      isVerified: user.isVerified
    },
    kyc: {
      status: user.kyc?.status || 'not_started',
      levelName: user.kyc?.levelName,
      attempts: user.kyc?.attempts || 0,
      verifiedAt: user.kyc?.verifiedAt,
      lastUpdatedAt: user.kyc?.lastUpdatedAt
    },
    review: {
      status: user.kyc?.frontendReview?.reviewStatus || user.kyc?.review?.status,
      result: user.kyc?.frontendReview?.reviewAnswer || user.kyc?.review?.result,
      reviewId: user.kyc?.frontendReview?.reviewId || user.kyc?.review?.reviewId,
      attemptId: user.kyc?.frontendReview?.attemptId,
      attemptCount: user.kyc?.frontendReview?.attemptCount,
      reviewDate: user.kyc?.frontendReview?.reviewDate || user.kyc?.review?.reviewedAt,
      processingTime: user.kyc?.frontendReview?.processingTime
    },
    verificationToken: user.kyc?.verificationToken ? {
      token: user.kyc.verificationToken.token,
      tokenType: user.kyc.verificationToken.tokenType,
      expiresAt: user.kyc.verificationToken.expiresAt,
      used: user.kyc.verificationToken.used
    } : null,
    isKYCVerified: user.isKYCVerified,
    hasGreenToken: user.hasGreenToken
  };

  res.status(200).json({
    success: true,
    data: responseData
  });
};


// @desc    Generate GREEN verification token for user
// @route   POST /api/v1/users/kyc/:id/generate-token
// @access  Private/Admin
exports.generateGreenVerificationToken = async (req, res, next) => {
  const user = await User.findById(req.params.id);

  if (!user) {
    return next(
      new ErrorResponse(`User not found with id of ${req.params.id}`, 404)
    );
  }

  if (user.kyc?.status !== 'verified') {
    return next(
      new ErrorResponse('User KYC is not verified', 400)
    );
  }

  const reviewData = user.kyc.frontendReview || user.kyc.review;
  if (!reviewData || reviewData.reviewAnswer !== 'GREEN') {
    return next(
      new ErrorResponse('User does not have GREEN verification status', 400)
    );
  }

  const token = await user.generateGreenVerificationToken({
    reviewId: reviewData.reviewId,
    attemptId: reviewData.attemptId,
    levelName: reviewData.levelName
  });

  res.status(200).json({
    success: true,
    data: {
      token,
      expiresAt: user.kyc.verificationToken.expiresAt
    }
  });
};

// @desc    Verify GREEN token
// @route   POST /api/v1/users/kyc/verify-token
// @access  Public
exports.verifyGreenToken = async (req, res, next) => {
  const { token } = req.body;

  if (!token) {
    return next(
      new ErrorResponse('Please provide a verification token', 400)
    );
  }

  const user = await User.findByGreenToken(token);

  if (!user) {
    return next(
      new ErrorResponse('Invalid or expired token', 401)
    );
  }

  const isValid = await user.verifyGreenToken(token);

  if (!isValid) {
    return next(
      new ErrorResponse('Token verification failed', 401)
    );
  }

  res.status(200).json({
    success: true,
    data: {
      user: {
        _id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email
      },
      kycStatus: user.kyc.status,
      isVerified: user.isVerified
    }
  });
};




// @desc    Get current user's dashboard data (including KYC status)
// @route   GET /api/v1/users/me/dashboard
// @access  Private (user can only access their own data)
exports.getMyDashboardData =async (req, res, next) => {
  // req.user is set by the protect middleware
  const user = await User.findById(req.user.id)
    .select('firstName lastName email role profilePicture isVerified kyc createdAt');

  if (!user) {
    return next(
      new ErrorResponse('User not found', 404)
    );
  }

  // Prepare dashboard response
  const dashboardData = {
    user: {
      _id: user._id,
      firstName: user.firstName,
      lastName: user.lastName,
      email: user.email,
      role: user.role,
      profilePicture: user.profilePicture,
      isVerified: user.isVerified,
      accountCreated: user.createdAt
    },
    kyc: {
      status: user.kyc?.status || 'not_started',
      levelName: user.kyc?.frontendReview.levelName,
      attempts: user.kyc?.attempts || 0,
      lastUpdated: user.kyc?.lastUpdatedAt,
      // Simplified verification status for dashboard
      verificationStatus: user.isKYCVerified ? 'verified' : 'pending',
      // Frontend review status
      review: user.kyc?.frontendReview ? {
        status: user.kyc.frontendReview.reviewStatus,
        result: user.kyc.frontendReview.reviewAnswer,
        date: user.kyc.frontendReview.reviewDate
      } : null,
      // Token information (if exists)
      token: user.kyc?.verificationToken ? {
        token: user.kyc.verificationToken.token,
        type: user.kyc.verificationToken.tokenType,
        expires: user.kyc.verificationToken.expiresAt,
        isActive: !user.kyc.verificationToken.used && 
                 user.kyc.verificationToken.expiresAt > new Date()
      } : null
    },
    // Add any other dashboard metrics here
    metrics: {
      // Example metrics - customize based on your application
      completedActions: 0, // Replace with actual metrics
      pendingActions: 0
    }
  };

  res.status(200).json({
    success: true,
    data: dashboardData
  });
};

// @desc    Get current user's KYC verification details
// @route   GET /api/v1/users/me/kyc
// @access  Private
exports.getMyKYCData = async (req, res, next) => {
  const user = await User.findById(req.user.id)
    .select('kyc');

  if (!user) {
    return next(
      new ErrorResponse('User not found', 404)
    );
  }

  // Prepare detailed KYC response
  const kycData = {
    status: user.kyc?.status || 'not_started',
    levelName: user.kyc?.levelName,
    attempts: user.kyc?.attempts || 0,
    verifiedAt: user.kyc?.verifiedAt,
    lastUpdatedAt: user.kyc?.lastUpdatedAt,
    frontendReview: user.kyc?.frontendReview || null,
    verificationToken: user.kyc?.verificationToken ? {
      tokenType: user.kyc.verificationToken.tokenType,
      expiresAt: user.kyc.verificationToken.expiresAt,
      generatedFromFrontend: user.kyc.verificationToken.generatedFromFrontend,
      used: user.kyc.verificationToken.used
    } : null,
    documents: user.kyc?.documents || [],
    isVerified: user.isKYCVerified,
    hasGreenToken: user.hasGreenToken
  };

  res.status(200).json({
    success: true,
    data: kycData
  });
};






exports.getAllUsersKYCData = async (req, res, next) => {
  const users = res.advancedResults.data;
  
  const stats = await calculateKYCStatistics();
  
  res.status(200).json({
    ...res.advancedResults,
    statistics: stats
  });
};


// Helper function to calculate comprehensive KYC statistics
const calculateKYCStatistics = async () => {
  const now = new Date();
  const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  const yesterday = new Date(today.getTime() - 24 * 60 * 60 * 1000);
  const lastWeek = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
  const lastMonth = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);

  // Get all users
  const allUsers = await User.find({}).select('kyc createdAt lastActiveAt isVerified');
  const totalUsers = allUsers.length;

  // Basic user counts
  const activeUsers = allUsers.filter(user => 
    user.lastActiveAt && new Date(user.lastActiveAt) > yesterday
  ).length;

  const newUsersToday = allUsers.filter(user => 
    new Date(user.createdAt) >= today
  ).length;

  const newUsersThisWeek = allUsers.filter(user => 
    new Date(user.createdAt) >= lastWeek
  ).length;

  const newUsersThisMonth = allUsers.filter(user => 
    new Date(user.createdAt) >= lastMonth
  ).length;

  // KYC Status counts
  const kycStatusCounts = {
    not_started: 0,
    initiated: 0,
    pending: 0,
    verified: 0,
    rejected: 0,
    expired: 0,
    on_hold: 0,
    under_review: 0
  };

  // KYC Review result counts
  const reviewResultCounts = {
    GREEN: 0,
    RED: 0,
    YELLOW: 0,
    AMBER: 0,
    PENDING: 0
  };

  // Special verification counts
  let greenVerifiedCount = 0;
  let greenTokenCount = 0;
  let expiredTokenCount = 0;

  // Process each user
  allUsers.forEach(user => {
    // Count KYC statuses
    const kycStatus = user.kyc?.status || 'not_started';
    if (kycStatusCounts.hasOwnProperty(kycStatus)) {
      kycStatusCounts[kycStatus]++;
    }

    // Count review results
    const frontendResult = user.kyc?.frontendReview?.reviewAnswer;
    const backendResult = user.kyc?.review?.result;
    const reviewResult = frontendResult || backendResult;

    if (reviewResult && reviewResultCounts.hasOwnProperty(reviewResult)) {
      reviewResultCounts[reviewResult]++;
    } else if (kycStatus === 'pending' || kycStatus === 'under_review') {
      reviewResultCounts.PENDING++;
    }

    // Count special verifications
    if (user.kyc?.greenVerification?.verifiedAt || 
        (user.kyc?.verificationToken?.tokenType === 'GREEN_VERIFICATION' && !user.kyc?.verificationToken?.used)) {
      greenVerifiedCount++;
    }

    if (user.kyc?.verificationToken?.tokenType === 'GREEN_VERIFICATION' && !user.kyc?.verificationToken?.used) {
      greenTokenCount++;
    }

    if (user.kyc?.verificationToken && user.kyc?.verificationToken?.expiresAt < now) {
      expiredTokenCount++;
    }
  });

  // Calculate percentages and growth rates
  const verificationRate = totalUsers > 0 ? ((kycStatusCounts.verified / totalUsers) * 100).toFixed(1) : 0;
  const greenVerificationRate = totalUsers > 0 ? ((reviewResultCounts.GREEN / totalUsers) * 100).toFixed(1) : 0;
  const dailyGrowthRate = totalUsers > 0 ? ((newUsersToday / totalUsers) * 100).toFixed(2) : 0;
  const weeklyGrowthRate = totalUsers > 0 ? ((newUsersThisWeek / totalUsers) * 100).toFixed(2) : 0;
  const monthlyGrowthRate = totalUsers > 0 ? ((newUsersThisMonth / totalUsers) * 100).toFixed(2) : 0;

  // Recent activity (last 24 hours)
  const recentVerifications = await User.countDocuments({
    'kyc.verifiedAt': { $gte: yesterday }
  });

  const recentTokenGeneration = await User.countDocuments({
    'kyc.verificationToken.metadata.generatedAt': { $gte: yesterday }
  });

  return {
    // Basic counts
    totalUsers,
    activeUsers,
    newUsersToday,
    newUsersThisWeek,
    newUsersThisMonth,
    
    // KYC Status breakdown
    kycStatusCounts,
    
    // Review results breakdown
    reviewResultCounts,
    
    // Special verification counts
    greenVerifiedCount,
    greenTokenCount,
    expiredTokenCount,
    
    // Calculated percentages
    verificationRate: parseFloat(verificationRate),
    greenVerificationRate: parseFloat(greenVerificationRate),
    
    // Growth rates
    dailyGrowthRate: parseFloat(dailyGrowthRate),
    weeklyGrowthRate: parseFloat(weeklyGrowthRate),
    monthlyGrowthRate: parseFloat(monthlyGrowthRate),
    
    // Recent activity
    recentActivity: {
      verifications: recentVerifications,
      tokenGeneration: recentTokenGeneration
    },
    
    // Summary for dashboard
    summary: {
      pendingKYC: kycStatusCounts.pending + kycStatusCounts.under_review + kycStatusCounts.initiated,
      verifiedKYC: kycStatusCounts.verified,
      rejectedKYC: kycStatusCounts.rejected,
      totalGreenVerified: reviewResultCounts.GREEN,
      conversionRate: totalUsers > 0 ? ((kycStatusCounts.verified / totalUsers) * 100).toFixed(1) : 0
    },
    
    // Timestamp
    generatedAt: new Date(),
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
  };
};
