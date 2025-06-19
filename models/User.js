const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

// KYC Sub-schemas
const KYCDocumentSchema = new mongoose.Schema({
  type: {
    type: String,
    enum: ['PASSPORT', 'ID_CARD', 'DRIVERS_LICENSE', 'RESIDENCE_PERMIT', 'OTHER'],
    required: true
  },
  number: {
    type: String,
    trim: true
  },
  country: {
    type: String,
    required: true
  },
  frontImage: String,
  backImage: String,
  selfieImage: String,
  issuedDate: Date,
  expiryDate: Date,
  verified: Boolean
}, { _id: false });

// Enhanced KYC Review Schema
const KYCReviewSchema = new mongoose.Schema({
  status: {
    type: String,
    enum: ['pending', 'completed', 'on_hold', 'withdrawn'],
    default: 'pending'
  },
  result: {
    type: String,
    enum: ['GREEN', 'RED', 'YELLOW', 'AMBER', null],
    default: null
  },
  rejectType: String,
  rejectLabels: [String],
  comment: String,
  clientComment: String,
  reviewedAt: Date,
  reviewerId: String
}, { _id: false });

// 🔐 ENHANCED: Custom Token Schema for GREEN verification
const KYCTokenSchema = new mongoose.Schema({
  token: {
    type: String,
    required: true,
    unique: true,
    index: true
  },
  expiresAt: {
    type: Date,
    required: true
  },
  used: {
    type: Boolean,
    default: false
  },
  usedAt: Date,
  generatedFromFrontend: {
    type: Boolean,
    default: false
  },
  // 🟢 NEW: Enhanced token properties for GREEN verification
  tokenType: {
    type: String,
    enum: ['STANDARD', 'GREEN_VERIFICATION', 'ADMIN_OVERRIDE'],
    default: 'STANDARD'
  },
  metadata: {
    reviewId: String,
    attemptId: String,
    levelName: String,
    generatedAt: {
      type: Date,
      default: Date.now
    },
    ipAddress: String,
    userAgent: String,
    // Additional security metadata
    verificationLevel: String,
    securityHash: String
  }
}, { _id: false });

// Frontend Review Schema for real-time updates
const FrontendReviewSchema = new mongoose.Schema({
  reviewAnswer: {
    type: String,
    enum: ['GREEN', 'RED', 'YELLOW']
  },
  reviewId: String,
  attemptId: String,
  attemptCount: Number,
  levelName: String,
  reviewStatus: String,
  reviewDate: String,
  createDate: String,
  processingTime: {
    elapsedSincePendingMs: Number,
    elapsedSinceQueuedMs: Number
  },
  updatedFromFrontend: {
    type: Boolean,
    default: true
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
}, { _id: false });

// Enhanced KYC Metadata Schema
const KYCMetadataSchema = new mongoose.Schema({
  firstName: String,
  lastName: String,
  dob: Date,
  country: String,
  documentType: String,
  documentNumber: String,
  placeOfBirth: String,
  issuedDate: Date,
  validUntil: Date
}, { _id: false });

const userSchema = new mongoose.Schema({
  firstName: {
    type: String,
    required: [true, 'Please add first name'],
    trim: true,
    maxlength: [30, 'First name cannot be more than 30 characters']
  },
  lastName: {
    type: String,
    required: [true, 'Please add last name'],
    trim: true,
    maxlength: [30, 'Last name cannot be more than 30 characters']
  },
  fullName: {
    type: String,
    trim: true
  },
  email: {
    type: String,
    required: [true, 'Please add an email'],
    unique: true,
    trim: true,
    lowercase: true,
    match: [
      /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/,
      'Please add a valid email'
    ]
  },
  password: {
    type: String,
    required: function() { return this.authMethod === 'local'; },
    minlength: [6, 'Password must be at least 6 characters'],
    select: false
  },
  role: {
    type: String,
    enum: ['user', 'admin', 'moderator'],
    default: 'user'
  },
  profilePicture: {
    type: String,
    default: ''
  },
  googleId: {
    type: String,
    unique: true,
    sparse: true
  },
  authMethod: {
    type: String,
    enum: ['local', 'google', 'apple', 'facebook'],
    default: 'local'
  },
  isVerified: {
    type: Boolean,
    default: false
  },
  resetPasswordToken: String,
  resetPasswordExpire: Date,
  terms: {
    type: Boolean,
    default: false,
    required: [true, 'You must accept the terms and conditions']
  },
  profile: {
    phone: {
      type: String,
      trim: true,
      maxlength: [20, 'Phone number cannot be longer than 20 characters']
    },
    address: {
      type: String,
      trim: true,
      maxlength: [200, 'Address cannot be more than 200 characters']
    },
    dateOfBirth: Date,
    nationality: String,
    gender: {
      type: String,
      enum: ['male', 'female', 'other', 'prefer_not_to_say']
    }
  },
  // Enhanced KYC fields
  kyc: {
    applicantId: {
      type: String,
      unique: true,
      sparse: true
    },
    status: {
      type: String,
      enum: ['not_started', 'initiated', 'pending', 'verified', 'rejected', 'expired', 'on_hold', 'under_review'],
      default: 'not_started'
    },
    levelName: String,
    verificationToken: KYCTokenSchema, // Enhanced with GREEN token support
    documents: [KYCDocumentSchema],
    review: KYCReviewSchema,
    frontendReview: FrontendReviewSchema,
    lastVerifiedAt: Date,
    lastUpdatedAt: Date,
    verifiedAt: Date,
    createdAt: Date,
    attempts: {
      type: Number,
      default: 0
    },
    metadata: KYCMetadataSchema,
    lastStatusData: mongoose.Schema.Types.Mixed,
    // 🟢 NEW: Track GREEN verification specifically
    greenVerification: {
      verifiedAt: Date,
      tokenGenerated: Boolean,
      reviewId: String,
      attemptId: String,
      levelName: String
    }
  },
  // Tracking
  lastActiveAt: Date,
  ipAddress: String,
  userAgent: String
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Indexes
userSchema.index({ email: 1 }, { unique: true });
userSchema.index({ googleId: 1 }, { unique: true, sparse: true });
userSchema.index({ 'kyc.applicantId': 1 }, { unique: true, sparse: true });
userSchema.index({ 'kyc.verificationToken.token': 1 }, { unique: true, sparse: true });
userSchema.index({ 'kyc.status': 1 });
userSchema.index({ isVerified: 1 });
// 🟢 NEW: Index for GREEN token types
userSchema.index({ 'kyc.verificationToken.tokenType': 1 });

// Middleware
userSchema.pre('save', async function(next) {
  if (!this.isModified('password') || this.authMethod !== 'local') {
    return next();
  }

  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

userSchema.pre('save', function(next) {
  if (this.isModified('firstName') || this.isModified('lastName')) {
    this.fullName = `${this.firstName} ${this.lastName}`.trim();
  }
  next();
});

// Virtuals
userSchema.virtual('name').get(function() {
  return `${this.firstName} ${this.lastName}`.trim() || this.fullName;
});

userSchema.virtual('isKYCVerified').get(function() {
  return this.kyc.status === 'verified' && 
         (this.kyc.review?.result === 'GREEN' || this.kyc.frontendReview?.reviewAnswer === 'GREEN') &&
         (!this.kyc.verificationToken || this.kyc.verificationToken.expiresAt > new Date());
});

// 🟢 NEW: Virtual to check if user has GREEN verification token
userSchema.virtual('hasGreenToken').get(function() {
  return !!(this.kyc.verificationToken && 
           this.kyc.verificationToken.tokenType === 'GREEN_VERIFICATION' &&
           !this.kyc.verificationToken.used &&
           this.kyc.verificationToken.expiresAt > new Date());
});

userSchema.virtual('kycSummary').get(function() {
  if (!this.kyc) return null;
  
  return {
    status: this.kyc.status,
    isVerified: this.isVerified,
    applicantId: this.kyc.applicantId,
    verifiedAt: this.kyc.verifiedAt || this.kyc.lastVerifiedAt,
    lastUpdated: this.kyc.lastUpdatedAt,
    reviewResult: this.kyc.frontendReview?.reviewAnswer || this.kyc.review?.result,
    hasToken: !!this.kyc.verificationToken && !this.kyc.verificationToken.used,
    tokenType: this.kyc.verificationToken?.tokenType || 'NONE',
    hasGreenToken: this.hasGreenToken, // Include GREEN token status
    metadata: this.kyc.metadata
  };
});

// Methods
userSchema.methods.matchPassword = async function(enteredPassword) {
  if (this.authMethod !== 'local') {
    throw new Error('This account uses social login');
  }
  return await bcrypt.compare(enteredPassword, this.password);
};

// 🟢 ENHANCED: Generate custom token specifically for GREEN verification
userSchema.methods.generateGreenVerificationToken = async function(additionalData = {}) {
  const crypto = require('crypto');
  
  // Generate sophisticated GREEN token
  const baseToken = crypto.randomBytes(32).toString('hex');
  const timestamp = Date.now().toString(36);
  const userHash = crypto.createHash('sha256').update(this._id.toString()).digest('hex').substring(0, 8);
  const securityHash = crypto.createHash('sha256').update(`${this._id}${this.email}${timestamp}`).digest('hex').substring(0, 16);
  
  const customToken = `GREEN_${timestamp}_${userHash}_${baseToken}`;
  const expiresAt = new Date(Date.now() + 90 * 24 * 60 * 60 * 1000); // 90 days
  
  this.kyc.verificationToken = {
    token: customToken,
    expiresAt,
    used: false,
    generatedFromFrontend: true,
    tokenType: 'GREEN_VERIFICATION',
    metadata: {
      generatedAt: new Date(),
      securityHash,
      verificationLevel: 'GREEN',
      ...additionalData
    }
  };
  
  // Track GREEN verification
  this.kyc.greenVerification = {
    verifiedAt: new Date(),
    tokenGenerated: true,
    reviewId: additionalData.reviewId,
    attemptId: additionalData.attemptId,
    levelName: additionalData.levelName
  };
  
  await this.save();
  return customToken;
};

userSchema.methods.verifyGreenToken = async function(token) {
  if (!this.kyc.verificationToken || 
      this.kyc.verificationToken.token !== token ||
      this.kyc.verificationToken.tokenType !== 'GREEN_VERIFICATION' ||
      this.kyc.verificationToken.expiresAt < new Date() ||
      this.kyc.verificationToken.used) {
    return false;
  }
  
  this.kyc.verificationToken.used = true;
  this.kyc.verificationToken.usedAt = new Date();
  await this.save();
  return true;
};

// Legacy method for backward compatibility
userSchema.methods.generateKYCToken = async function() {
  const token = require('crypto').randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + 90 * 24 * 60 * 60 * 1000);
  
  this.kyc.verificationToken = {
    token,
    expiresAt,
    used: false,
    tokenType: 'STANDARD'
  };
  
  await this.save();
  return token;
};

userSchema.methods.verifyKYCToken = async function(token) {
  if (!this.kyc.verificationToken || 
      this.kyc.verificationToken.token !== token ||
      this.kyc.verificationToken.expiresAt < new Date() ||
      this.kyc.verificationToken.used) {
    return false;
  }
  
  this.kyc.verificationToken.used = true;
  this.kyc.verificationToken.usedAt = new Date();
  await this.save();
  return true;
};

// Statics
userSchema.statics.findByKYCToken = async function(token) {
  return this.findOne({
    'kyc.verificationToken.token': token,
    'kyc.verificationToken.expiresAt': { $gt: new Date() },
    'kyc.verificationToken.used': false
  });
};

// 🟢 NEW: Find users with GREEN tokens
userSchema.statics.findByGreenToken = async function(token) {
  return this.findOne({
    'kyc.verificationToken.token': token,
    'kyc.verificationToken.tokenType': 'GREEN_VERIFICATION',
    'kyc.verificationToken.expiresAt': { $gt: new Date() },
    'kyc.verificationToken.used': false
  });
};

userSchema.statics.findByKYCStatus = async function(status) {
  return this.find({ 'kyc.status': status });
};

userSchema.statics.findVerifiedUsers = async function() {
  return this.find({ 
    isVerified: true,
    'kyc.status': 'verified'
  });
};

// 🟢 NEW: Find users with GREEN verification
userSchema.statics.findGreenVerifiedUsers = async function() {
  return this.find({
    isVerified: true,
    'kyc.status': 'verified',
    $or: [
      { 'kyc.frontendReview.reviewAnswer': 'GREEN' },
      { 'kyc.review.result': 'GREEN' }
    ]
  });
};

module.exports = mongoose.model('User', userSchema);