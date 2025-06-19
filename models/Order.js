const mongoose = require('mongoose');
const { Schema } = mongoose;

const orderSchema = new Schema({
  userId: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  fullName: {
    type: String,
    required: true
  },
  email: {
    type: String,
    required: true
  },
  currencyToSend: {
    type: String,
    enum: ['CAD', 'AUD'],
    required: true
  },
  currencyToReceive: {
    type: String,
    required: true
  },
  amountToSend: {
    type: Number,
    required: true
  },
  destinationCountry: {
    type: String,
    default: ''
  },
  recipientName: {
    type: String,
    required: true
  },
  recipientAccount: {
    type: String,
    required: true
  },
  transferMethod: {
    type: String,
    enum: ['Bank Transfer', 'Mobile Money', 'Crypto Wallet'],
    required: true
  },
  purpose: {
    type: String,
    default: ''
  },
  notes: {
    type: String,
    default: ''
  },
  documentPath: {
    type: String,
    default: ''
  },
  status: {
    type: String,
    enum: ['pending', 'processing', 'completed', 'rejected'],
    default: 'pending'
  },
  otpVerified: {
    type: Boolean,
    default: false
  }
}, { timestamps: true });

module.exports = mongoose.model('Order', orderSchema);