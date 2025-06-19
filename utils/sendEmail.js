const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  service: 'Gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

const sendEmail = async ({ to, subject, text, html }) => {
  try {
    await transporter.sendMail({
      from: `"pinovX Platform" <${process.env.EMAIL_USER}>`,
      to,
      subject,
      text,
      html,
    });
    console.log(`Email sent to ${to}`);
  } catch (error) {
    console.error('Error sending email:', error);
    throw error;
  }
};

// Email templates
const emailTemplates = {
  welcome: (user) => ({
    subject: 'Welcome to pinovX Platform!',
    text: `Hi ${user.firstName || user.fullName || 'User'}, welcome to our platform!`,
    html: `<h1>Welcome ${user.firstName || user.fullName || 'User'}!</h1><p>Thank you for joining our platform.</p>`
  }),
  login: (user) => ({
    subject: 'New Login Detected',
    text: `Hi ${user.firstName || user.fullName || 'User'}, we noticed a new login to your account.`,
    html: `<h1>New Login</h1><p>Your account was accessed at ${new Date().toLocaleString()}.</p>`
  }),
  passwordUpdate: (user) => ({
    subject: 'Password Changed Successfully',
    text: `Hi ${user.firstName || user.fullName || 'User'}, your password has been updated.`,
    html: `<h1>Password Updated</h1><p>Your password was changed at ${new Date().toLocaleString()}.</p>`
  }),
  passwordReset: (user) => ({
    subject: 'Password Reset Request',
    text: `Hi ${user.firstName || user.fullName || 'User'}, here's your password reset link.`,
    html: `<h1>Password Reset</h1><p>Please click the link to reset your password.</p>`
  }),
  adminNewUser: (admin, user) => ({
    subject: 'New User Registration',
    text: `Admin, a new user has registered: ${user.firstName || user.fullName || 'User'} (${user.email})`,
    html: `<h1>New User</h1><p>User ${user.firstName || user.fullName || 'User'} (${user.email}) registered at ${new Date().toLocaleString()}.</p>`
  }),
  adminPasswordReset: (admin, user) => ({
    subject: 'Password Reset Requested',
    text: `Admin, user ${user.firstName || user.fullName || 'User'} (${user.email}) requested a password reset.`,
    html: `<h1>Password Reset Request</h1><p>User ${user.firstName || user.fullName || 'User'} (${user.email}) requested a reset at ${new Date().toLocaleString()}.</p>`
  }),
  otpVerification: (user, otp) => ({
  subject: 'Verify Your Order with OTP',
  text: `Hi ${user.firstName || user.lastName || 'User'},\n\nYour OTP for verifying the order is: ${otp}\n\nThis OTP will expire in 10 minutes.`,
  html: `
    <h2>OTP Verification</h2>
    <p>Hi ${user.firstName || user.lastName || 'User'},</p>
    <p>Your OTP for verifying your order is: <strong>${otp}</strong></p>
    <p>This OTP will expire in <strong>10 minutes</strong>.</p>
  `
}),

adminOrderNotification: (user, order) => ({
  subject: '📥 New Order Received on pinovX Platform',
  text: `Admin,\n\nA new order has been placed by ${user.firstName} - ${user.lastName} (${user.email}).\n\nAmount: ${order.amountToSend} ${order.currencyToSend}\nReceiving: ${order.currencyToReceive} (${order.destinationCountry})\nMethod: ${order.transferMethod}\nPurpose: ${order.purpose || 'N/A'}\nNotes: ${order.notes || 'N/A'}`,
  html: `
    <h2>New Order Alert</h2>
    <p><strong>User:</strong> ${user.firstName} - ${user.lastName} (${user.email})</p>
    <p><strong>Amount:</strong> ${order.amountToSend} ${order.currencyToSend}</p>
    <p><strong>Receiving:</strong> ${order.currencyToReceive} (${order.destinationCountry})</p>
    <p><strong>Transfer Method:</strong> ${order.transferMethod}</p>
    <p><strong>Purpose:</strong> ${order.purpose || 'N/A'}</p>
    <p><strong>Notes:</strong> ${order.notes || 'N/A'}</p>
    <p>Submitted on: ${new Date().toLocaleString()}</p>
  `
})

};

module.exports = { sendEmail, emailTemplates };