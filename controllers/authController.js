const User = require('../models/userModel');
const { generateToken } = require('../utils/generateToken');
const bcrypt = require('bcryptjs');
const { sendOTP } = require('../utils/sendOTP');

let otpStore = {};

// Register User
exports.registerUser = async (req, res) => {
  try {
    const { username, email, password } = req.body;
    const userExists = await User.findOne({ email });
    if (userExists) return res.status(400).json({ message: 'User already exists' });

    const newUser = new User({ username, email, password });
    await newUser.save();

    const otp = Math.floor(100000 + Math.random() * 900000).toString(); // Generate 6-digit OTP
    otpStore[email] = { otp, expiry: Date.now() + 10 * 60 * 1000 }; // OTP expires in 10 minutes

    await sendOTP(email, otp);
    res.status(201).json({ message: 'Registration successful. OTP sent to email.' });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error });
  }
};

// Verify OTP during registration
exports.verifyOTP = async (req, res) => {
  const { email, otp } = req.body;

  if (!otpStore[email]) return res.status(400).json({ message: 'OTP not sent' });

  const storedOtp = otpStore[email];
  if (Date.now() > storedOtp.expiry) {
    delete otpStore[email];
    return res.status(400).json({ message: 'OTP has expired, please request a new one' });
  }

  if (storedOtp.otp !== otp) {
    return res.status(400).json({ message: 'Invalid OTP' });
  }

  const user = await User.findOne({ email });
  const token = generateToken(user._id);
  delete otpStore[email];
  res.json({ token });
};

// Login User
exports.loginUser = async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'User not found' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

    // Generate OTP and send via email
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    otpStore[email] = { otp, expiry: Date.now() + 10 * 60 * 1000 };

    await sendOTP(email, otp);
    res.json({ message: 'Login successful. OTP sent to email.' });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error });
  }
};

// Verify OTP during login
exports.verifyLoginOTP = async (req, res) => {
  const { email, otp } = req.body;

  if (!otpStore[email]) return res.status(400).json({ message: 'OTP not sent' });

  const storedOtp = otpStore[email];
  if (Date.now() > storedOtp.expiry) {
    delete otpStore[email];
    return res.status(400).json({ message: 'OTP has expired, please request a new one' });
  }

  if (storedOtp.otp !== otp) {
    return res.status(400).json({ message: 'Invalid OTP' });
  }

  const user = await User.findOne({ email });
  const token = generateToken(user._id);
  delete otpStore[email];
  res.json({ token });
};

// Forgot Password - Send OTP
exports.forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'User not found' });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    otpStore[email] = { otp, expiry: Date.now() + 10 * 60 * 1000 };

    await sendOTP(email, otp);
    res.status(200).json({ message: 'OTP sent to email for password reset' });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error });
  }
};

// Reset Password - Verify OTP and Set New Password
exports.resetPassword = async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;

    if (!otpStore[email]) return res.status(400).json({ message: 'OTP not sent' });

    const storedOtp = otpStore[email];
    if (Date.now() > storedOtp.expiry) {
      delete otpStore[email];
      return res.status(400).json({ message: 'OTP has expired, please request a new one' });
    }

    if (storedOtp.otp !== otp) {
      return res.status(400).json({ message: 'Invalid OTP' });
    }

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'User not found' });

    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(newPassword, salt);
    await user.save();

    delete otpStore[email];
    res.status(200).json({ message: 'Password reset successful' });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error });
  }
};

// Change Password - Authenticated Users
exports.changePassword = async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;
    const user = await User.findById(req.user._id);
    if (!user) return res.status(404).json({ message: 'User not found' });

    const isMatch = await bcrypt.compare(oldPassword, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Incorrect old password' });

    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(newPassword, salt);
    await user.save();

    res.status(200).json({ message: 'Password changed successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error });
  }
};
