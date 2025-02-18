const User = require('../models/userModel');
const generateToken = require('../utils/generateToken');
const bcrypt = require('bcryptjs');
const { sendOTP } = require('../utils/sendOTP');

let otpStore = {};

exports.registerUser = async (req, res) => {
  try {
    const { username, email, password } = req.body;
    const userExists = await User.findOne({ email });
    if (userExists) return res.status(400).json({ message: 'User already exists' });

    const newUser = new User({ username, email, password });
    await newUser.save();

    const otp = generateOTP();
    otpStore[email] = { otp, expiry: Date.now() + process.env.OTP_EXPIRATION };

    await sendOTP(email, otp);
    res.status(201).json({ message: 'Registration successful. OTP sent to email.' });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
};

// Verify OTP during registration
exports.verifyOTP = async(req, res) => {
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

// Login User with OTP
exports.loginUser = async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'User not found' });

    const isMatch = await user.comparePassword(password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

    // Generate OTP and send via email
    const otp = generateOTP();
    otpStore[email] = { otp, expiry: Date.now() + process.env.OTP_EXPIRATION };

    await sendOTP(email, otp);
    res.json({ message: 'Login successful. OTP sent to email.' });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
};

// Verify OTP during login
exports.verifyLoginOTP = async(req, res) => {
  const { email, otp } = req.body;

  if (!otpStore[email]) return res.status(400).json({ message: 'OTP not sent' });

  const storedOtp = otpStore[email];
  if (Date.now() > storedOtp.expiry) {
    delete otpStore[email]; // OTP expired
    return res.status(400).json({ message: 'OTP has expired, please request a new one' });
  }

  if (storedOtp.otp !== otp) {
    return res.status(400).json({ message: 'Invalid OTP' });
  }

  // OTP is validation
  const user = await User.findOne({ email });
  const token = generateToken(user._id);
  delete otpStore[email]; // Remove OTP after verification
  res.json({ token });
};
