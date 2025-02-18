const express = require('express');
const passport = require('passport');
const { registerUser, verifyOTP, loginUser, verifyLoginOTP } = require('../controllers/authController');

const router = express.Router();

// Register user
router.post('/register', registerUser);

// OTP verification for registration
router.post('/verify-otp', verifyOTP);

// User login
router.post('/login', loginUser);

// OTP verification for login
router.post('/verify-login-otp', verifyLoginOTP);

// Google authentication routes
router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

router.get('/google/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => {
    const token = generateToken(req.user._id);
    res.redirect(`http://localhost:3000?token=${token}`); //redirect to client with jwt
  });

module.exports = router;
