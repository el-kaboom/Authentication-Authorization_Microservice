const express = require('express');
const passport = require('passport');
const { registerUser, verifyOTP, loginUser, verifyLoginOTP, forgotPassword, resetPassword, changePassword } = require('../controllers/authController');
const authMiddleware = require('../middlewares/authMiddleware'); 

const router = express.Router();

// Auth Routes
router.post('/register', registerUser);
router.post('/verify-otp', verifyOTP);
router.post('/login', loginUser);
router.post('/verify-login-otp', verifyLoginOTP);

// Password Management Routes
router.post('/forgot-password', forgotPassword);
router.post('/reset-password', resetPassword);
router.post('/change-password', authMiddleware, changePassword);

router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
router.get(
  '/google/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => {
    const token = generateToken(req.user._id);
    res.redirect(`http://localhost:3000?token=${token}`);
  }
);

module.exports = router;
