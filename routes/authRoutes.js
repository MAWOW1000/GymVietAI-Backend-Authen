const express = require('express');
const { register, login, logout, forgotPassword } = require('../controllers/authController');
const router = express.Router();
const authController = require('../controllers/authController');
router.post('/register', register);
router.post('/login', login);
router.post('/logout', logout);
router.post('/forgot-password', authController.forgotPassword);
router.post('/reset-password/:token', authController.resetPassword);

module.exports = router;
