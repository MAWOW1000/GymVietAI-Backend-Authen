const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { authenticateToken } = require('../middleware/auth');

router.post('/register', authController.register);
router.post('/login', authController.login);
router.post('/login-admin', authController.loginAdmin);
router.post('/forgot-password', authController.forgotPassword);
router.post('/reset-password', authController.resetPassword);
router.put('/update-profile', authenticateToken, authController.updateProfile);
router.get('/user', authenticateToken, authController.getUser);
router.get('/user/:id', authenticateToken, authController.getUserById);
router.get('/dashboard/stats', authenticateToken, authController.getDashboardStats);
router.get('/roles', authenticateToken, authController.getRoles);

// Upgrade user role
router.put('/upgrade-role', authController.upgradeUserRole);

module.exports = router;
