const express = require('express');
const { adminLogin, addUser, deleteUser, updateUser, getAllUsers } = require('../controllers/adminController');
const authMiddleware = require('../middleware/authMiddleware');
const router = express.Router();

// Admin login
router.post('/login', adminLogin);

// Quản lý tài khoản người dùng
router.post('/addUser', authMiddleware, addUser);
router.delete('/deleteUser/:id', authMiddleware, deleteUser);
router.put('/updateUser/:id', authMiddleware, updateUser);
router.get('/users', authMiddleware, getAllUsers);

module.exports = router;
