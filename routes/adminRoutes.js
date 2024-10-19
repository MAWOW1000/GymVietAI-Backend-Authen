const express = require('express');
const { authMiddleware, adminMiddleware } = require('../middleware/authMiddleware');
const { getAllUsers, getUserById, createUser, updateUser, deleteUser } = require('../controllers/adminController');
const router = express.Router();

// CRUD cho Admin

router.get('/users', authMiddleware, adminMiddleware, getAllUsers);
router.get('/users/:id', authMiddleware, adminMiddleware, getUserById);
router.post('/users', authMiddleware, adminMiddleware, createUser);
router.put('/users/:id', authMiddleware, adminMiddleware, updateUser);
router.delete('/users/:id', authMiddleware, adminMiddleware, deleteUser);

module.exports = router;
