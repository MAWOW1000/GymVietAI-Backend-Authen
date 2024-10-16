const express = require('express');
const { authMiddleware } = require('../middleware/authMiddleware');
const { updateProfile } = require('../controllers/userController');
const router = express.Router();

// CRUD cho User
router.get('/profile', authMiddleware, (req, res) => {
    res.json(req.user);
});

// Cập nhật thông tin người dùng
router.put('/profile', authMiddleware, updateProfile);

module.exports = router;
