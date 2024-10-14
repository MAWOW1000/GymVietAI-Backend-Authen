const express = require('express');
const { registerUser, loginUser, getUserProfile, updateUserProfile, recoverPassword } = require('../controllers/userController');
const router = express.Router();

router.post('/register', registerUser);
router.post('/login', loginUser);
router.get('/profile', getUserProfile);
router.put('/profile', updateUserProfile);
router.post('/recover', recoverPassword);

module.exports = router;
