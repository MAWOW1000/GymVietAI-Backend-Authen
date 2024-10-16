const User = require('../models/User');
const bcrypt = require('bcryptjs');

// Cập nhật thông tin người dùng
exports.updateProfile = async (req, res) => {
    const { username, email, password } = req.body;
    const userId = req.user.id;

    try {
        const updateData = {
            username,
            email,
        };

        // Nếu có mật khẩu mới, mã hóa nó
        if (password) {
            updateData.password = await bcrypt.hash(password, 10);
        }

        const updatedUser = await User.findByIdAndUpdate(userId, updateData, { new: true });
        res.status(200).json({ message: 'Profile updated', user: updatedUser });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};
