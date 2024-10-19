const User = require('../models/User');
const bcrypt = require('bcryptjs');

// Lấy danh sách tất cả người dùng
exports.getAllUsers = async (req, res) => {
    try {
        const users = await User.find();
        res.status(200).json(users);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

// Lấy thông tin người dùng theo ID
exports.getUserById = async (req, res) => {
    const { id } = req.params;
    try {
        const user = await User.findById(_id);
        if (!user) return res.status(404).json({ message: 'User not found' });
        res.status(200).json(user);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

// Tạo người dùng mới
exports.createUser = async (req, res) => {
    const { username, email, password, role } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = await User.create({
            username,
            email,
            password: hashedPassword,
            role,
        });
        res.status(201).json({ message: 'User created', user: newUser });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

// Cập nhật thông tin người dùng
exports.updateUser = async (req, res) => {
    const { id } = req.params;
    const { username, email, role } = req.body;

    try {
        const updatedUser = await User.findByIdAndUpdate(id, { username, email, role }, { new: true });
        if (!updatedUser) return res.status(404).json({ message: 'User not found' });
        res.status(200).json({ message: 'User updated', user: updatedUser });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

// Xóa người dùng
exports.deleteUser = async (req, res) => {
    const { id } = req.params;
    try {
        const deletedUser = await User.findByIdAndDelete(id);
        if (!deletedUser) return res.status(404).json({ message: 'User not found' });
        res.status(200).json({ message: 'User deleted' });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};
