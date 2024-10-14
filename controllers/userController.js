const User = require('../models/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Đăng ký người dùng
exports.registerUser = async (req, res) => {
    const { name, phone, email, password, birthday, weight, height } = req.body;
    
    // Kiểm tra xem người dùng đã tồn tại
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: 'Người dùng đã tồn tại!' });

    // Mã hóa mật khẩu
    const hashedPassword = await bcrypt.hash(password, 10);

    // Tạo người dùng mới
    const user = new User({
        name,
        phone,
        email,
        password: hashedPassword,
        birthday,
        weight,
        height,
    });

    await user.save();
    res.status(201).json({ message: 'Đăng ký thành công!' });
};

// Đăng nhập người dùng
exports.loginUser = async (req, res) => {
    const { email, password } = req.body;
    
    // Tìm người dùng
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'Người dùng không tồn tại!' });

    // Kiểm tra mật khẩu
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Mật khẩu không đúng!' });

    // Tạo JWT
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.status(200).json({ token, user });
};

// Xem hồ sơ người dùng
exports.getUserProfile = async (req, res) => {
    const user = await User.findById(req.user.id).select('-password');
    res.status(200).json(user);
};

// Cập nhật hồ sơ người dùng
exports.updateUserProfile = async (req, res) => {
    const { name, phone, email, birthday, weight, height } = req.body;

    const user = await User.findByIdAndUpdate(req.user.id, { name, phone, email, birthday, weight, height }, { new: true });
    res.status(200).json(user);
};

// Khôi phục mật khẩu
exports.recoverPassword = async (req, res) => {
    // Logic khôi phục mật khẩu (ví dụ: gửi email)
    res.status(200).json({ message: 'Khôi phục mật khẩu thành công!' });
};
