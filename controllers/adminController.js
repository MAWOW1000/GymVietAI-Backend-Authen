const Admin = require('../models/Admin');
const User = require('../models/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Đăng nhập admin
exports.adminLogin = async (req, res) => {
    const { username, password } = req.body;

    // Kiểm tra admin có tồn tại không
    const admin = await Admin.findOne({ username });
    if (!admin) return res.status(404).json({ message: 'Admin không tồn tại!' });

    // So sánh mật khẩu
    const isMatch = await bcrypt.compare(password, admin.password);
    if (!isMatch) return res.status(400).json({ message: 'Mật khẩu không đúng!' });

    // Tạo JWT cho admin
    const token = jwt.sign({ id: admin._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.status(200).json({ token, admin });
};

// Thêm người dùng mới
exports.addUser = async (req, res) => {
    const { name, phone, email, password, birthday, weight, height } = req.body;

    // Kiểm tra người dùng đã tồn tại chưa
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: 'Người dùng đã tồn tại!' });

    // Mã hóa mật khẩu người dùng
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
    res.status(201).json({ message: 'Thêm người dùng thành công!' });
};

// Xóa người dùng
exports.deleteUser = async (req, res) => {
    const { id } = req.params;

    const user = await User.findById(id);
    if (!user) return res.status(404).json({ message: 'Người dùng không tồn tại!' });

    await User.findByIdAndDelete(id);
    res.status(200).json({ message: 'Xóa người dùng thành công!' });
};

// Cập nhật thông tin người dùng
exports.updateUser = async (req, res) => {
    const { id } = req.params;
    const { name, phone, email, birthday, weight, height } = req.body;

    const user = await User.findByIdAndUpdate(id, { name, phone, email, birthday, weight, height }, { new: true });
    if (!user) return res.status(404).json({ message: 'Người dùng không tồn tại!' });

    res.status(200).json({ message: 'Cập nhật thông tin thành công!', user });
};

// Lấy danh sách người dùng
exports.getAllUsers = async (req, res) => {
    const users = await User.find().select('-password');
    res.status(200).json(users);
};
