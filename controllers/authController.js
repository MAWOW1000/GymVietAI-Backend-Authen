const User = require('../models/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');

// Đăng ký
exports.register = async (req, res) => {
    try {
        const { username, email, password } = req.body;

        // Kiểm tra xem người dùng đã tồn tại chưa (theo email và username)
        let userByEmail = await User.findOne({ email });
        if (userByEmail) {
            return res.status(400).json({ message: 'Email already exists' });
        }

        let userByUsername = await User.findOne({ username });
        if (userByUsername) {
            return res.status(400).json({ message: 'Username already exists' });
        }

        // Tạo người dùng mới
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ username, email, password: hashedPassword });
        await user.save();


        // Tạo token
        const token = jwt.sign(
            {
                id: user._id,
                username: user.username,
                email: user.email,
                role: user.role
            },
            process.env.JWT_SECRET,
            { expiresIn: '2h' }
        );

        // Gửi token về client
        res.json({ token });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
};

// Đăng nhập
exports.login = async (req, res) => {
    try {
        const { email, password } = req.body;
        
        // Tìm người dùng trong cơ sở dữ liệu
        const user = await User.findOne({ email });
        
        console.log('User found:', user); // Ghi log thông tin người dùng
        
        if (!user) {
            return res.status(400).json({ message: 'Wrong email or password' });
        }

        // Kiểm tra mật khẩu
        const isMatch = await bcrypt.compare(password, user.password); // So sánh mật khẩu

        if (!isMatch) {
            return res.status(400).json({ message: 'Wrong email or password' });
        }

        // Tạo token nếu tất cả đều đúng
        const token = jwt.sign(
            { id: user._id, username: user.username, email: user.email, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: '2h' }
        );

        // Gửi token về client
        res.json({ token });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
};

// Đăng xuất
exports.logout = (req, res) => {
    // Đơn giản trả về thông báo đăng xuất
    res.json({ message: 'Logged out' });
};

// Quên mật khẩu
exports.forgotPassword = async (req, res) => {
    try {
        const { email } = req.body;

        // Tìm người dùng qua email
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Tạo token đặt lại mật khẩu
        const resetToken = jwt.sign(
            { id: user._id },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        // Tạo đường dẫn để người dùng đặt lại mật khẩu
        const resetUrl = `http://localhost:3000/reset-password/${resetToken}`;

        // Cấu hình dịch vụ gửi email
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.EMAIL_USER,  // Địa chỉ email gửi đi
                pass: process.env.EMAIL_PASS   // Mật khẩu ứng dụng hoặc API key
            }
        });

        // Thiết lập nội dung email
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Password Reset Request',
            text: `You requested a password reset. Click this link to reset your password: ${resetUrl}`,
            html: `<p>You requested a password reset. Click this <a href="${resetUrl}">link</a> to reset your password.</p>`
        };

        // Gửi email
        await transporter.sendMail(mailOptions);

        res.json({ message: 'Password reset email sent' });
    } catch (error) {
        console.error('Error sending email:', error);
        res.status(500).json({ message: 'Error sending email' });
    }
};

// Đặt lại mật khẩu
exports.resetPassword = async (req, res) => {
    try {
        const { token } = req.params;  // Lấy token từ URL
        const { newPassword } = req.body;  // Mật khẩu mới từ người dùng

        // Giải mã token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const userId = decoded.id;

        // Tìm người dùng theo ID từ token
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Mã hóa mật khẩu mới
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        // Cập nhật mật khẩu mới
        user.password = hashedPassword;
        await user.save();

        res.json({ message: 'Password has been reset successfully' });
    } catch (error) {
        console.error('Error resetting password:', error);
        if (error.name === 'TokenExpiredError') {
            return res.status(400).json({ message: 'Token has expired' });
        }
        res.status(500).json({ message: 'Server error' });
    }
};
