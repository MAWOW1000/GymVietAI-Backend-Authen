const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const Admin = require('./models/Admin');
const dotenv = require('dotenv');

// Load biến môi trường
dotenv.config();

// Kết nối đến cơ sở dữ liệu
mongoose.connect(process.env.MONGODB_URI)
    .then(async () => {
        console.log('MongoDB connected...');

        // Tên ban đầu
        let username = 'admin';

        // Hàm kiểm tra và tìm username mới nếu trùng lặp
        let suffix = 1;
        while (await Admin.findOne({ username })) {
            username = `admin${suffix}`;
            suffix++;
        }

        // Mã hóa mật khẩu
        const hashedPassword = await bcrypt.hash('Admin123@', 10);

        // Tạo admin mới với username mới
        const admin = new Admin({
            username: username,
            password: hashedPassword,
        });

        await admin.save();
        console.log(`Admin created with username: ${username}`);
        process.exit();
    })
    .catch(err => {
        console.error(err);
        process.exit(1);
    });
