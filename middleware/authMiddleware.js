const jwt = require('jsonwebtoken');

exports.authMiddleware = (req, res, next) => {
    const authHeader = req.header('Authorization');
    if (!authHeader) return res.status(401).json({ message: 'Access denied. No token provided.' });

    const token = authHeader.split(' ')[1]; // Tách token từ chuỗi "Bearer <token>"
    
    if (!token) {
        return res.status(401).json({ message: 'Access denied. Token missing.' });
    }

    try {
        const verified = jwt.verify(token, process.env.JWT_SECRET); // Xác thực token
        req.user = verified; // Lưu thông tin user vào req.user
        next(); // Tiếp tục tới middleware hoặc route handler tiếp theo
    } catch (error) {
        console.error("Error verifying token:", error);
        res.status(400).json({ message: 'Invalid token' });
    }
};

exports.adminMiddleware = (req, res, next) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: 'Access denied' });
    next();
};
