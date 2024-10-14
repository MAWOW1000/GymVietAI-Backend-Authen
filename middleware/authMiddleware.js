const jwt = require('jsonwebtoken');

const authMiddleware = (req, res, next) => {
    const token = req.headers.authorization;

    // Kiểm tra xem token có tồn tại không
    if (!token) {
        return res.status(401).json({ message: 'No token, authorization denied' });
    }

    // Tách token từ header
    const bearer = token.split(' ');
    if (bearer.length !== 2 || bearer[0] !== 'Bearer') {
        return res.status(401).json({ message: 'Token format is invalid' });
    }

    const jwtToken = bearer[1];

    // Xác thực token
    jwt.verify(jwtToken, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Token is not valid' });
        }
        req.user = user; // Gán thông tin người dùng vào request
        next();
    });
};

module.exports = authMiddleware;
