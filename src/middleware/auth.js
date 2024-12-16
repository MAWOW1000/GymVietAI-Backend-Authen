const jwt = require('jsonwebtoken');
const db = require('../config/database');

const authenticateToken = async (req, res, next) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];

        if (!token) {
            return res.status(401).json({ message: 'No token provided' });
        }

        // Verify token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        // Check if user exists and is active
        const [users] = await db.query(
            'SELECT id, email, role_id FROM users WHERE id = ? AND is_active = true',
            [decoded.id]
        );

        if (users.length === 0) {
            return res.status(401).json({ message: 'Invalid token - User not found or inactive' });
        }

        // Add user info to request
        req.user = {
            id: users[0].id,
            email: users[0].email,
            role: users[0].role_id
        };

        next();
    } catch (error) {
        console.error('Authentication error:', error);
        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({ message: 'Invalid token' });
        }
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ message: 'Token expired' });
        }
        res.status(500).json({ message: 'Internal server error' });
    }
};

const isAdmin = (req, res, next) => {
    if (req.user && req.user.role === 1) {
        next();
    } else {
        res.status(403).json({ message: 'Access denied - Admin only' });
    }
};

module.exports = {
    authenticateToken,
    isAdmin
};
