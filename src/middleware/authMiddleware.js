require("dotenv").config();
import jwt from "jsonwebtoken";
import { v4 as uuidv4 } from 'uuid';
import db from '../models/index';
import authService from '../service/authService';

const nonSecurePaths = ['/login', '/loginGoogle', '/register', '/sendOTP', '/resetPassword', '/logout'];

const checkUserJWT = async (req, res, next) => {
    try {
        if (nonSecurePaths.includes(req.path)) return next();

        const cookies = req.cookies;
        if (!cookies || !cookies['access-token'] || !cookies['refresh-token']) {
            return res.status(401).json({
                EC: -1,
                DT: '',
                EM: 'No authentication tokens found'
            });
        }

        const access_token = cookies['access-token'];
        const refresh_token = cookies['refresh-token'];
        const verifyResult = await authService.verifyToken(access_token, refresh_token);

        if (verifyResult.EC === 0) {
            // Token còn hạn
            return next();
        }

        if (verifyResult.EC === 1) {
            // Access token hết hạn nhưng refresh token còn hạn
            const newTokens = await authService.updateCookies(refresh_token);
            if (newTokens.EC === 0) {
                // Set cookie mới với access token mới
                res.cookie('access-token', newTokens.DT.access_token, {
                    maxAge: 3600000, // 1 hour
                    httpOnly: true
                });
                req.user = newTokens.DT.user;
                return next();
            }
        }

        // Chỉ xóa cookies khi cả access và refresh đều hết hạn
        if (verifyResult.EC === 3) {
            res.clearCookie('access-token');
            res.clearCookie('refresh-token');
            return res.status(401).json({
                EC: 3,
                DT: '',
                EM: 'Session expired. Please login again.'
            });
        }

        // Các trường hợp lỗi khác không xóa cookie
        return res.status(401).json({
            EC: -1,
            DT: '',
            EM: verifyResult.EM || 'Authentication failed'
        });

    } catch (error) {
        console.error('Authentication error:', error);
        return res.status(500).json({
            EC: -1,
            DT: '',
            EM: 'Internal server error during authentication'
        });
    }
};

const checkUserPermission = (req, res, next) => {
    if (nonSecurePaths.includes(req.path)) return next();

    if (req.user) {
        let email = req.user.email;
        let roles = req.user.groupWithRoles.Roles;
        let currentUrl = req.path;
        if (!roles || roles.length === 0) {
            return res.status(403).json({
                EC: -1,
                DT: '',
                EM: `you don't permission to access this resource...`
            })
        }

        let canAccess = roles.some(item => item.url === currentUrl || currentUrl.includes(item.url));
        if (canAccess === true) {
            next();
        } else {
            return res.status(403).json({
                EC: -1,
                DT: '',
                EM: `you don't permission to access this resource...`
            })
        }
    } else {
        return res.status(401).json({
            EC: -1,
            DT: '',
            EM: 'Not authenticated the user'
        })
    }
}

const verifyJWT = async (req, res, next) => {
    try {
        // Get token from header or cookie
        const token = req.headers.authorization?.split(' ')[1] ||
            req.cookies['access-token'];

        if (!token) {
            return res.status(401).json({
                EM: 'No token provided',
                EC: 1,
                DT: null
            });
        }

        // Verify token
        const verified = authService.verifyToken(token);
        if (verified.EC !== 0) {
            return res.status(401).json({
                EM: verified.EM,
                EC: verified.EC,
                DT: null
            });
        }

        // Add user data to request
        req.user = verified.DT;
        next();
    } catch (error) {
        console.error('JWT Verification Error:', error);
        return res.status(500).json({
            EM: 'Internal server error',
            EC: -1,
            DT: null
        });
    }
};

module.exports = {
    checkUserJWT, checkUserPermission, verifyJWT
}