require("dotenv").config();
import jwt from "jsonwebtoken";
import { v4 as uuidv4 } from 'uuid';
import db from '../models/index';
import authService from '../service/authService';

const nonSecurePaths = ['/login', '/loginGoogle', '/register', '/sendOTP', '/resetPassword', '/logout'];

const checkUserJWT = async (req, res, next) => {
    if (nonSecurePaths.includes(req.path)) return next();
    let cookies = req.cookies;

    if ((cookies && cookies['access-token'] && cookies['refresh-token'])) {
        let access_token = cookies['access-token'];
        let refresh_token = cookies['refresh-token'];
        let decoded = authService.verifyToken(access_token, refresh_token);
        if (decoded?.EC === 0) {
            next();
        }
        else if (decoded.EC === 1) {
            const data = await updateCookies(refresh_token)
            if (data.EC === 0) {
                res.cookie('access-token', data.DT.access_token,
                    { maxAge: process.env.JWT_EXPIRES_IN, httpOnly: true }
                )
                res.cookie('refresh-token', data.DT.refresh_token, {
                    maxAge: process.env.REFRESH_TOKEN_EXPIRES_IN, httpOnly: true
                })
            }
            else {
                return res.status(433).json({
                    EC: -1,
                    DT: '',
                    EM: 'Not authenticated the user'
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
    else {
        return res.status(401).json({
            EC: -1,
            DT: '',
            EM: 'Not authenticated the user'
        })
    }
}

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