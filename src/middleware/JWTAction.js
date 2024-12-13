
require("dotenv").config();
import jwt from "jsonwebtoken";
import { getGroupWithRoles } from '../service/JWTService'
import { v4 as uuidv4 } from 'uuid';
import db from '../models/index';

const nonSecurePaths = [ '/login', '/loginGoogle', '/register'];

const createJWT = (payload) => {
    let key = process.env.JWT_SECRET;
    let token = null;
    try {
        token = jwt.sign(payload, key, {
            expiresIn: process.env.JWT_EXPIRES_IN
        });
    } catch (err) {
        console.log(err)
    }
    return token;
}

const verifyToken = (token) => {
    let key = process.env.JWT_SECRET;
    let decoded = null;

    try {
        decoded = jwt.verify(token, key);
    } catch (err) {
        if (err.name === "TokenExpiredError") {
            return decoded = "TokenExpiredError";
        }
    }
    return decoded;
}

const checkUserJWT = async (req, res, next) => {
    if (nonSecurePaths.includes(req.path)) return next();
    let cookies = req.cookies;

    if ((cookies && cookies['access-token'])) {
        let token = cookies['access-token'];
        let decoded = verifyToken(token);
        if (decoded && decoded !== "TokenExpiredError") {
            decoded.access_token = cookies['access-token']
            decoded.refresh_token = cookies['refresh-token']
            req.user = decoded;
            next();
        }
        else if (decoded && decoded === "TokenExpiredError") {
            const refresh_token = cookies['refresh-token']
            const data = await updateCookies(refresh_token)
            if (data.token && data.refreshToken) {
                res.cookie('access-token', data.token,
                    { maxAge: 3000000, httpOnly: true }
                )
                res.cookie('refresh-token', data.refreshToken)
            }
            return res.status(433).json({
                EC: -1,
                DT: '',
                EM: 'Not authenticated the user'
            })
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


const updateCookies = async (refresh_token) => {
    try {
        let user = await db.User.findOne({
            where: { refreshToken: refresh_token }
        })
        if (user) {
            let groupWithRoles = await getGroupWithRoles(user);
            const payload = {
                email: user.email,
                username: user.username,
                groupWithRoles
            }
            const token = await createJWT(payload)
            const refreshToken = uuidv4();
            await user.update({
                refreshToken: refreshToken
            })
            return {
                token, refreshToken
            }
        } else {
            //not found
            return {
                EM: 'User not found',
                EC: 2,
                DT: ''
            }
        }
    } catch (e) {
        console.log(e);
        return {
            EM: 'something wrongs with servies',
            EC: 1,
            DT: []
        }
    }
}
module.exports = {
    createJWT, verifyToken, checkUserJWT, checkUserPermission
}