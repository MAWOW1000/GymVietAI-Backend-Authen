import loginRegisterService from '../service/loginRegisterService';
import dotenv from 'dotenv';
import { v4 as uuidv4 } from 'uuid';
import { createJWT } from '../middleware/JWTAction';

dotenv.config();
const { google } = require('googleapis');

const testApi = (req, res) => {
    return res.status(200).json({
        message: 'ok',
        data: 'test api'
    })
}

const handleRegister = async (req, res) => {
    try {
        //req.body:  email, password, username
        if (!req.body.email || !req.body.password) {
            return res.status(200).json({
                EM: 'Missing required parameters', // error message
                EC: '1', //error code
                DT: '', //date
            })
        }
        // New validation for email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(req.body.email)) {
            return res.status(200).json({
                EM: 'Invalid email format', // error message
                EC: '1', //error code
                DT: '', //date
            })
        }
        // New validation for password strength using regex
        const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!#$%^&*()_+={}\[\]:;"'<>,.?~`-])[A-Za-z\d!#$%^&*()_+={}\[\]:;"'<>,.?~`-]{8,}$/;
        if (!passwordRegex.test(req.body.password)) {
            return res.status(200).json({
                EM: 'Your password must be at least 8 characters long, contain at least one uppercase letter, one lowercase letter, one number, and one special character.', // error message
                EC: '1', //error code
                DT: '', //date
            })
        }

        //service: create user
        let data = await loginRegisterService.registerNewUser(req.body)

        return res.status(200).json({
            EM: data.EM,
            EC: data.EC, //error code
            DT: '', //date
        })

    } catch (e) {
        return res.status(500).json({
            EM: 'error from server', // error message
            EC: '-1', //error code
            DT: '', //date
        })
    }
}

const handleGoogleLogin = async (req, res) => {
    const accessToken = req.body.accessToken; // Get accessToken from request body

    // Validate accessToken presence
    if (!accessToken) {
        return res.status(400).json({
            EM: 'Access token is required', // error message
            EC: '1', // error code
            DT: '', // date
        });
    }

    const oauth2Client = new google.auth.OAuth2(process.env.GOOGLE_CLIENT_ID, process.env.GOOGLE_CLIENT_SECRET);
    oauth2Client.setCredentials({ access_token: accessToken });

    const oauth2 = google.oauth2({
        auth: oauth2Client,
        version: 'v2',
    });
    try {
        const { data } = await oauth2.userinfo.get();
        // Check if user exists in the database
        let user = await loginRegisterService.checkEmailExist(data.email);
        if (!user) {
            // Create new user if they don't exist
            await loginRegisterService.upsertUserSocialMedia(data);
        }

        // Generate a new refresh token with expiration time
        const payload = {
            email: data.email,
        };
        const jwtAccessToken = createJWT(payload, { expiresIn: '1h' }); // Set access token to expire in 1 hour
        const refreshToken = uuidv4(); // Generate a new refresh token
        const refreshTokenExpiration = Date.now() + 7 * 24 * 60 * 60 * 1000; // 7 days

        // Set cookies for access token and refresh token
        res.cookie('access-token', jwtAccessToken, { maxAge: 3600000, httpOnly: true }); // 1 hour
        res.cookie('refresh-token', refreshToken);

        // Upsert refresh token and expiration
        await loginRegisterService.upsertRefreshToken(data.email, refreshToken, refreshTokenExpiration); // Pass expiration time

        return res.status(200).json({ // Send response
            EM: 'Login successful!',
            EC: 0,
            DT: data,
        });
    } catch (error) {
        console.log(error);
        return res.status(500).json({ // Send response
            EM: 'Error from server',
            EC: -1,
            DT: '',
        });
    }
}

const handleLogin = async (req, res) => {
    try {
        const { email, password } = req.body;

        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({
                EM: 'Invalid email format', // error message
                EC: '1', // error code
                DT: '', // date
            });
        }

        // Validate password strength
        const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&<>])[A-Za-z\d@$!%*?&<>]{8,}$/;
        if (!passwordRegex.test(password)) {
            return res.status(400).json({
                EM: 'Your password must be at least 8 characters long, contain at least one uppercase letter, one lowercase letter, one number, and one special character.', // error message
                EC: '1', // error code
                DT: '', // date
            });
        }

        // Handle normal login with email and password
        let data = await loginRegisterService.handleUserLogin(req.body);

        if (data.EC === 0) {
            const refreshToken = uuidv4();
            const refreshTokenExpiration = Date.now() + 7 * 24 * 60 * 60 * 1000; // 7 days
            await loginRegisterService.upsertRefreshToken(data.DT.email, refreshToken, refreshTokenExpiration); // Pass expiration time

            const payload = {
                email: data.DT.email,
                groupWithRoles: data.DT.groupWithRoles // Adjust based on your user data structure
            };
            const accessToken = createJWT(payload, { expiresIn: '1h' }); // Set access token to expire in 1 hour

            // Set cookies or send tokens in response
            res.cookie('access-token', accessToken, { maxAge: 3600000, httpOnly: true }); // 1 hour
            res.cookie('refresh-token', refreshToken);

            return res.status(200).json({
                EM: 'Login successful!',
                EC: 0,
                DT: {
                    access_token: accessToken,
                    refresh_token: refreshToken,
                    firstName: data.DT.firstName, // Include first name
                    lastName: data.DT.lastName, // Include last name
                    picture: data.DT.picture, // Include profile picture
                },
            });
        } else {
            return res.status(401).json({
                EM: data.EM,
                EC: data.EC,
                DT: '',
            });
        }

    } catch (error) {
        console.log(error);
        return res.status(500).json({
            EM: 'error from server', // error message
            EC: '-1', // error code
            DT: '', // date
        });
    }
}

const handleLogout = (req, res) => {
    try {
        // Clear cookies for access and refresh tokens
        res.clearCookie("access-token");
        res.clearCookie("refresh-token");

        // Optionally, you can also invalidate the refresh token in the database if needed
        // await loginRegisterService.invalidateRefreshToken(req.user.email); // Uncomment if you have such a function

        return res.status(200).json({
            EM: 'Logout successful! Cookies cleared.', // success message
            EC: 0, // success code
            DT: '', // data
        });

    } catch (error) {
        console.log(error);
        return res.status(500).json({
            EM: 'Error during logout process', // error message
            EC: '-1', // error code
            DT: '', // data
        });
    }
}

module.exports = {
    testApi, handleRegister, handleLogin, handleLogout, handleGoogleLogin
}