import authService from '../service/authService';
import dotenv from 'dotenv';
import { v4 as uuidv4 } from 'uuid';
import { google } from 'googleapis';
import nodemailer from "nodemailer";
import { EXPIRATION_TIME_OFFSET } from 'google-auth-library/build/src/auth/baseexternalclient';

dotenv.config();

const testApi = (req, res) => {
    return res.status(200).json({
        message: 'ok',
        data: 'test api'
    });
};

const handleValidateUser = async (req, res) => {
    console.log('validated user');
    return res.status(200).json({
        EC: 0,
        EM: 'Success',
        DT: ''
    })
}

const handleRegister = async (req, res) => {
    try {
        if (!req.body.email || !req.body.password || !req.body.otp) {
            return res.status(400).json({
                EM: 'Missing required parameters (email, password, or OTP)',
                EC: '1',
                DT: null
            });
        }

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(req.body.email)) {
            return res.status(400).json({
                EM: 'Invalid email format',
                EC: '1',
                DT: null
            });
        }

        const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!#$%^&*()_+={}\[\]:;"'<>,.?~`-])[A-Za-z\d!#$%^&*()_+={}\[\]:;"'<>,.?~`-]{8,}$/;
        if (!passwordRegex.test(req.body.password)) {
            return res.status(400).json({
                EM: 'Password must be at least 8 characters long, contain uppercase, lowercase, number, and special character',
                EC: '1',
                DT: null
            });
        }

        // Stricter OTP validation
        if (!req.body.otp || typeof req.body.otp !== 'string' || !/^[0-9]{6}$/.test(req.body.otp)) {
            return res.status(400).json({
                EM: 'OTP must be a string containing exactly 6 digits',
                EC: '1',
                DT: null
            });
        }

        const data = await authService.registerNewUser({
            email: req.body.email,
            password: req.body.password,
            otp: req.body.otp
        });

        return res.status(data.EC === 0 ? 200 : 400).json({
            EM: data.EM,
            EC: data.EC,
            DT: data.DT
        });
    } catch (e) {
        console.error('Registration error:', e);
        return res.status(500).json({
            EM: 'Error from server',
            EC: '-1',
            DT: null
        });
    }
};

const handleGoogleLogin = async (req, res) => {
    try {
        // Input validation
        const { accessToken } = req.body;
        if (!accessToken) {
            return res.status(400).json({
                EM: 'Access token is required',
                EC: '1',
                DT: null
            });
        }

        // Initialize Google OAuth client
        const oauth2Client = new google.auth.OAuth2(
            process.env.GOOGLE_CLIENT_ID,
            process.env.GOOGLE_CLIENT_SECRET
        );
        oauth2Client.setCredentials({ access_token: accessToken });

        const oauth2 = google.oauth2({
            auth: oauth2Client,
            version: 'v2',
        });

        // Get user info from Google
        const { data } = await oauth2.userinfo.get();
        if (!data || !data.email) {
            return res.status(400).json({
                EM: 'Invalid Google account data',
                EC: '1',
                DT: null
            });
        }

        // Create or update user in database
        const userSocialMedia = await authService.upsertUserSocialMedia(data);
        if (userSocialMedia.EC !== 0) {
            return {
                EM: userSocialMedia.EM,
                EC: userSocialMedia.EC,
                DT: userSocialMedia.DT
            }
        }

        // Generate tokens
        const payload = {
            email: data.email,
        };
        const jwtAccessToken = await authService.createJWT(payload);
        if (jwtAccessToken.EC !== 0) {
            return {
                EM: jwtAccessToken.EM,
                EC: jwtAccessToken.EC,
                DT: jwtAccessToken.DT
            }
        }
        const refreshToken = uuidv4();
        const refreshTokenExpiration = new Date(Date.now() + parseInt(process.env.REFRESH_TOKEN_EXPIRES_IN));

        // Save refresh token
        const uuidRefreshToken = await authService.upsertRefreshToken(data.email, refreshToken, refreshTokenExpiration);
        if (uuidRefreshToken.EC !== 0) {
            return {
                EM: uuidRefreshToken.EM,
                EC: uuidRefreshToken.EC,
                DT: uuidRefreshToken.DT
            }
        }

        // Set cookies
        res.cookie('access-token', jwtAccessToken.DT, {
            maxAge: parseInt(process.env.JWT_EXPIRES_IN), // Convert to milliseconds
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production'
        });
        res.cookie('refresh-token', uuidRefreshToken.DT, {
            maxAge: parseInt(process.env.REFRESH_TOKEN_EXPIRES_IN), // Already in milliseconds
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production'
        });

        // Return success response
        return res.status(200).json({
            EM: 'Login successful!',
            EC: 0,
            DT: {
                access_token: jwtAccessToken.DT,
                refresh_token: uuidRefreshToken.DT,
                email: userSocialMedia.DT.email,
                firstName: userSocialMedia.DT.firstName,
                lastName: userSocialMedia.DT.lastName,
                picture: userSocialMedia.DT.picture,
                role: userSocialMedia.DT.role,
            }
        });
    } catch (error) {
        console.error('Google login error:', error);
        return res.status(500).json({
            EM: 'Error from server',
            EC: -1,
            DT: null
        });
    }
};

const handleLogin = async (req, res) => {
    try {
        const { email, password } = req.body;

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({
                EM: 'Invalid email format',
                EC: '1',
                DT: null
            });
        }

        const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&<>])[A-Za-z\d@$!%*?&<>]{8,}$/;
        if (!passwordRegex.test(password)) {
            return res.status(400).json({
                EM: 'Password must be at least 8 characters long, contain uppercase, lowercase, number, and special character',
                EC: '1',
                DT: null
            });
        }

        let data = await authService.handleUserLogin(req.body);

        if (data.EC === 0) {
            const payload = {
                email: data.DT.email,
            };
            const jwtAccessToken = await authService.createJWT(payload);
            if (jwtAccessToken.EC !== 0) {
                return {
                    EM: jwtAccessToken.EM,
                    EC: jwtAccessToken.EC,
                    DT: jwtAccessToken.DT
                }
            }

            const refreshToken = uuidv4();
            const refreshTokenExpiration = new Date(Date.now() + parseInt(process.env.REFRESH_TOKEN_EXPIRES_IN));

            const uuidRefreshToken = await authService.upsertRefreshToken(data.DT.email, refreshToken, refreshTokenExpiration);
            if (uuidRefreshToken.EC !== 0) {
                return {
                    EM: uuidRefreshToken.EM,
                    EC: uuidRefreshToken.EC,
                    DT: uuidRefreshToken.DT
                }
            }

            // Set cookies
            res.cookie('access-token', jwtAccessToken.DT, {
                maxAge: parseInt(process.env.JWT_EXPIRES_IN), // Convert to milliseconds
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production'
            });
            res.cookie('refresh-token', uuidRefreshToken.DT, {
                maxAge: parseInt(process.env.REFRESH_TOKEN_EXPIRES_IN), // Already in milliseconds
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production'
            });

            // Fixed response data using data.DT instead of userSocialMedia
            return res.status(200).json({
                EM: 'Login successful!',
                EC: 0,
                DT: {
                    access_token: jwtAccessToken.DT,
                    refresh_token: uuidRefreshToken.DT,
                    email: data.DT.email,
                    firstName: data.DT.firstName,
                    lastName: data.DT.lastName,
                    picture: data.DT.picture,
                    role: data.DT.role,
                }
            });
        } else {
            return res.status(401).json({
                EM: data.EM,
                EC: data.EC,
                DT: null
            });
        }
    } catch (error) {
        console.log(error);
        return res.status(500).json({
            EM: 'Error from server',
            EC: -1,
            DT: null
        });
    }
};

const handleLogout = async (req, res) => {
    try {
        res.clearCookie("access-token");
        res.clearCookie("refresh-token");

        return res.status(200).json({
            EM: 'Logout successful! Cookies cleared.',
            EC: 0,
            DT: null
        });
    } catch (error) {
        console.log(error);
        return res.status(500).json({
            EM: 'Error during logout process',
            EC: '-1',
            DT: null
        });
    }
};

const handleVerifyToken = async (req, res) => {
    try {
        const ssoToken = req.body.ssoToken;
        const refreshToken = uuidv4();
        const payload = {
            email: req.user.email,
            username: req.user.username,
        };
        const token = authService.createJWT(payload);
        const reqDefault = {
            jwt: token,
            refreshToken,
            email: req.user.email,
            username: req.user.username,
        };
        await updateRefreshToken(payload.email, refreshToken);
        req.user.access_token = token;
        req.session.destroy((err) => {
            req.logout();
        });
        if (req.user && req.user.code1 && req.user.code1 === ssoToken) {
            res.cookie('access-token', token, { maxAge: 3000000, httpOnly: true });
            res.cookie('refresh-token', refreshToken);
            return res.status(200).json({
                EC: 0,
                EM: 'Success',
                DT: reqDefault
            });
        } else {
            return res.status(401).json({
                EC: 1,
                EM: 'Limit session or session invalid',
                DT: null
            });
        }
    } catch (err) {
        return res.status(500).json({
            EC: -1,
            EM: 'Internal server error',
            DT: null
        });
    }
};

const hanleResendCode = async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) {
            return res.status(400).json({
                EM: 'Email is required',
                EC: 1,
                DT: null
            });
        }

        // Generate OTP as string of 6 digits
        const OTP = Array.from({ length: 6 }, () => Math.floor(Math.random() * 10)).join('');

        // Verify OTP format
        if (!/^[0-9]{6}$/.test(OTP)) {
            throw new Error('Generated OTP format is invalid');
        }

        // Save OTP to database
        const saveResult = await authService.saveResetPasswordCode(email, OTP);
        if (saveResult.EC !== 0) {
            return res.status(400).json({
                EM: saveResult.EM,
                EC: saveResult.EC,
                DT: saveResult.DT
            });
        }

        // Updated transporter configuration
        const transporter = nodemailer.createTransport({
            host: 'smtp.gmail.com',
            port: 587,
            secure: false, // Changed to false for TLS
            requireTLS: true, // Require TLS
            auth: {
                user: process.env.GOOGLE_APP_USER,
                pass: process.env.GOOGLE_APP_PASSWORD
            },
            tls: {
                minVersion: 'TLSv1.2',
                ciphers: 'HIGH:MEDIUM:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA'
            }
        });

        const mailOptions = {
            from: `"GymVietAI Platform" <${process.env.GOOGLE_APP_USER}>`,
            to: email,
            subject: "Your OTP Code from GymVietAI ",
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #f9f9f9;">
                    <div style="text-align: center; margin-bottom: 20px;">
                        <h1 style="color: #2C3E50; margin: 0;">GymVietAI</h1>
                        <p style="color: #7F8C8D; margin: 5px 0;">Your AI-Powered Fitness Partner</p>
                    </div>
                    
                    <div style="background-color: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 5px rgba(0,0,0,0.1);">
                        <h2 style="color: #2C3E50; margin-top: 0;">OTP Code Request</h2>
                        <p style="color: #34495E;">Hello,</p>
                        <p style="color: #34495E;">We received a request to send you an OTP code to register your GymVietAI account. Here's your OTP code:</p>
                        
                        <div style="background-color: #f8f9fa; padding: 15px; margin: 20px 0; border-radius: 5px; text-align: center;">
                            <span style="font-size: 24px; font-weight: bold; color: #2C3E50; letter-spacing: 3px;">${OTP}</span>
                        </div>
                        
                        <p style="color: #34495E;">This code will be deleted after used. If you didn't request this reset, please ignore this email.</p>
                        
                        <p style="color: #34495E; margin-top: 20px;">Best regards,<br>The GymVietAI Team</p>
                    </div>
                    
                    <div style="text-align: center; margin-top: 20px; color: #7F8C8D; font-size: 12px;">
                        <p>This is an automated message, please do not reply directly to this email.</p>
                        <p>© ${new Date().getFullYear()} GymVietAI. All rights reserved.</p>
                    </div>
                </div>
            `
        };

        await transporter.sendMail(mailOptions);

        return res.status(200).json({
            EM: 'OTP sent successfully',
            EC: 0,
            DT: null
        });
    } catch (err) {
        console.error('Reset password error details:', err);
        return res.status(500).json({
            EM: 'Failed to send email: ' + err.message,
            EC: -1,
            DT: process.env.NODE_ENV === 'development' ? err.stack : null
        });
    }
};

const handleResetPassword = async (req, res) => {
    try {
        const { email, otp, newPassword } = req.body;

        // Validate required fields
        if (!email || !otp || !newPassword) {
            return res.status(400).json({
                EM: 'Missing required parameters (email, OTP, or new password)',
                EC: 1,
                DT: null
            });
        }

        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({
                EM: 'Invalid email format',
                EC: 1,
                DT: null
            });
        }

        // Validate new password
        const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!#$%^&*()_+={}\[\]:;"'<>,.?~`-])[A-Za-z\d!#$%^&*()_+={}\[\]:;"'<>,.?~`-]{8,}$/;
        if (!passwordRegex.test(newPassword)) {
            return res.status(400).json({
                EM: 'New password must be at least 8 characters long, contain uppercase, lowercase, number, and special character',
                EC: 1,
                DT: null
            });
        }

        // Validate OTP format
        if (!otp || typeof otp !== 'string' || !/^[0-9]{6}$/.test(otp)) {
            return res.status(400).json({
                EM: 'OTP must be a string containing exactly 6 digits',
                EC: 1,
                DT: null
            });
        }

        const result = await authService.resetPassword({
            email,
            otp,
            newPassword
        });

        return res.status(result.EC === 0 ? 200 : 400).json(result);

    } catch (error) {
        console.error('Reset password error:', error);
        return res.status(500).json({
            EM: 'Error from server',
            EC: -1,
            DT: null
        });
    }
};

module.exports = {
    testApi,
    handleRegister,
    handleLogin,
    handleLogout,
    handleGoogleLogin,
    handleVerifyToken,
    hanleResendCode,
    handleResetPassword,
    handleValidateUser
};