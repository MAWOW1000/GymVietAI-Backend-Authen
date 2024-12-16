const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('../config/database');
const { sendResetPasswordEmail } = require('../utils/emailService');
const crypto = require('crypto');

class AuthController {
    async register(req, res) {
        try {
            console.log('Register request received:', req.body);
            
            const { firstname, lastname, email, password, gender, dob } = req.body;
            
            // Validate input
            if (!firstname || !lastname || !email || !password || !gender || !dob) {
                console.log('Validation failed - Missing required fields');
                return res.status(400).json({ 
                    message: 'All fields are required',
                    missing: {
                        firstname: !firstname,
                        lastname: !lastname,
                        email: !email,
                        password: !password,
                        gender: !gender,
                        dob: !dob
                    }
                });
            }

            // Check if user exists
            console.log('Checking for existing user with email:', email);
            const [existingUser] = await db.query('SELECT id FROM users WHERE email = ?', [email]);
            if (existingUser.length > 0) {
                console.log('User already exists with email:', email);
                return res.status(400).json({ message: 'Email already registered' });
            }

            // Hash password
            console.log('Hashing password...');
            const hashedPassword = await bcrypt.hash(password, 10);

            // Convert gender to bit
            const genderBit = gender.toLowerCase() === 'male' ? 1 : 0;
            console.log('Converted gender to bit:', genderBit);

            // Create user
            console.log('Attempting to create user...');
            const [result] = await db.query(
                'INSERT INTO users (firstname, lastname, email, password_hash, gender, dob, role_id) VALUES (?, ?, ?, ?, ?, ?, 2)',
                [firstname, lastname, email, hashedPassword, genderBit, dob]
            );
            console.log('User created successfully:', result);

            res.status(201).json({ 
                message: 'User registered successfully',
                userId: result.insertId 
            });
        } catch (error) {
            console.error('Register error:', error);
            console.error('Error stack:', error.stack);
            if (error.code === 'ER_DUP_ENTRY') {
                return res.status(400).json({ message: 'Email already registered' });
            }
            res.status(500).json({ 
                message: 'Internal server error',
                error: process.env.NODE_ENV === 'development' ? error.message : undefined
            });
        }
    }

    async login(req, res) {
        try {
            const { email, password } = req.body;

            // Validate required fields
            if (!email || !password) {
                return res.status(400).json({ message: 'Email and password are required' });
            }

            // Get user
            const [users] = await db.query(
                'SELECT id, email, password_hash, role_id FROM users WHERE email = ?',
                [email]
            );

            if (users.length === 0) {
                return res.status(401).json({ message: 'Invalid credentials' });
            }

            const user = users[0];

            // Compare password
            const validPassword = await bcrypt.compare(password, user.password_hash);
            if (!validPassword) {
                return res.status(401).json({ message: 'Invalid credentials' });
            }

            // Generate JWT token
            const token = jwt.sign(
                { 
                    id: user.id, 
                    email: user.email,
                    role: user.role_id
                },
                process.env.JWT_SECRET,
                { expiresIn: '24h' }
            );

            res.json({
                message: 'Login successful',
                token,
                user: {
                    id: user.id,
                    email: user.email,
                    role: user.role_id
                }
            });
        } catch (error) {
            console.error('Login error:', error);
            res.status(500).json({ 
                message: 'Internal server error',
                error: process.env.NODE_ENV === 'development' ? error.message : undefined
            });
        }
    }

    async loginAdmin(req, res) {
        try {
            const { email, password } = req.body;

            // Validate required fields
            if (!email || !password) {
                return res.status(400).json({ message: 'Email and password are required' });
            }

            // Get user with role_id = 1 (admin)
            const [users] = await db.query(
                'SELECT id, email, password_hash, role_id FROM users WHERE email = ? AND role_id = 1 AND is_active = true',
                [email]
            );

            if (users.length === 0) {
                return res.status(401).json({ message: 'Invalid admin credentials' });
            }

            const user = users[0];

            // Compare password
            const validPassword = await bcrypt.compare(password, user.password_hash);
            if (!validPassword) {
                return res.status(401).json({ message: 'Invalid admin credentials' });
            }

            // Generate JWT token
            const token = jwt.sign(
                { 
                    id: user.id, 
                    email: user.email,
                    role: user.role_id
                },
                process.env.JWT_SECRET,
                { expiresIn: '24h' }
            );

            res.json({
                message: 'Admin login successful',
                token,
                user: {
                    id: user.id,
                    email: user.email,
                    role: user.role_id
                }
            });
        } catch (error) {
            console.error('Admin login error:', error);
            res.status(500).json({ 
                message: 'Internal server error',
                error: process.env.NODE_ENV === 'development' ? error.message : undefined
            });
        }
    }

    async forgotPassword(req, res) {
        try {
            const { email } = req.body;

            // Check if user exists
            const [users] = await db.query('SELECT id FROM users WHERE email = ?', [email]);
            if (users.length === 0) {
                return res.status(404).json({ message: 'User not found' });
            }

            // Generate reset token
            const resetToken = crypto.randomBytes(32).toString('hex');
            const resetTokenExpiry = new Date(Date.now() + 3600000); // 1 hour

            // Save reset token
            await db.query(
                'UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE email = ?',
                [resetToken, resetTokenExpiry, email]
            );

            // Send email
            await sendResetPasswordEmail(email, resetToken);

            res.json({ message: 'Password reset email sent' });
        } catch (error) {
            console.error('Forgot password error:', error);
            res.status(500).json({ message: 'Internal server error' });
        }
    }

    async resetPassword(req, res) {
        try {
            const { token, newPassword } = req.body;

            if (!token || !newPassword) {
                return res.status(400).json({ 
                    message: 'Token and new password are required',
                    missing: {
                        token: !token,
                        newPassword: !newPassword
                    }
                });
            }

            // Find user with valid reset token
            const [users] = await db.query(
                'SELECT id FROM users WHERE reset_token = ? AND reset_token_expiry > NOW()',
                [token]
            );

            if (users.length === 0) {
                return res.status(400).json({ message: 'Invalid or expired reset token' });
            }

            // Hash new password
            const hashedPassword = await bcrypt.hash(newPassword, 10);

            // Update password and clear reset token
            await db.query(
                'UPDATE users SET password_hash = ?, reset_token = NULL, reset_token_expiry = NULL WHERE id = ?',
                [hashedPassword, users[0].id]
            );

            res.json({ message: 'Password reset successful' });
        } catch (error) {
            console.error('Reset password error:', error);
            res.status(500).json({ 
                message: 'Internal server error',
                error: process.env.NODE_ENV === 'development' ? error.message : undefined
            });
        }
    }

    async updateProfile(req, res) {
        try {
            const userId = req.user.id;
            const { firstname, lastname, gender, dob, height, weight, level, goal } = req.body;

            // Validate input
            if (!firstname || !lastname || !gender || !dob) {
                return res.status(400).json({ 
                    message: 'Required fields are missing',
                    missing: {
                        firstname: !firstname,
                        lastname: !lastname,
                        gender: !gender,
                        dob: !dob
                    }
                });
            }

            // Validate height and weight if provided
            if (height && (height <= 0 || height > 300)) {
                return res.status(400).json({ 
                    message: 'Invalid height value. Height must be between 0 and 300 cm'
                });
            }
            if (weight && (weight <= 0 || weight > 500)) {
                return res.status(400).json({ 
                    message: 'Invalid weight value. Weight must be between 0 and 500 kg'
                });
            }

            // Validate level if provided
            if (level && !['beginner', 'intermediate', 'advanced'].includes(level)) {
                return res.status(400).json({ 
                    message: 'Invalid level. Must be one of: beginner, intermediate, advanced'
                });
            }

            // Convert gender to bit
            const genderBit = gender.toLowerCase() === 'male' ? 1 : 0;

            // Update user
            await db.query(
                `UPDATE users 
                SET firstname = ?, 
                    lastname = ?, 
                    gender = ?, 
                    dob = ?,
                    height = ?,
                    weight = ?,
                    level = ?,
                    goal = ?
                WHERE id = ?`,
                [firstname, lastname, genderBit, dob, height || null, weight || null, level || 'beginner', goal || null, userId]
            );

            // Get updated user data
            const [users] = await db.query(
                `SELECT id, firstname, lastname, email, gender, dob, 
                        height, weight, level, goal, role_id 
                FROM users WHERE id = ?`,
                [userId]
            );

            if (users.length === 0) {
                return res.status(404).json({ message: 'User not found' });
            }

            const user = users[0];
            // Convert gender bit back to string
            user.gender = user.gender === 1 ? 'male' : 'female';

            res.json({
                message: 'Profile updated successfully',
                user: {
                    id: user.id,
                    firstname: user.firstname,
                    lastname: user.lastname,
                    email: user.email,
                    gender: user.gender,
                    dob: user.dob,
                    height: user.height,
                    weight: user.weight,
                    level: user.level,
                    goal: user.goal,
                    role: user.role_id
                }
            });
        } catch (error) {
            console.error('Update profile error:', error);
            res.status(500).json({ 
                message: 'Internal server error',
                error: process.env.NODE_ENV === 'development' ? error.message : undefined
            });
        }
    }

    async getUser(req, res) {
        try {
            const userId = req.user.id;

            // Get user data
            const [users] = await db.query(
                `SELECT id, firstname, lastname, email, gender, dob, 
                        height, weight, level, goal, role_id,
                        created_at, updated_at
                FROM users 
                WHERE id = ? AND is_active = true`,
                [userId]
            );

            if (users.length === 0) {
                return res.status(404).json({ message: 'User not found' });
            }

            const user = users[0];
            // Convert gender bit to string
            user.gender = user.gender === 1 ? 'male' : 'female';

            res.json({
                user: {
                    id: user.id,
                    firstname: user.firstname,
                    lastname: user.lastname,
                    email: user.email,
                    gender: user.gender,
                    dob: user.dob,
                    height: user.height,
                    weight: user.weight,
                    level: user.level,
                    goal: user.goal,
                    role: user.role_id,
                    created_at: user.created_at,
                    updated_at: user.updated_at
                }
            });
        } catch (error) {
            console.error('Get user error:', error);
            res.status(500).json({ 
                message: 'Internal server error',
                error: process.env.NODE_ENV === 'development' ? error.message : undefined
            });
        }
    }

    async getUserById(req, res) {
        try {
            const userId = req.params.id;

            // Get user data
            const [users] = await db.query(
                `SELECT id, firstname, lastname, email, gender, dob, 
                        height, weight, level, goal, role_id,
                        created_at, updated_at
                FROM users 
                WHERE id = ? AND is_active = true`,
                [userId]
            );

            if (users.length === 0) {
                return res.status(404).json({ message: 'User not found' });
            }

            const user = users[0];
            // Convert gender bit to string
            user.gender = user.gender === 1 ? 'male' : 'female';

            res.json({
                user: {
                    id: user.id,
                    firstname: user.firstname,
                    lastname: user.lastname,
                    email: user.email,
                    gender: user.gender,
                    dob: user.dob,
                    height: user.height,
                    weight: user.weight,
                    level: user.level,
                    goal: user.goal,
                    role: user.role_id,
                    created_at: user.created_at,
                    updated_at: user.updated_at
                }
            });
        } catch (error) {
            console.error('Get user by id error:', error);
            res.status(500).json({ 
                message: 'Internal server error',
                error: process.env.NODE_ENV === 'development' ? error.message : undefined
            });
        }
    }

    async getDashboardStats(req, res) {
        try {
            // Get total users count
            const [totalUsers] = await db.query(
                'SELECT COUNT(*) as total FROM users WHERE is_active = true'
            );

            // Get users by level
            const [usersByLevel] = await db.query(
                `SELECT level, COUNT(*) as count 
                FROM users 
                WHERE is_active = true AND level IS NOT NULL 
                GROUP BY level`
            );

            // Get users by gender
            const [usersByGender] = await db.query(
                `SELECT 
                    CASE gender 
                        WHEN 1 THEN 'male'
                        WHEN 0 THEN 'female'
                    END as gender,
                    COUNT(*) as count
                FROM users 
                WHERE is_active = true 
                GROUP BY gender`
            );

            // Get average height and weight
            const [avgStats] = await db.query(
                `SELECT 
                    AVG(height) as avg_height,
                    AVG(weight) as avg_weight
                FROM users 
                WHERE is_active = true 
                AND height IS NOT NULL 
                AND weight IS NOT NULL`
            );

            // Format the response
            const stats = {
                total_users: totalUsers[0].total,
                users_by_level: usersByLevel.reduce((acc, curr) => {
                    acc[curr.level] = curr.count;
                    return acc;
                }, {}),
                users_by_gender: usersByGender.reduce((acc, curr) => {
                    acc[curr.gender] = curr.count;
                    return acc;
                }, {}),
                average_stats: {
                    height: avgStats[0].avg_height ? Math.round(avgStats[0].avg_height * 10) / 10 : null,
                    weight: avgStats[0].avg_weight ? Math.round(avgStats[0].avg_weight * 10) / 10 : null
                }
            };

            res.json({ stats });
        } catch (error) {
            console.error('Dashboard stats error:', error);
            res.status(500).json({ 
                message: 'Internal server error',
                error: process.env.NODE_ENV === 'development' ? error.message : undefined
            });
        }
    }

    async getRoles(req, res) {
        try {
            // Get all roles
            const [roles] = await db.query(
                'SELECT id, name FROM roles ORDER BY id'
            );

            // Map role names to descriptions
            const rolesWithDescriptions = roles.map(role => ({
                id: role.id,
                name: role.name,
                description: role.id === 1 ? 'System administrator' : 
                           role.id === 2 ? 'Regular user' :
                           role.id === 3 ? 'Fitness trainer' : null
            }));

            res.json({ roles: rolesWithDescriptions });
        } catch (error) {
            console.error('Get roles error:', error);
            res.status(500).json({ 
                message: 'Internal server error',
                error: process.env.NODE_ENV === 'development' ? error.message : undefined
            });
        }
    }

    async upgradeUserRole(req, res) {
        try {
            const { userId, newRole } = req.body;

            if (!userId || !newRole) {
                return res.status(400).json({
                    success: false,
                    message: 'Missing required parameters'
                });
            }

            // Get role_id from roles table
            const [roles] = await db.query(
                'SELECT id FROM roles WHERE name = ?',
                [newRole]
            );

            if (roles.length === 0) {
                return res.status(400).json({
                    success: false,
                    message: 'Invalid role'
                });
            }

            // Cập nhật role trong database
            const [result] = await db.query(
                'UPDATE users SET role_id = ? WHERE id = ?',
                [roles[0].id, userId]
            );

            if (result.affectedRows === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'User not found'
                });
            }

            return res.status(200).json({
                success: true,
                message: 'User role updated successfully'
            });

        } catch (error) {
            console.error('Error upgrading user role:', error);
            return res.status(500).json({
                success: false,
                message: 'Internal server error'
            });
        }
    }
}

module.exports = new AuthController();
