const bcrypt = require('bcryptjs');
const db = require('../config/database');

class AdminController {
    async createUser(req, res) {
        try {
            const { firstname, lastname, email, password, gender, dob, role_id } = req.body;

            // Validate required fields
            if (!firstname || !lastname || !email || !password || !gender || !dob || !role_id) {
                return res.status(400).json({ message: 'All fields are required' });
            }

            // Validate email format
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (!emailRegex.test(email)) {
                return res.status(400).json({ message: 'Invalid email format' });
            }

            // Check if email already exists
            const [existingUsers] = await db.query(
                'SELECT id FROM users WHERE email = ?',
                [email]
            );

            if (existingUsers.length > 0) {
                return res.status(400).json({ message: 'Email already exists' });
            }

            // Hash password
            const salt = await bcrypt.genSalt(10);
            const hashedPassword = await bcrypt.hash(password, salt);

            // Convert gender to bit
            const genderBit = gender.toLowerCase() === 'male' ? 1 : 0;

            // Insert new user
            const [result] = await db.query(
                `INSERT INTO users (firstname, lastname, email, password_hash, gender, dob, role_id, is_active, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, true, NOW(), NOW())`,
                [firstname, lastname, email, hashedPassword, genderBit, dob, role_id]
            );

            res.status(201).json({
                message: 'User created successfully',
                user: {
                    id: result.insertId,
                    firstname,
                    lastname,
                    email,
                    gender,
                    dob,
                    role_id
                }
            });
        } catch (error) {
            console.error('Create user error:', error);
            res.status(500).json({ 
                message: 'Internal server error',
                error: process.env.NODE_ENV === 'development' ? error.message : undefined
            });
        }
    }

    async getUsers(req, res) {
        try {
            const [users] = await db.query(
                `SELECT id, firstname, lastname, email, 
                        CASE gender WHEN 1 THEN 'male' ELSE 'female' END as gender,
                        dob, role_id, height, weight, level, goal,
                        created_at, updated_at
                FROM users 
                ORDER BY created_at DESC`
            );

            res.json({ users });
        } catch (error) {
            console.error('Get users error:', error);
            res.status(500).json({ 
                message: 'Internal server error',
                error: process.env.NODE_ENV === 'development' ? error.message : undefined
            });
        }
    }

    async updateUser(req, res) {
        try {
            const userId = req.params.id;
            const { firstname, lastname, email, gender, dob, role_id, height, weight, level, goal } = req.body;

            // Check if user exists
            const [existingUsers] = await db.query(
                'SELECT id FROM users WHERE id = ?',
                [userId]
            );

            if (existingUsers.length === 0) {
                return res.status(404).json({ message: 'User not found' });
            }

            // Convert gender to bit if provided
            const genderBit = gender ? (gender.toLowerCase() === 'male' ? 1 : 0) : undefined;

            // Build update query dynamically
            let updateFields = [];
            let queryParams = [];

            if (firstname) {
                updateFields.push('firstname = ?');
                queryParams.push(firstname);
            }
            if (lastname) {
                updateFields.push('lastname = ?');
                queryParams.push(lastname);
            }
            if (email) {
                updateFields.push('email = ?');
                queryParams.push(email);
            }
            if (gender !== undefined) {
                updateFields.push('gender = ?');
                queryParams.push(genderBit);
            }
            if (dob) {
                updateFields.push('dob = ?');
                queryParams.push(dob);
            }
            if (role_id) {
                updateFields.push('role_id = ?');
                queryParams.push(role_id);
            }
            if (height !== undefined) {
                updateFields.push('height = ?');
                queryParams.push(height);
            }
            if (weight !== undefined) {
                updateFields.push('weight = ?');
                queryParams.push(weight);
            }
            if (level) {
                updateFields.push('level = ?');
                queryParams.push(level);
            }
            if (goal) {
                updateFields.push('goal = ?');
                queryParams.push(goal);
            }

            updateFields.push('updated_at = NOW()');

            // Add userId to params array
            queryParams.push(userId);

            // Update user
            await db.query(
                `UPDATE users SET ${updateFields.join(', ')} WHERE id = ?`,
                queryParams
            );

            // Get updated user data
            const [updatedUsers] = await db.query(
                `SELECT id, firstname, lastname, email, 
                        CASE gender WHEN 1 THEN 'male' ELSE 'female' END as gender,
                        dob, role_id, height, weight, level, goal,
                        created_at, updated_at
                FROM users 
                WHERE id = ?`,
                [userId]
            );

            res.json({
                message: 'User updated successfully',
                user: updatedUsers[0]
            });
        } catch (error) {
            console.error('Update user error:', error);
            res.status(500).json({ 
                message: 'Internal server error',
                error: process.env.NODE_ENV === 'development' ? error.message : undefined
            });
        }
    }

    async deleteUser(req, res) {
        try {
            const userId = req.params.id;

            // Check if user exists
            const [existingUsers] = await db.query(
                'SELECT id FROM users WHERE id = ?',
                [userId]
            );

            if (existingUsers.length === 0) {
                return res.status(404).json({ message: 'User not found' });
            }

            // Hard delete user
            await db.query(
                'DELETE FROM users WHERE id = ?',
                [userId]
            );

            res.json({ message: 'User permanently deleted' });
        } catch (error) {
            console.error('Delete user error:', error);
            res.status(500).json({ 
                message: 'Internal server error',
                error: process.env.NODE_ENV === 'development' ? error.message : undefined
            });
        }
    }
}

module.exports = new AdminController();
