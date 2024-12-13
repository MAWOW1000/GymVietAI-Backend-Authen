require('dotenv').config();
import db from '../models/index';
import bcrypt from 'bcryptjs';
import { Op } from 'sequelize';
import { getRoleWithPermission } from './JWTService';
import { v4 as uuidv4 } from 'uuid';

const salt = bcrypt.genSaltSync(10);

const hashUserPassword = (userPassword) => {
    let hashPassword = bcrypt.hashSync(userPassword, salt);
    return hashPassword;
}

const checkEmailExist = async (userEmail) => {
    let user = await db.User.findOne({
        where: { email: userEmail }
    })

    if (user) {
        return true;
    }
    return false;
}

const registerNewUser = async (rawUserData) => {
    try {
        // Check if email exists
        let isEmailExist = await checkEmailExist(rawUserData.email);
        if (isEmailExist) {
            return {
                EM: 'The email already exists',
                EC: 1
            };
        }

        // Hash user password
        let hashPassword = hashUserPassword(rawUserData.password);

        // Create new user with default roleID of 2
        await db.User.create({
            email: rawUserData.email,
            password: hashPassword, // Only email and password are required
            roleID: 2 // Default roleID
        });

        return {
            EM: 'User created successfully!',
            EC: 0
        };

    } catch (e) {
        console.log(e);
        return {
            EM: 'Something went wrong in service.',
            EC: -2
        };
    }
}

const checkPassword = (inputPassword, hashPassword) => {
    return bcrypt.compareSync(inputPassword, hashPassword); // true or false
}

const handleUserLogin = async (rawData) => {
    try {
        let user = await db.User.findOne({
            where: { email: rawData.email },
            raw: true
        })

        if (user) {
            let isCorrectPassword = checkPassword(rawData.password, user.password);
            if (isCorrectPassword === true) {
                return {
                    EM: 'Login successful! Welcome back!',
                    EC: 0,
                    DT: {
                        email: user.email,
                        role: user.roleID,
                        firstName: user.firstName,
                        lastName: user.lastName,
                        picture: user.picture,
                    }
                }
            }
        }

        return {
            EM: 'Your email/phone number or password is incorrect!',
            EC: 1,
            DT: ''
        }

    } catch (error) {
        console.log(error)
        return {
            EM: 'Something went wrong in service!',
            EC: -2
        }
    }
}

const upsertUserSocialMedia = async (dataRaw) => {
    try {
        let user = null
        user = await db.User.findOne({
            where: { email: dataRaw?.email },
            raw: true
        })
        if (!user) {
            user = await db.User.create({
                email: dataRaw?.email,
                firstName: dataRaw.given_name,
                lastName: dataRaw.family_name,
                picture: dataRaw.picture,
                roleId: 2
            })
        }
        return user
    } catch (err) {
        console.log('bug in upsertUserSocailMedia >>', err)
    }
}

const upsertRefreshToken = async (email, token, expiresAt) => {
    try {
        let [user, created] = await db.User.findOrCreate({
            where: { email: email },
            defaults: { refreshToken: token, refreshTokenExpiresAt: expiresAt }
        });

        if (!created) {
            await user.update({
                refreshToken: token,
                refreshTokenExpiresAt: expiresAt
            });
        }

        return {
            EM: created ? 'User created successfully' : 'User updated successfully',
            EC: 0,
            DT: ''
        };
    } catch (e) {
        console.log(e);
        return {
            EM: 'something wrongs with services',
            EC: 1,
            DT: []
        }
    }
}
module.exports = {
    registerNewUser, handleUserLogin, hashUserPassword, checkEmailExist, upsertUserSocialMedia, upsertRefreshToken
}