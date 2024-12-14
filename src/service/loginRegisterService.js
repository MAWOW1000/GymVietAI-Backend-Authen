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
        //check email/phonenumber are exist
        let isEmailExist = await checkEmailExist(rawUserData.email);
        if (isEmailExist === true) {
            return {
                EM: 'The email is already exist',
                EC: 1
            }
        }

        //hash user password
        let hashPassword = hashUserPassword(rawUserData.password);

        //create new user
        await db.User.create({
            email: rawUserData.email,
            username: rawUserData.username,
            password: hashPassword,
            phone: rawUserData.phone,
            groupId: 4
        })

        return {
            EM: 'A user is created successfully!',
            EC: '0'
        }

    } catch (e) {
        console.log(e)
        return {
            EM: 'Somthing wrongs in service...',
            EC: -2
        }
    }
}

const checkPassword = (inputPassword, hashPassword) => {
    return bcrypt.compareSync(inputPassword, hashPassword); // true or false
}

const handleUserLogin = async (rawData) => {
    try {
        let user = await db.User.findOne({
            where: { email: rawData.valueLogin },
            raw: true
        })

        if (user) {
            // let isCorrectPassword = checkPassword(rawData.password, user.password);
            let isCorrectPassword = true;
            if (isCorrectPassword === true) {
                let RoleWithPermission = await getRoleWithPermission(user);
                console.log('check >> ', user, user.password, rawData.password)
                const code1 = uuidv4();
                return {
                    EM: 'ok!',
                    EC: 0,
                    DT: {
                        email: user.email,
                        code1: code1,
                        RoleWithPermission,
                        username: user.username
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
            EM: 'Somthing wrongs in service...',
            EC: -2
        }
    }
}

const upsertUserSocialMedia = async (typeAcc, dataRaw) => {
    try {
        let user = null
        user = await db.User.findOne({
            where: { email: dataRaw?.email ?? dataRaw?.facebookId, typeLogin: typeAcc },
            raw: true
        })
        if (!user) {
            user = await db.User.create({
                email: dataRaw?.email ?? dataRaw?.facebookId,
                firstName: dataRaw.displayName.split(' ')[0],
                lastName: dataRaw.displayName.split(' ')[1],
                typeLogin: typeAcc
            })
        }
        return user
    } catch (err) {
        console.log('bug in upsertUserSocailMedia >>', err)
    }
}

module.exports = {
    registerNewUser, handleUserLogin, hashUserPassword, checkEmailExist, upsertUserSocialMedia
}