import db from '../models/index';
import { rangeRight } from 'lodash';


const updateRefreshToken = async (email, token) => {
    try {
        let user = await db.User.findOne({
            where: { email: email }
        })
        if (user) {
            await user.update({
                refreshToken: token
            })
            return {
                EM: 'Update user succeeds',
                EC: 0,
                DT: ''
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

const updateCode = async (email, code) => {
    try {
        let user = await db.User.findOne({
            where: { email }
        })
        if (user) {
            await user.update({
                code
            })
            return {
                EM: 'Update user succeeds',
                EC: 0,
                DT: ''
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
    updateRefreshToken, updateCode
}