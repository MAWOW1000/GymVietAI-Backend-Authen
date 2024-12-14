import { v4 as uuidv4 } from 'uuid';
import { createJWT } from '../middleware/JWTAction';
import { updateCode } from '../service/updateRefreshToken';
import nodemailer from "nodemailer";
import { updateRefreshToken } from '../service/updateRefreshToken'

const getLoginPage = (req, res) => {
    // const reqArr = req.flash('message')
    // let errMessage = ''
    // let username = ''
    // if (reqArr && reqArr[0]) {
    //     errMessage = reqArr[0].EC !== 0 ? reqArr[0].EM : ""
    //     username = reqArr[1]
    // }
    return res.render("login.ejs", { url: req.query.serviceURL });
}

const getForgotPassword = (req, res) => {
    // const reqArr = req.flash('message')
    // let errMessage = ''
    // let username = ''
    // if (reqArr && reqArr[0]) {
    //     errMessage = reqArr[0].EC !== 0 ? reqArr[0].EM : ""
    //     username = reqArr[1]
    // }
    return res.render("forgotPassword.ejs");
}

const handleVerifyToken = async (req, res) => {
    try {
        const ssoToken = req.body.ssoToken
        const refreshToken = uuidv4();
        const payload = {
            email: req.user.email,
            username: req.user.username,
            groupWithRoles: req.user.groupWithRoles
        }
        const token = createJWT(payload);
        const reqDefault = {
            jwt: token,
            refreshToken,
            email: req.user.email,
            username: req.user.username,
        }
        await updateRefreshToken(payload.email, refreshToken)
        req.user.access_token = token
        req.session.destroy((err) => {
            req.logout()
        })
        console.log("check user>> ", req.user)
        console.log("check sso Token>> ", ssoToken)
        if (req.user && req.user.code1 && req.user.code1 === ssoToken) {
            res.cookie('access-token', token,
                { maxAge: 3000000, httpOnly: true }
            )
            res.cookie('refresh-token', refreshToken)
            return res.status(200).json({
                EC: 0,
                EM: 'Success',
                DT: reqDefault
            })
        }
        else {
            return res.status(401).json({
                EC: 1,
                EM: 'Limit session or session invalid',
                DT: ''
            })
        }
    } catch (err) {
        return res.status(500).json({
            EC: -1,
            EM: 'Internal server error',
            DT: ''
        })
    }
}

const getResendCode = async (req, res) => {
    try {
        const transporter = nodemailer.createTransport({
            host: "smtp.gmail.com",
            port: 587,
            secure: false, // true for port 465, false for other ports
            auth: {
                user: "duc22092003@gmail.com",
                pass: process.env.GOOGLE_APP_PASSWORD,
            },
        });

        const OTP = Math.floor(100000 + Math.random() * 900000);

        await updateCode(req.body.email, OTP)
        // send mail with defined transport object
        const info = await transporter.sendMail({
            from: '"Dev Pham Admin 👻" <maddison53@ethereal.email>', // sender address
            to: req.body.email, // list of receivers
            subject: "Hello ✔", // Subject line
            text: "Hello world?", // plain text body
            html: `<b>Hello world?</b>
                <h1>Your OTP is ${OTP}</h1>
            `, // html body
        });

        console.log("Message sent: %s", info);
        return res.status(200).json({
            EM: 'Success'
        })
        // Message sent: <d786aa62-4e0a-070a-47ed-0b0666549519@ethereal.email>
    } catch (err) {
        return res.status(403).json({
            EM: 'Bug'
        })
    }

}

module.exports = {
    getLoginPage, handleVerifyToken, getForgotPassword, getResendCode
}