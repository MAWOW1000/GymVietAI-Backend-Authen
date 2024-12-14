const passport = require('passport');
const LocalStrategy = require('passport-local');
import { handleUserLogin } from '../service/loginRegisterService'
const configPassport = () => {
    passport.use(new LocalStrategy({
        passReqToCallback: true
    }, async (req, username, password, cb) => {
        const rawData = {
            valueLogin: username,
            password
        }

        let res = await handleUserLogin(rawData)
        if (res && +res.EC === 0) {
            return cb(null, res.DT)
        }
        else {
            return cb(null, false, { message: res.EM });
        }
    }));
}

const handleLogout = (req, res) => {
    req.session.destroy((err) => {
        req.logout()
        res.redirect('/login')
    })
}

export { configPassport, handleLogout }