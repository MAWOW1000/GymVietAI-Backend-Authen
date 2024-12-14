import passport from 'passport'
import { upsertUserSocialMedia } from '../../service/loginRegisterService'
require('dotenv').config()


var FacebookStrategy = require('passport-facebook').Strategy;

const configFacebook = () => {
    passport.use(new FacebookStrategy({
        clientID: process.env.FACEBOOK_CLIENT_ID,
        clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
        callbackURL: process.env.FACEBOOK_APP_CALLBACK_URL,
    },
        async function (accessToken, refreshToken, profile, cb) {
            // console.log('check profile ', profile)
            const dataRaw = {
                email: profile?.emails,
                displayName: profile?.displayName,
                facebookId: profile.id,
            }
            const typeAcc = 'FACEBOOK'
            const user = await upsertUserSocialMedia(typeAcc, dataRaw)
            return cb(null, user);
        }
    ));

}

export default configFacebook;