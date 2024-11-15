import passport from 'passport'
import { upsertUserSocialMedia } from '../../service/loginRegisterService'
require('dotenv').config()


const GoogleStrategy = require('passport-google-oauth20').Strategy;

const configGoogle = () => {
    passport.use(new GoogleStrategy({
        clientID: process.env.GOOGLE_APP_CLIENT_ID,
        clientSecret: process.env.GOOGLE_APP_CLIENT_SECRET,
        callbackURL: process.env.GOOGLE_APP_CALLBACK_URL,
    },
        async function (accessToken, refreshToken, profile, cb) {
            const dataRaw = {
                email: profile?.emails[0]?.value ?? profile.id,
                displayName: `${profile.name.givenName} ${profile.name.familyName}`,
                googleId: profile.id,
            }
            const typeAcc = 'GOOGLE'
            const user = await upsertUserSocialMedia(typeAcc, dataRaw)
            return cb(null, user);
        }
    ));

}

export default configGoogle;