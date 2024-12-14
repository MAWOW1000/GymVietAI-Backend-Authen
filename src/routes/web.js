import express from "express";
import homeController from '../controller/homeController';
import apiController from '../controller/apiController';
import passport from "passport";
import checkLogin from "../middleware/checkLogin";
import { handleLogout } from "../controller/passportController";
import { getLoginPage, handleVerifyToken, getForgotPassword, getResendCode } from "../controller/loginController";
require('dotenv').config()
const router = express.Router();

/**
 * 
 * @param {*} app : express app
 */

const initWebRoutes = (app) => {
    //path, handler
    router.get("/", checkLogin, homeController.handleHelloWord);
    router.get("/login", getLoginPage);
    // router.post("/login", configPassport);

    router.post('/login', function (req, res, next) {
        passport.authenticate('local', function (error, user, info) {
            if (error) {
                return res.status(500).json(error);
            }
            if (!user) {
                return res.status(401).json(info.message);
            }
            req.logIn(user, function (err) {
                if (err) { return res.status(401).json(err); }
                return res.status(200).json({ ...user, redirectURL: req.body.serviceURL });
            });

        })(req, res, next);
    });

    router.get('/auth/google',
        passport.authenticate('google', { scope: ['profile', 'email'] }));

    router.get('/google/redirect',
        passport.authenticate('google', { failureRedirect: '/login' }),
        function (req, res) {
            // Successful authentication, redirect home.
            return res.render('social.ejs')
        });


    router.get('/auth/facebook',
        passport.authenticate('facebook'));

    router.get('/facebook/redirect',
        passport.authenticate('facebook', { failureRedirect: '/login' }),
        function (req, res) {
            // Successful authentication, redirect home.
            return res.render('social.ejs');
        });
    router.get('/forgotPassword', getForgotPassword)

    router.post('/resendCode', getResendCode)

    router.post('/logout', handleLogout);

    router.post('/verify-token', handleVerifyToken);

    router.get("/user", homeController.handleUserPage);
    router.post("/users/create-user", homeController.handleCreateNewUser);
    router.post("/delete-user/:id", homeController.handleDelteUser)
    router.get("/update-user/:id", homeController.getUpdateUserPage);
    router.post("/user/update-user", homeController.handleUpdateUser);

    //rest api
    //GET - R, POST- C, PUT - U, DELETE - D
    router.get("/api/test-api", apiController.testApi);

    return app.use("/", router);
}

export default initWebRoutes;