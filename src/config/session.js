require('dotenv').config();
const Sequelize = require('sequelize');
const session = require("express-session");
import passport from "passport";

function configSession(app) {
    // initalize sequelize with session store
    let SequelizeStore = require("connect-session-sequelize")(session.Store);

    // create database
    const sequelize = new Sequelize(process.env.DB_NAME, process.env.DB_USERNAME, process.env.DB_PASSWORD, {
        host: process.env.DB_HOST,
        dialect: process.env.DB_DIALECT,
        logging: false,
        define: {
            freezeTableName: true
        },
        timezone: '+07:00'
    });


    // configure express
    let myStore = new SequelizeStore({
        db: sequelize,
    });
    app.use(
        session({
            secret: "keyboard cat",
            store: myStore,
            resave: false,
            proxy: true,
            saveUninitialized: false,
            expiration: 30000 * 2 * 60,
            cookie: { expires: 30000 * 2 * 60 }
        })
    );

    myStore.sync();
    // continue as normal
    app.use(passport.authenticate('session'));

    passport.serializeUser(function (user, cb) {
        process.nextTick(function () {
            cb(null, user);
        });
    });

    passport.deserializeUser(function (user, cb) {
        process.nextTick(function () {
            return cb(null, user);
        });
    });
}

export default configSession;