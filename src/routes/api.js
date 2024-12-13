import express from "express";
import authenticationController from '../controller/authenticationController';
import userController from "../controller/userController";
import groupController from '../controller/groupController';
import { checkUserJWT, checkUserPermission } from '../middleware/JWTAction';
import roleController from '../controller/roleController';

const router = express.Router();

/**
 * 
 * @param {*} app : express app
 */

const initApiRoutes = (app) => {


    //path, handler
    //rest api
    //GET - R, POST- C, PUT - U, DELETE - D

    router.all('*', checkUserJWT, checkUserPermission);

    router.post("/register", authenticationController.handleRegister);
    router.post("/login", authenticationController.handleLogin);
    router.post("/loginGoogle", authenticationController.handleGoogleLogin);
    router.post("/logout", authenticationController.handleLogout);

    //user routes
    router.get("/user/read", userController.readFunc);
    router.post("/user/create", userController.createFunc);
    router.put("/user/update", userController.updateFunc);
    router.delete("/user/delete", userController.deleteFunc);

    // roles routes
    router.get("/role/read", roleController.readFunc);
    router.post("/role/create", roleController.createFunc);
    router.put("/role/update", roleController.updateFunc);
    router.delete("/role/delete", roleController.deleteFunc);
    router.get("/role/by-group/:groupId", roleController.getRoleByGroup);
    router.post("/role/assign-to-group", roleController.assignRoleToGroup);

    //group routes
    router.get("/group/read", groupController.readFunc);

    return app.use("/api/v1/", router);
}

export default initApiRoutes;