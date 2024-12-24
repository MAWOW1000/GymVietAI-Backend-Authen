import express from 'express';
import authController from '../controller/authController';
import userController from '../controller/userController';
import groupController from '../controller/groupController';
import roleController from '../controller/roleController';
import { checkUserJWT, checkUserPermission } from '../middleware/authMiddleware';

const router = express.Router();

/**
 * Initialize API routes for the application
 * @param {Express} app - Express application instance
 * @returns {void}
 */
const initApiRoutes = (app) => {
    // Apply JWT and Permission middleware to all routes
    router.all('*', checkUserJWT);

    // Authentication routes
    router.post('/register', authController.handleRegister);
    router.post('/login', authController.handleLogin);
    router.post('/loginGoogle', authController.handleGoogleLogin);
    router.post('/logout', authController.handleLogout);
    router.post('/sendOTP', authController.hanleResendCode);
    router.post('/resetPassword', authController.handleResetPassword);

    //Other service call to validate user
    router.post('/validateUser', authController.handleValidateUser);

    // User routes
    router.get('/user/read', userController.readFunc);
    router.post('/user/create', userController.createFunc);
    router.put('/user/update', userController.updateFunc);
    router.delete('/user/delete', userController.deleteFunc);

    // Role routes
    router.get('/role/read', roleController.readFunc);
    router.post('/role/create', roleController.createFunc);
    router.put('/role/update', roleController.updateFunc);
    router.delete('/role/delete', roleController.deleteFunc);
    router.get('/role/by-group/:groupId', roleController.getRoleByGroup);
    router.post('/role/assign-to-group', roleController.assignRoleToGroup);

    // Group routes
    router.get('/group/read', groupController.readFunc);

    return app.use('/api/v1/', router);
};

export default initApiRoutes;