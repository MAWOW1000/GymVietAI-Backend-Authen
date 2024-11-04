const express = require('express');
const router = express.Router();
const{updateProfileValidation, signUpValidation, loginValidation, forgetValidation} = require ('../helpers/validation');

const userController = require('../controllers/userController');
const { use } = require('./webRoute');

const {isAuthorize} =  require('../middleware/auth');

router.post('/register',signUpValidation, userController.register);
router.post('/login',loginValidation, userController.login);

router.get('/get-user',auth.isAuthorize, userController.getUser);

router.post('/forget-password', forgetValidation,userController.forgetPassword);

router.post('/update-profile', upload.single('image'), updateProfileValidation, isAuthorize, userController.updateProfile);
module.exports = router;