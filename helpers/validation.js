const { check } = require ('express-validator');

exports.signUpValidation = [
    check('name','Name is required').not().isEmpty(),
    check('email','Please enter avalid mail').isEmail().normalizeEmail({gmail_remove_dots:true}),
    check('password','Password is required').isLength({min:8})
]

exports.loginValidation = [
    check('email','Please enter avalid mail').isEmail().normalizeEmail({gmail_remove_dots:true}),
    check('password','Password is required').isLength({min:8})
]

exports.forgetValidation = [
    check('email','Please enter avalid mail').isEmail().normalizeEmail({gmail_remove_dots:true}),
]

exports.updateProfileValidation = [
    check('name','Name is required').not().isEmpty(),
    check('email','Please enter avalid mail').isEmail().normalizeEmail({gmail_remove_dots:true}),
]