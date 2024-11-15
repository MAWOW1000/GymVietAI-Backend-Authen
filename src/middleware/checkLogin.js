require('dotenv').config();

function checkLogin(req, res, next) {
    if (req.isAuthenticated()) {
        if (req.path == '/login') {
            window.location.href = `${process.env.REACT_URL}`
        }
        else {
            next()
        }
    }
    else {
        if (req.path == '/login') {
            next()
        }
        else {
            return res.redirect('/login')
        }
    }
}

export default checkLogin;