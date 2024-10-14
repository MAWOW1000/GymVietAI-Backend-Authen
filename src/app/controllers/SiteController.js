const New = require('../models/New');
const { multiMongooseToObject } = require('../../ulti/mongoose');

class NewController {
    async index(req, res) {
        try {
            const news = await New.find({}).lean();
            res.render('home', { news });
        } catch (error) {
            res.status(400).json({ error: 'Error!!!' });
        }
    }

    search(req, res) {
        res.render('search');
    }
}

module.exports = new NewController();
