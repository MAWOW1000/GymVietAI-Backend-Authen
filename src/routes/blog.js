const express = require('express');
const router = express.Router();

const blogController = require('../app/controllers/BlogController');
const siteController = require('../app/controllers/SiteController');

router.post('/option', blogController.option);

router.get('/table', blogController.table);

router.get('/trash', blogController.trash);

router.get('/update/:iid', blogController.update);

router.put('/conduct/:id', blogController.conduct);

router.patch('/recover/:id', blogController.recover);

router.delete('/delete/:id', blogController.delete);

router.delete('/trash/delete/:id', blogController.deleteTrash);

router.get('/create', blogController.create);

router.post('/store', blogController.store);

router.get('/:slug', blogController.show);

router.get('/', siteController.index);

module.exports = router;
