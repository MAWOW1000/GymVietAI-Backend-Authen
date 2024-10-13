const New = require('../models/New');

class BlogController {
    show(req, res, next) {
        New.findOne({ slug: req.params.slug })
            .lean()
            .then((news) => res.render('news', { news }))
            .catch(next);
    }

    create(req, res, next) {
        res.render('create');
    }

    async update(req, res, next) {
        try {
            const news = await New.findById(req.params.iid).lean();
            res.render('update', { news });
        } catch (error) {
            res.status(400).json({ error: 'Error!!!' });
        }
    }

    store(req, res, next) {
        const blogData = new New(req.body);
        blogData
            .save()
            .then(() => res.redirect('/')) // Redirect after successful save
            .catch((err) => {
                console.log(err); // Log the error to the console
                res.status(500).send('Error saving the blog post.'); // Send error response
            });
    }

    conduct(req, res, next) {
        New.updateOne({ _id: req.params.id }, req.body)
            .then(() => res.redirect('/')) // Redirect after successful save
            .catch((err) => {
                console.log(err); // Log the error to the console
                res.status(500).send('Error saving the blog post.'); // Send error response
            });
    }

    recover(req, res, next) {
        New.restore({ _id: req.params.id })
            .then(() => res.redirect('back')) // Redirect after successful save
            .catch(next);
    }

    delete(req, res, next) {
        New.delete({ _id: req.params.id })
            .then(() => res.redirect('back')) // Redirect after successful save
            .catch(next);
    }

    deleteTrash(req, res, next) {
        New.deleteOne({ _id: req.params.id })
            .then(() => res.redirect('back')) // Redirect after successful save
            .catch(next);
    }
    table(req, res, next) {
        let elementSorted = New.find({
            $or: [{ deleted: false }, { deleted: null }],
        })
            .sortSpecial(req)
            .lean();
        Promise.all([elementSorted, New.countDocuments({ deleted: true })])
            .then(([news, countDel]) => {
                res.render('table', { news, countDel });
            })
            .catch(next);
    }

    async trash(req, res) {
        try {
            const news = await New.find({ deleted: true }).lean();
            res.render('trash', { news });
        } catch (error) {
            res.status(400).json({ error: 'Error!!!' });
        }
    }

    option(req, res, next) {
        switch (req.body.action) {
            case 'delete': {
                New.delete({ _id: { $in: req.body.itemsList } })
                    .then(() => res.redirect('back')) // Redirect after successful save
                    .catch(next);
                break;
            }
            default:
                res.json({ error: 'Error!!!' });
        }
    }
}

module.exports = new BlogController();
