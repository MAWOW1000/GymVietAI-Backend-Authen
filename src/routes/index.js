const siteRouter = require('./site');
const blogRouter = require('./blog');

function route(app) {
    app.use('/blog', blogRouter);
    app.use('/', siteRouter);
}

module.exports = route;
