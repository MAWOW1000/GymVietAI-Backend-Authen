const path = require('path');
const handlebars = require('express-handlebars');
const express = require('express');
const morgan = require('morgan');
const app = express();
const port = 3000;
const route = require('./routes');
const methodOverride = require('method-override');
const SortMiddleWare = require('./app/middleware/SortMiddleware');

const db = require('./config/db');
db.connect();
//config static path to run static file
app.use(express.static(path.join(__dirname, 'public')));

//config run handlebars file and reduce handlebar => hbs
app.engine(
    '.hbs',
    handlebars.engine({
        extname: '.hbs',
        helpers: {
            sum(a, b) {
                return a + b;
            },
            sortFc: require('./helpers/sort'),
        },
    }),
);
app.set('view engine', '.hbs');
app.set('views', 'src/resources/views');

// Use override method POST, GET, ...
app.use(methodOverride('_method'));

// Config to read req.body with form
app.use(
    express.urlencoded({
        extended: true,
    }),
);

// Config to read req.body with JS, XML, ...
app.use(express.json());

//Use middleware in all system
app.use(SortMiddleWare);

//use morgan to view looger and state request
app.use(morgan('combined'));

//config routes for web server
route(app);

//config listen port for web server
app.listen(port, () => {
    console.log(`App listening on port ${port}`);
});
