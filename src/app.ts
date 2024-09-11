import createError from 'http-errors';
import express from 'express';
import path from 'path';
import cookieParser from 'cookie-parser';
import logger from 'morgan';
import session from 'express-session';
import flash from 'connect-flash';
import i18next from "./i18n";
import i18nextMiddleware from "i18next-http-middleware";
import indexRouter from './routes/index';
import { config } from 'dotenv';
import { AppDataSource } from './config/data-source';
import handlebarsHelpers from 'handlebars-helpers';
import { User } from './entities/user.entity';
config();

const app = express();
const hbs = require('hbs');
const helpers = handlebarsHelpers();


// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'hbs');
hbs.registerPartials(__dirname + '/views/partials');
hbs.registerHelper(helpers);


app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// i18n configuration
app.use(i18nextMiddleware.handle(i18next));
hbs.registerHelper('t', (key: string) => {
  return i18next.t(key);
});

hbs.registerHelper('isFollowing', function(user: User, followingUsers: Array<User>) {
  return followingUsers.some(followingUser => followingUser.userId === user.userId);
});


app.use(
  session({
    resave: false,
    saveUninitialized: true,
    secret: process.env.SESSION_SECRET || 'A randomly generated confusing string',
    cookie: { maxAge: 8640000 } // session last for 1 day
  })
)

app.use(flash());

app.use('/', indexRouter);

// catch 404 and forward to error handler
app.use((req, res, next) => {
    next(createError(404));
});

// error handler
app.use((err: Error, req: express.Request, res: express.Response) => {
    res.locals.message = err.message;
    res.locals.error = req.app.get('env') === 'development' ? err : {};
    res.status(500);
    res.render('error');
});
// Connect DB
AppDataSource.initialize()
    .then(() => {
        console.log('Datasource has been initialized')  
    })
    .catch((err) => {
        console.error('Error during Datasource initialization: ', err)
    })
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});

export default app;
