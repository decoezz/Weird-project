const express = require('express');
const path = require('path');
const xss = require('xss-clean');
const hpp = require('hpp');
const morgan = require('morgan');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const AppError = require('./utils/appError.js');
const globalErrorHandler = require('./controllers/errorController.js');
const userRouter = require('./routes/userRoutes.js');
const app = express();

app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: [
        "'self'",
        'https://use.fontawesome.com',
        'https://cdn.jsdelivr.net',
        'https://cdnjs.cloudflare.com',
      ],
      styleSrc: [
        "'self'",
        "'unsafe-inline'",
        'https://use.fontawesome.com',
        'https://cdn.jsdelivr.net',
      ],
      fontSrc: ["'self'", 'https://use.fontawesome.com'],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: [],
    },
  })
);
app.use(morgan('dev'));
const limiter = rateLimit({
  max: 100,
  windowMs: 60 * 60 * 1000,
  message: 'Too many request from this IP,please try again in an hour!',
});
app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());
app.use(mongoSanitize()); //for security aganist NO sql injection
app.use(xss());
//Prevent parameter pollution
app.use(
  hpp({
    whitelist: [], //Will write here some data that the user could query for
  })
);
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, '../frontend')));
app.use('/api', limiter);
app.use((err, req, res, next) => {
  res.status(err.statusCode || 500).json({
    status: 'error',
    message: err.message || 'Internal Server Error',
  });
});
app.get('/api/v1/users', (req, res) => {
  res.json(req.user); // Assuming req.user contains the user data
});
//this if the website is a single page website so i will always make the user return to the main page but i figured it's a multi page website
// app.get('*', (req, res) => {
//   res.sendFile(path.join(__dirname, '../frontend/index.html'));
// });
app.use('/api/v1/users', userRouter);
//if the user wanted to enter a wrong route
app.all('*', (req, res, next) => {
  next(new AppError(`can't find ${req.originalUrl} on this server!`, 404));
});
app.use(globalErrorHandler);
module.exports = app;
