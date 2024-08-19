const express = require('express');
const path = require('path');
const xss = require('xss-clean');
const hpp = require('hpp');
const morgan = require('morgan');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const cookieParser = require('cookie-parser');
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
        'https://use.fontawesome.com', // Allow FontAwesome
        'https://cdn.jsdelivr.net', // Allow JSDelivr (Bootstrap)
        'https://cdnjs.cloudflare.com', // Allow CDNJS (Chart.js)
      ],
      styleSrc: [
        "'self'",
        "'unsafe-inline'", // Allow inline styles (for Bootstrap)
        'https://use.fontawesome.com', // Allow FontAwesome styles
        'https://cdn.jsdelivr.net', // Allow JSDelivr (Bootstrap)
      ],
      fontSrc: [
        "'self'",
        'https://use.fontawesome.com', // Allow FontAwesome fonts
      ],
      imgSrc: ["'self'", 'data:'], // Allow images from 'self' and data URIs
      connectSrc: ["'self'"], // Allow connections from 'self'
      objectSrc: ["'none'"], // Disallow object sources
      upgradeInsecureRequests: [], // Automatically upgrade http to https
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

app.use(express.static(path.join(__dirname, '../frontend')));
app.use('/api', limiter);
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
