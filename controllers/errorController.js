const AppError = require('./../utils/appError');
const errors = require('./../utils/errors.js');
const path = require('path');

const sendErrorDev = (err, req, res) => {
  if (req.originalUrl.startsWith('/api')) {
    return res.status(err.statusCode).json({
      status: err.status,
      error: err,
      message: err.message,
      stack: err.stack,
    });
  } else {
    // Send an HTML file for non-API routes
    return res
      .status(err.statusCode)
      .sendFile(path.join(__dirname, '../../frontend/error.html'));
  }
};

const sendErrorProd = (err, req, res) => {
  if (err.isOperational) {
    if (req.originalUrl.startsWith('/api')) {
      return res.status(err.statusCode).json({
        status: err.status,
        message: err.message,
      });
    } else {
      return res
        .status(err.statusCode)
        .sendFile(path.join(__dirname, '../../frontend/error.html'));
    }
  } else {
    console.error('ERROR 💥', err);

    if (req.originalUrl.startsWith('/api')) {
      return res.status(500).json({
        status: 'error',
        message: 'Something went very wrong',
      });
    }

    return res
      .status(500)
      .sendFile(path.join(__dirname, '../../frontend/500.html'));
  }
};

module.exports = (err, req, res, next) => {
  err.statusCode = err.statusCode || 500;
  err.status = err.status || 'error';
  const errorFilePath = (statusCode) => {
    switch (statusCode) {
      case 404:
        return path.join(__dirname, '../../frontend/404.html');
      case 401:
        return path.join(__dirname, '../../frontend/401.html');
      case 500:
        return path.join(__dirname, '../../frontend/500.html');
      default:
        return path.join(__dirname, '../../frontend/error.html');
    }
  };

  if (process.env.NODE_ENV === 'development') {
    sendErrorDev(err, req, res);
  } else if (process.env.NODE_ENV === 'production') {
    let error = { ...err };
    error.message = err.message;

    if (err.name === 'CastError') error = errors.handleCastErrorDB(error);
    if (err.code === 11000) error = errors.handleDuplicateErrorDB(error);
    if (err.name === 'ValidationError')
      error = errors.handleValidationErrorDB(error);
    if (err.name === 'JsonWebTokenError') error = errors.handleJWTError();
    if (err.name === 'TokenExpiredError')
      error = errors.handleJWTExpiredError();

    res.status(err.statusCode).sendFile(errorFilePath(err.statusCode));
  }
};
