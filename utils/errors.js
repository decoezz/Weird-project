const AppError = require('./../utils/appError.js');
const handleCastErrorDB = (err) => {
    const message = `Invalid ${err.path} :${err.value}`;
    return new AppError(message, 400);
  };
  const handleDuplicateErrorDB = (err) => {
    if (err.errmsg) {
      const value = err.errmsg.match(/(["'])(\\?.)*?\1/)[0];
      const message = `Duplicate value: ${value}, please use another value`;
      return new AppError(message, 400);
    }
    return new AppError('Duplicate field value', 400);
  };
  const handleValidationErrorDB = (err) => {
    const errors = Object.values(err.errors).map((el) => el.message);
    const messsage = `Invalid Input data.${errors.join('. ')}`;
    return new AppError(messsage, 400);
  };
  const handleJWTError = () =>
    new AppError('Invalid token. Please log in again!', 401);
  const handleJWTExpiredError = () =>
    new AppError('Your Token has expired!. Please log in again.');
  module.exports = {
    handleCastErrorDB,
    handleDuplicateErrorDB,
    handleValidationErrorDB,
    handleJWTError,
    handleJWTExpiredError,
  };