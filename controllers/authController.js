const { promisify } = require('util');
const jwt = require('jsonwebtoken');
const User = require('../models/userModel.js');
const catchAsync = require('./../utils/catchAsync.js');
const AppError = require('./../utils/appError.js');
// const Email = require('./../utils/email.js');
const createSendToken = (user, statusCode, res) => {
  const token = signToken(user._id);
  const cookieOptions = {
    expires: new Date(
      Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000
    ),
    httplOnly: true,
  };
  if (process.env.NODE_ENV === 'production') cookieOptions.secure = true;
  res.cookie('jwt', token, cookieOptions);
  user.password = undefined;
  res.status(statusCode).json({
    status: 'success',
    token,
    data: {
      user,
    },
  });
};
const signToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });
};
exports.signup = catchAsync(async (req, res, next) => {
  const role = req.body.role;
  if (role && role === 'admin' && req.user.role !== 'admin') {
    return next(new AppError('Only admins can assign the admin role', 403));
  }
  const newUser = await User.create({
    FirstName: req.body.FirstName,
    LastName: req.body.LastName,
    email: req.body.email,
    password: req.body.password,
    passwordConfirm: req.body.passwordConfirm,
    role: role || 'user',
  });
  //   const url = `${req.protocol}://${req.get('host')}/index.html`;
  //   await new Email(newUser, url).sendWelcome();

  createSendToken(newUser, 201, res);
});
exports.login = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;
  //1)check if the email and password exist
  if (!email || !password) {
    return next(new AppError('Please provide email and password!', 400));
  }
  //2) check if user exists and password is correct
  const user = await User.findOne({ email }).select('+password');
  if (!user || !(await user.correctPassword(password, user.password))) {
    return next(new AppError('Incorrect email or password', 401)); // 401 status for unauthorized request
  }
  //3)If everything ok,send token to client
  createSendToken(user, 200, res);
});
