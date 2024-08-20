const { promisify } = require('util');
const jwt = require('jsonwebtoken');
const User = require('../models/userModel.js');
const catchAsync = require('./../utils/catchAsync.js');
const AppError = require('./../utils/appError.js');
const Email = require('./../utils/email.js');
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
  try {
    // Role assignment check
    const role = req.body.role;
    if (role && role === 'admin') {
      // Assuming req.user might not exist for public signup
      if (!req.user || req.user.role !== 'admin') {
        return next(new AppError('Only admins can assign the admin role', 403));
      }
    }

    // Create new user
    const newUser = await User.create({
      FirstName: req.body.FirstName,
      LastName: req.body.LastName,
      email: req.body.email,
      password: req.body.password,
      passwordConfirm: req.body.passwordConfirm,
      role: role || 'user',
    });

    // Send welcome email
    try {
      const url = `${req.protocol}://${req.get('host')}/index.html`;
      await new Email(newUser, url).sendWelcome();
    } catch (emailError) {
      console.error('Error sending welcome email:', emailError);
      // Continue even if email fails
    }

    // Create and send token
    createSendToken(newUser, 201, res);
  } catch (error) {
    if (error.name === 'ValidationError') {
      // Handle Mongoose validation errors
      const messages = Object.values(error.errors).map((el) => el.message);
      return res.status(400).json({
        status: 'fail',
        message: `Invalid input data. ${messages.join('. ')}`,
      });
    } else if (error.code === 11000) {
      // Handle duplicate key error (like unique email)
      return res.status(400).json({
        status: 'fail',
        message: 'This email is already registered. Please use another email!',
      });
    } else {
      // General error handling
      console.error('Error during signup:', error);
      return res.status(500).json({
        status: 'error',
        message: 'An error occurred during signup. Please try again.',
      });
    }
  }
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
exports.protect = catchAsync(async (req, res, next) => {
  let token;
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer')
  ) {
    token = req.headers.authorization.split(' ')[1];
  } else if (req.cookies.jwt) {
    token = req.cookies.jwt;
  }
  // If the token is 'loggedout' or missing, stop processing
  if (!token || token === 'loggedout') {
    // Redirect for browser requests
    if (!req.originalUrl.startsWith('/api')) {
      return res.redirect('/login'); // Redirect to login page
    }
    // For API requests, send an error
    return next(
      new AppError('You are not logged in! Please log in to get access.', 401)
    );
  }
  // Verify the token
  const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);
  // Check if the user still exists
  const currentUser = await User.findById(decoded.id);
  if (!currentUser) {
    return next(
      new AppError('The user belonging to this token no longer exists.', 401)
    );
  }
  // Grant access to protected routes
  req.user = currentUser;
  next();
});

exports.forgotPassword = catchAsync(async (req, res, next) => {
  //1)Get user based on POSTed email
  const user = await User.findOne({ email: req.body.email });
  if (!user) {
    return next(new AppError('There is no user with email address.', 404));
  }
  //2) Generate the random reset token
  const resetToken = user.createPasswordResetToken();
  await user.save({ validateBeforeSave: false });
  //3)send it to user's email
  try {
    const resetURL = `${req.protocol}://${req.get(
      'host',
    )}/api/v1/users/resetPassword/${resetToken}`;
    await new Email(user, resetURL).sendpasswordReset();
    res.status(200).json({
      status: 'success',
      message: 'Token sent to email!',
    });
  } catch (err) {
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save({ validateBeforeSave: false });
    return next(
      new AppError(
        'There was an error sending the email.Try again Later!',
        500,
      ),
    );
  }
});
exports.resetPassword = catchAsync(async (req, res, next) => {
  //1)get user based on the token
  const hashedToken = crypto
    .createHash('sha256')
    .update(req.params.token)
    .digest('hex');
  const user = await User.findOne({
    passwordResetToken: hashedToken,
    passwordResetExpires: { $gt: Date.now() },
  });
  //2)if token has not expired,and there is user,set the new password
  if (!user) {
    return next(new AppError('Token is invalid or has expired', 400));
  }
  user.password = req.body.password;
  user.passwordConfirm = req.body.passwordConfirm;
  user.passwordResetToken = undefined;
  user.passwordResetExpires = undefined;
  await user.save();
  //3)Update changedPasswordAt property for the user

  //4)Log the user in,send JWT
  createSendToken(user, 200, res);
});

exports.updatePassword = catchAsync(async (req, res, next) => {
  //1)Get the user from collection
  const user = await User.findById(req.user.id).select('+password');
  //2)Check if the posted current password is correct
  if (!(await user.correctPassword(req.body.passwordCurrent, user.password))) {
    return next(new AppError('You Entered a wrong password!', 401));
  }
  //3)If so,update the password
  user.password = req.body.password;
  user.passwordConfirm = req.body.passwordConfirm;
  await user.save();
  //4)log user in , send JWT
  createSendToken(user, 200, res);
});
exports.logout = (req, res) => {
  res.cookie('jwt', 'loggedout', {
    expires: new Date(Date.now() + 10 * 1000), // Cookie expires in 10 seconds
    httpOnly: true,
  });
  res.status(200).json({ status: 'success' });
};