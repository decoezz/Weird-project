const multer = require('multer');
const sharp = require('sharp');
const jwt = require('jsonwebtoken');
const { promisify } = require('util');
const User = require('../models/userModel.js');
const catchAsync = require('../utils/catchAsync.js');
const AppError = require('./../utils/appError.js');
const multerStorage = multer.memoryStorage();
const multerFilter = (req, file, cb) => {
  if (file.mimetype.startsWith('image')) {
    cb(null, true);
  } else {
    cb(new AppError('Not an image! Please upload only images', 400), false);
  }
};
const upload = multer({
  storage: multerStorage,
  fileFilter: multerFilter,
});
exports.uploadUserPhoto = upload.single('photo');
exports.resizeUserPhoto = catchAsync(async (req, res, next) => {
  if (!req.file) return next();
  req.file.filename = `uesr-${req.user.id}-${Date.now()}.jpeg`;
  await sharp(req.file.buffer)
    .resize(500, 500)
    .toFormat('jpeg')
    .jpeg({ qulaity: 90 })
    .toFile(`public/img/users/${req.file.filename}`);
  next();
});
const filterObj = (obj, ...allowedFileds) => {
  const newObj = {};
  Object.keys(obj).forEach((el) => {
    if (allowedFileds.includes(el)) newObj[el] = obj[el];
  });
  return newObj;
};
exports.getMe = (req, res, next) => {
  req.params.id = req.user.id;
  next();
};

exports.getUser = catchAsync(async (req, res, next) => {
  const user = await User.findById(req.params.id);
  if (!user) {
    return next(new AppError('No User found with this id ', 404));
  }
  res.status(200).json({
    status: 'success',
    data: {
      user,
    },
  });
});
