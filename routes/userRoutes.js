const express = require('express');
const userController = require('../controllers/userController.js');
const authController = require('../controllers/authController.js');
const router = express.Router();
router.post('/signup', authController.signup);
router.post('/login', authController.login);
router.get(
  '/me',
  authController.protect,
  userController.getMe,
  userController.getUser
);

module.exports = router;
