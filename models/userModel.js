const crypto = require('crypto');
const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcryptjs');

// Function to check if the first letter is capitalized
const nameValidator = (value) => /^[A-Z]/.test(value);

// Function to format the date as YYYY/MM/DD
const formatDate = (date) => {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0'); // Months are 0-based
  const day = String(date.getDate()).padStart(2, '0');
  return `${year}/${month}/${day}`;
};

// Regular expression for password validation
const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\W).+$/;

const userSchema = new mongoose.Schema(
  {
    FirstName: {
      type: String,
      required: [true, 'Please enter your First name'],
      minlength: 2,
      maxlength: 30,
      validate: [
        {
          validator: nameValidator,
          message: 'First name must start with a capital letter',
        },
        {
          validator: validator.isAlpha,
          message: 'First name must only contain alphabetic characters',
        },
      ],
    },
    LastName: {
      type: String,
      required: [true, 'Please enter your Last name'],
      minlength: 2,
      maxlength: 30,
      validate: [
        {
          validator: nameValidator,
          message: 'Last name must start with a capital letter',
        },
        {
          validator: validator.isAlpha,
          message: 'Last name must only contain alphabetic characters',
        },
      ],
    },
    name: {
      type: String,
    },
    email: {
      type: String,
      required: [true, 'Please enter your email'],
      unique: true,
      lowercase: true,
      validate: [validator.isEmail, 'Please enter a valid email address'],
    },
    password: {
      type: String,
      required: [true, 'Please enter your password'],
      validate: {
        validator: function (value) {
          return passwordRegex.test(value);
        },
        message:
          'Password must contain at least one uppercase letter, one lowercase letter, and one special character.',
      },
    },
    passwordConfirm: {
      type: String,
      required: [true, 'Please confirm your password'],
      validate: {
        validator: function (el) {
          return el === this.password;
        },
        message: 'Passwords do not match',
      },
    },
    passwordChangedAt: Date,
    passwordResetToken: String,
    passwordResetExpires: Date,
    photo: { type: String, default: 'default.jpg' },
    Position: {
      type: String,
      validate: [validator.isAlpha, 'Position must only contain characters'],
    },
    Office: {
      type: String,
      enum: [
        'New York',
        'Singapore',
        'Edinburgh',
        'San Francisco',
        'London',
        'Sidney',
        'Tokyo',
      ],
    },
    Age: {
      type: Number,
      max: 80,
      min: 18,
    },
    StartDate: {
      type: Date,
      default: Date.now, // Automatically set to the current date
      get: formatDate, // Format the date when it is retrieved
    },
    Salary: {
      type: Number,
      max: 1500000,
    },
    active: {
      type: Boolean,
      default: false,
      select: false,
    },
    role: {
      type: String,
      default: 'user',
      enum: {
        values: ['user', 'admin'],
      },
    },
    verificationToken: {
      type: String,
    },
    isEmailVerified: {
      type: Boolean,
      default: false,
      select: false // Optional: Exclude from queries by default
    },
  },
  {
    toJSON: { getters: true, virtuals: true }, // Apply getter when converting to JSON
    toObject: { getters: true, virtuals: true }, // Apply getter when converting to Object
  }
);
// In your Mongoose schema
userSchema.index({ email: 1 });
// Populate the `name` field by combining `FirstName` and `LastName`
userSchema.pre('save', function (next) {
  this.name = `${this.FirstName} ${this.LastName}`;
  next();
});
userSchema.pre('save', function (next) {
  if (this.isModified('email')) {
    this.email = this.email.trim().toLowerCase();
  }
  next();
});

// Hash the password before saving it to the database
userSchema.pre('save', async function (next) {
  // Only run this function if the password was actually modified
  if (!this.isModified('password')) return next();

  // Hash the password with bcrypt cost of 12
  this.password = await bcrypt.hash(this.password, 12);

  // Delete password confirmation field
  this.passwordConfirm = undefined;
  next();
});

// Set the passwordChangedAt field if the password was modified
userSchema.pre('save', function (next) {
  if (!this.isModified('password') || this.isNew) return next();

  this.passwordChangedAt = Date.now() - 1000;
  next();
});

// Compare candidate password with the user's password
userSchema.methods.correctPassword = async function (
  candidatePassword,
  userPassword
) {
  return bcrypt.compare(candidatePassword, userPassword);
};

// Check if the password was changed after the JWT token was issued
userSchema.methods.changedPasswordAfter = function (JWTTimestamp) {
  if (this.passwordChangedAt) {
    const changedTimestamp = parseInt(
      this.passwordChangedAt.getTime() / 1000,
      10
    );

    return JWTTimestamp < changedTimestamp;
  }

  // False means password was not changed
  return false;
};

// Generate a password reset token
userSchema.methods.createPasswordResetToken = function () {
  const resetToken = crypto.randomBytes(32).toString('hex');

  this.passwordResetToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');

  this.passwordResetExpires = Date.now() + 10 * 60 * 1000; // Token valid for 10 minutes

  return resetToken;
};

const User = mongoose.model('User', userSchema);

module.exports = User;
