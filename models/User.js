import { model, Schema } from "mongoose";
import validator from "validator";
import crypto from "crypto";
import bcrypt from "bcryptjs";

const userSchema = new Schema(
  {
    firstName: {
      type: String,
      required: [true, "Please tell us your first name!"],
    },
    lastName: {
      type: String,
      required: [true, "Please tell us your last name!"],
    },
    email: {
      type: String,
      required: [true, "Please provide your email address"],
      unique: true,
      lowercase: true,
      trim: true,
      validate: [validator.isEmail, "Please provide a valid email address"],
    },
    password: {
      type: String,
      required: [true, "please provide a password!"],
      minlength: 8,
      maxLength: 20,
      select: false,
    },
    passwordConfirm: {
      type: String,
      required: [true, "Please confirm your password!"],
      validate: {
        validator: function (el) {
          return el === this.password;
        },
        message: "Password did not match!",
      },
    },
    role: {
      type: String,
      enum: ["user", "admin", "manager"],
      default: "user",
    },
    profilePicture: {
      type: String,
      default:
        "https://res.cloudinary.com/dgxyjw6q8/image/upload/v1696332701/default_mwrcrs.png",
    },
    passwordChangedAt: Date,
    passwordResetToken: String,
    passwordResetExpires: Date,
    active: {
      type: Boolean,
      default: true,
    },

    emailVerified: {
      type: Boolean,
      default: false,
    },

    pendingEmail: {
      type: String,
      lowercase: true,
      trim: true,
    },
    emailChangeToken: String,
    emailChangeTokenExpires: Date,

    pendingEmailVerificationCode: String,
    pendingEmailVerificationExpires: Date,

    emailVerificationCode: String,
    emailVerificationExpires: Date,
    emailVerificationToken: String,

    failedLoginAttempts: { type: Number, default: 0 },
    lockUntil: { type: Date, default: null },
  },

  { timestamps: true }
);

userSchema.virtual("isLocked").get(function () {
  return !!(this.lockUntil && this.lockUntil > Date.now());
});

userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();

  this.password = await bcrypt.hash(this.password, 12);

  this.passwordConfirm = undefined;
  next();
});

userSchema.pre("save", function (next) {
  if (!this.isModified("password") || this.isNew) return next();

  this.passwordChangedAt = Date.now() - 1000;
  next();
});

userSchema.methods.correctPassword = async function (
  candidatePassword,
  userPassword
) {
  if (!candidatePassword || !userPassword) {
    throw new Error("Password comparison failed. Missing values.");
  }

  return await bcrypt.compare(candidatePassword, userPassword);
};

userSchema.methods.changedPasswordAfter = function (JWTTimestamp) {
  if (this.passwordChangedAt) {
    const changedTimestamp = parseInt(
      this.passwordChangedAt.getTime() / 1000,
      10
    );

    return JWTTimestamp < changedTimestamp;
  }

  return false;
};

userSchema.methods.createPasswordResetToken = function () {
  const resetToken = crypto.randomBytes(32).toString("hex");

  this.passwordResetToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");

  console.log(
    "coming from user model::::: ",
    { resetToken },
    this.passwordResetToken
  );

  this.passwordResetExpires = Date.now() + 10 * 60 * 1000;

  return resetToken;
};

userSchema.methods.updatePassword = async function (
  currentPassword,
  newPassword,
  newPasswordConfirm
) {
  const isCorrect = await this.correctPassword(currentPassword, this.password);
  if (!isCorrect) {
    throw new Error("Current password is incorrect!");
  }

  if (newPassword !== newPasswordConfirm) {
    throw new Error("New passwords do not match!");
  }

  this.password = await bcrypt.hash(newPassword, 12);

  this.passwordChangedAt = Date.now();

  this.passwordResetToken = undefined;
  this.passwordResetExpires = undefined;

  await this.save();
};

userSchema.methods.createEmailVerificationCode = function () {
  const verificationCode = Math.floor(
    100000 + Math.random() * 900000
  ).toString();

  this.emailVerificationCode = verificationCode;

  this.emailVerificationExpires = Date.now() + 10 * 60 * 1000; // 10 mins

  return verificationCode;
};

const User = model("User", userSchema);

export default User;
