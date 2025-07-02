import crypto from "crypto";
import { promisify } from "util";
import jwt from "jsonwebtoken";
import AppError from "../utils/appError.js";
import User from "../models/User.js";
import Token from "../models/Token.js";
import Email from "../utils/email.js";
import { validateEmailDomain } from "../utils/validateEmailDomain.js";
import asyncHandler from "express-async-handler";
import {
  signToken,
  signRefreshToken,
  createAndSendTokens,
} from "../helpers/token.js";
import {
  NAME_REGEX,
  EMAIL_REGEX,
  PASSWORD_REGEX,
  ACCOUNT_LOCK_TIME_MINUTES,
  MAX_FAILED_LOGIN_ATTEMPTS,
} from "../utils/validation.js";

const authController = {
  //Registration
  register: asyncHandler(async (req, res, next) => {
    console.log("SignUp function called");
    const { firstName, lastName, email, password, passwordConfirm } = req.body;
    console.log(req.body);

    if (!firstName || !lastName || !email || !password || !passwordConfirm) {
      return next(new AppError("All fields are required!", 400));
    }

    const trimmedEmail = email.trim().toLowerCase();
    const trimmedFirstName = firstName.trim();
    const trimmedLastName = lastName.trim();

    // Validate email format
    if (!EMAIL_REGEX.test(trimmedEmail)) {
      return next(new AppError("Invalid email format!", 401));
    }

    // Validate first and last name
    if (!NAME_REGEX.test(trimmedFirstName)) {
      return next(new AppError("Invalid first name!", 401));
    }

    if (!NAME_REGEX.test(trimmedLastName)) {
      return next(new AppError("Invalid last name!", 401));
    }

    // Validate email domain
    try {
      validateEmailDomain(trimmedEmail);
    } catch (err) {
      return next(err);
    }

    // Validate password strength
    if (!PASSWORD_REGEX.test(password)) {
      return next(
        new AppError(
          "Password must contain at least 1 special character, 1 lowercase letter, and 1 uppercase letter. It must be 8-20 characters long.",
          401
        )
      );
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    console.log("checking if user exist✅✅✅");
    console.log("Existing user:", existingUser);

    if (existingUser) {
      return next(
        new AppError("User with this email address already exists!", 401)
      );
    }

    console.log("creating new user✅✅✅");

    // Create new user
    const newUser = await User.create({
      firstName: trimmedFirstName,
      lastName: trimmedLastName,
      email: trimmedEmail,
      password,
      passwordConfirm,
    });

    console.log("new user created✅✅✅");

    try {
      // Generate 6-digit code and expiration
      const verificationCode = newUser.createEmailVerificationCode(); // sets expiry internally
      await newUser.save({ validateBeforeSave: false });
      console.log(verificationCode);

      const sendEmail = new Email(newUser, verificationCode);
      await sendEmail.sendEmailVerificationCode();

      return res.status(201).json({
        status: "success",
        verificationCode,
        message: "Verification code sent to email successfully!",
      });
    } catch (error) {
      console.log("EMAIL ERROR", error);
      return next(new AppError("Failed to send verification email!", 500));
    }
  }),

  //Login
  login: asyncHandler(async (req, res, next) => {
    const { email, password } = req.body;

    if (!email || !password) {
      return next(new AppError("Please provide email and password!", 422));
    }

    const trimmedEmail = email.trim().toLowerCase();

    if (!EMAIL_REGEX.test(trimmedEmail)) {
      return next(new AppError("Invalid email format!", 401));
    }

    const user = await User.findOne({ email: trimmedEmail }).select(
      "+password"
    );

    if (!user) {
      return next(new AppError("Incorrect email or password", 401));
    }

    if (user.isLocked) {
      return next(
        new AppError(
          "Account locked due to too many failed login attempts. Try again later.",
          423
        )
      ); // 423 Locked
    }

    const passwordCorrect = await user.correctPassword(password, user.password);

    if (!passwordCorrect) {
      user.failedLoginAttempts += 1;

      if (user.failedLoginAttempts >= MAX_FAILED_LOGIN_ATTEMPTS) {
        user.lockUntil = Date.now() + ACCOUNT_LOCK_TIME_MINUTES; // 15 minutes lock
        await user.save({ validateBeforeSave: false });
        return next(
          new AppError(
            "Account locked due to too many failed login attempts. Try again later.",
            423
          )
        );
      }

      await user.save({ validateBeforeSave: false });
      return next(new AppError("Incorrect email or password", 401));
    }

    // Reset failed attempts on successful login
    user.failedLoginAttempts = 0;
    user.lockUntil = null;
    await user.save({ validateBeforeSave: false });

    await createAndSendTokens(user, 200, req, res);
  }),

  // Create Admin
  createAdmin: asyncHandler(async (req, res, next) => {
    const { firstName, lastName, email, password, passwordConfirm, role } =
      req.body;
    const trimmedEmail = email.trim().toLowerCase();

    try {
      validateEmailDomain(trimmedEmail);
    } catch (err) {
      return next(err);
    }

    const newAdmin = await User.create({
      firstName,
      lastName,
      email: trimmedEmail,
      password,
      passwordConfirm,
      role: role || "admin",
    });

    await createAndSendTokens(newAdmin, 201, req, res);
  }),

  // Admin Login
  adminSignIn: asyncHandler(async (req, res, next) => {
    const { email, password } = req.body;

    if (!email || !password) {
      return next(new AppError("Please provide email and password!", 400));
    }

    const trimmedEmail = email.trim().toLowerCase();

    const admin = await User.findOne({ email: trimmedEmail }).select(
      "+password"
    );
    if (!admin || !(await admin.correctPassword(password, admin.password))) {
      return next(new AppError("Incorrect email or password", 401));
    }

    if (admin.role === "user") {
      return next(new AppError("Access denied! Only admins are allowed.", 403));
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    admin.emailVerificationCode = otp;
    admin.emailVerificationExpires = Date.now() + 10 * 60 * 1000;
    await admin.save({ validateBeforeSave: false });

    try {
      const sendEmail = new Email(admin, otp);
      await sendEmail.sendOtp();

      return res.status(200).json({
        status: "success",
        otp,
        message: "OTP sent to your email. Please verify to proceed.",
      });
    } catch (error) {
      admin.emailVerificationCode = undefined;
      admin.emailVerificationExpires = undefined;
      await admin.save({ validateBeforeSave: false });
      return next(new AppError("Failed to send OTP email!", 500));
    }
  }),

  // Verify Admin OTP
  verifyAdminOtp: asyncHandler(async (req, res, next) => {
    const { email, otp } = req.body;

    const admin = await User.findOne({ email });
    if (!admin) {
      return next(new AppError("No admin found with this email address!", 404));
    }

    if (
      otp !== admin.emailVerificationCode ||
      admin.emailVerificationExpires < Date.now()
    ) {
      return next(new AppError("Invalid or expired OTP!", 400));
    }

    admin.emailVerificationCode = undefined;
    admin.emailVerificationExpires = undefined;
    await admin.save({ validateBeforeSave: false });

    await createAndSendTokens(admin, 200, req, res);
  }),

  //Protect Routes
  protect: asyncHandler(async (req, res, next) => {
    let token;
    if (
      req.headers.authorization &&
      req.headers.authorization.startsWith("Bearer")
    ) {
      token = req.headers.authorization.split(" ")[1];
    } else if (req.cookies.jwt) {
      token = req.cookies.jwt;
    }

    if (!token && req.cookies.refreshToken) {
      const refreshToken = req.cookies.refreshToken;

      try {
        const decodedRefresh = await promisify(jwt.verify)(
          refreshToken,
          process.env.JWT_REFRESH_SECRET
        );

        // Check if refresh token exists in DB (reuse detection)
        const storedToken = await Token.findOne({ token: refreshToken });

        if (!storedToken) {
          // Token reuse detected: revoke all user's tokens
          await Token.deleteMany({ user: decodedRefresh.id });
          return next(
            new AppError(
              "Refresh token reuse detected! Please log in again.",
              401
            )
          );
        }

        // Valid refresh token: issue new tokens & rotate
        const user = await User.findById(decodedRefresh.id);
        if (!user) {
          return next(
            new AppError("User no longer exists for this refresh token.", 401)
          );
        }

        // Generate new tokens
        token = signToken(user._id);
        const newRefreshToken = signRefreshToken(user._id);

        // Replace old refresh token with new one
        storedToken.token = newRefreshToken;
        await storedToken.save();

        res.cookie("refreshToken", newRefreshToken, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: "strict",
          expires: new Date(
            Date.now() +
              process.env.JWT_REFRESH_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000
          ),
        });
      } catch (err) {
        return next(
          new AppError(
            "Invalid or expired refresh token. Please log in again.",
            401
          )
        );
      }
    }

    if (!token) {
      return next(
        new AppError(
          "You are not logged in! Please log in to gain access.",
          401
        )
      );
    }

    // Verify access token
    const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

    const currentUser = await User.findById(decoded.id);
    if (!currentUser) {
      return next(
        new AppError("The user belonging to this token no longer exists.", 401)
      );
    }

    if (currentUser.changedPasswordAfter(decoded.iat)) {
      return next(
        new AppError(
          "User recently changed password! Please log in again.",
          401
        )
      );
    }

    req.user = currentUser;
    res.locals.user = currentUser;
    next();
  }),

  //Restrict Routes so specified roles
  restrictTo: (...roles) => {
    return (req, res, next) => {
      if (!roles.includes(req.user.role)) {
        return next(
          new AppError("You do not have access to perform this action!!", 403)
        );
      }

      next();
    };
  },

  //Forgot Password
  forgotPassword: asyncHandler(async (req, res, next) => {
    const { email } = req.body;

    // Get User from EMAIL
    const user = await User.findOne({ email });

    if (!user) {
      return next(new AppError("No user with that email address!", 404));
    }

    // GENERATE random reset token
    const resetToken = user.createPasswordResetToken();
    await user.save({ validateBeforeSave: false });

    try {
      const payload = `${req.protocol}://${req.get(
        "host"
      )}/api/users/resetPassword/${resetToken}`;

      const sendEmail = new Email(user, payload);

      await sendEmail.sendForgotPassword();

      // GET the Password reset token
      res.status(200).json({
        status: "success",
        message: "Token sent!, Check your email to change your password...",
        resetURL: payload,
      });
    } catch (err) {
      user.passwordResetToken = undefined;
      user.passwordResetExpires = undefined;
      await user.save({ validateBeforeSave: false });

      return next(
        new AppError("There was an error sending the email. Try again later!"),
        500
      );
    }
  }),

  //Reset Password
  resetPassword: asyncHandler(async (req, res, next) => {
    const { password, passwordConfirm } = req.body;

    // GET user based on token
    const hashedToken = crypto
      .createHash("sha256")
      .update(req.params.token)
      .digest("hex");

    const user = await User.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: { $gt: Date.now() },
    });

    // If !token && !user ...Send ERROR
    if (!user) {
      return next(new AppError("Token is invalid or has expired", 400));
    }

    // If token hasn't expired and user exist...set new password
    user.password = password;
    user.passwordConfirm = passwordConfirm;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;

    // 3) Update changedPasswordAt property for the user
    user.changedPasswordAt = Date.now();
    await user.save();

    // 4) Log the user in, send JWT
    await createAndSendTokens(user, 200, req, res);
  }),

  //Update Password
  updatePassword: asyncHandler(async (req, res, next) => {
    const { currentPassword, newPassword, newPasswordConfirm } = req.body;

    if (!currentPassword || !newPassword) {
      return next(
        new AppError("Please provide current and new passwords.", 400)
      );
    }

    // 1) Get the user from the collection
    const user = await User.findById(req.user.id).select("+password");

    if (!user) {
      return next(new AppError("User not found", 404));
    }

    // 2) Check if the current password is correct
    const isCorrect = await user.correctPassword(
      currentPassword,
      user.password
    );

    if (!isCorrect) {
      return next(new AppError("Your current password is incorrect", 401));
    }

    // 3) Check if the new password is the same as the current password
    const isSameAsCurrent = await user.correctPassword(
      newPassword,
      user.password
    );

    if (isSameAsCurrent) {
      return next(
        new AppError(
          "New password cannot be the same as the current password",
          400
        )
      );
    }

    // 4) Update the password
    user.password = newPassword;
    user.passwordConfirm = newPasswordConfirm;
    await user.save();

    // 5) Send success response
    res.status(200).json({
      status: "success",
      message: "Password updated successfully!",
    });

    // Optionally, log the user in by sending new tokens
    await createAndSendTokens(user, 200, req, res);
  }),

  // Request change
  requestEmailChange: asyncHandler(async (req, res, next) => {
    const { newEmail } = req.body;

    if (!newEmail || !EMAIL_REGEX.test(newEmail)) {
      return next(new AppError("Please provide a valid new email!", 400));
    }

    // Get current user
    const user = await User.findById(req.user.id);

    // Check if the new email is the same as the current email
    const newEmailNormalized = newEmail.trim().toLowerCase();
    if (user.email === newEmailNormalized) {
      return next(
        new AppError("You are already using this email address!", 400)
      );
    }

    // Check if email is taken by another user
    const existing = await User.findOne({ email: newEmail });
    if (existing) {
      return next(new AppError("This email is already in use!", 409));
    }

    try {
      // Generate 6-digit code
      const code = Math.floor(100000 + Math.random() * 900000).toString();

      // Save to user doc
      user.pendingEmail = newEmail;
      user.pendingEmailVerificationCode = code;
      user.pendingEmailVerificationExpires = Date.now() + 10 * 60 * 1000;

      await user.save({ validateBeforeSave: false });

      // Send email to new address
      const sendEmail = new Email(user, code);
      await sendEmail.sendEmailVerificationCodeToPendingEmail?.(newEmail);

      res.status(200).json({
        status: "success",
        code,
        message: "Verification code sent to new email address.",
      });
    } catch (error) {
      console.log("EMAIL ERROR", error);
      return next(new AppError("Failed to send verification email!", 500));
    }
  }),

  // Confirm change
  confirmEmailChange: asyncHandler(async (req, res, next) => {
    const { code } = req.body;
    if (!code) {
      return next(new AppError("Please provide the verification code.", 400));
    }

    const user = await User.findById(req.user.id);

    if (
      !user.pendingEmail ||
      code !== user.pendingEmailVerificationCode ||
      user.pendingEmailVerificationExpires < Date.now()
    ) {
      return next(
        new AppError(
          "Invalid or expired verification code for email update!",
          400
        )
      );
    }

    // Apply the pending email update
    user.email = user.pendingEmail;
    user.emailVerified = false;
    user.pendingEmail = undefined;
    user.pendingEmailVerificationCode = undefined;
    user.pendingEmailVerificationExpires = undefined;

    await user.save({ validateBeforeSave: false });

    res.status(200).json({
      status: "success",
      message: "Email address updated successfully.",
    });
  }),

  //Protect Routes for verified users
  protectVerified: asyncHandler(async (req, res, next) => {
    if (!req.user.emailVerified) {
      return next(
        new AppError("Please verify your email to access this route.", 403)
      );
    }
    next();
  }),

  //Logout
  logOut: asyncHandler(async (req, res, next) => {
    const { refreshToken } = req.cookies;

    if (refreshToken) {
      await Token.findOneAndDelete({ token: refreshToken });
    }

    res.cookie("jwt", "loggedout", {
      expires: new Date(Date.now() + 10 * 1000),
      httpOnly: true,
    });
    res.clearCookie("refreshToken");

    res.status(200).json({
      status: "success",
      message: "User logged out successfully!",
    });
  }),
};

export default authController;
