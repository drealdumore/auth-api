import User from "../models/User.js";
import AppError from "../utils/appError.js";
import { filterObj } from "../utils/filterObj.js";
import asyncHandler from "express-async-handler";
import Email from "../utils/email.js";
import { NAME_REGEX, EMAIL_REGEX } from "../utils/validation.js";

const userController = {
  updateMe: asyncHandler(async (req, res, next) => {
    const { firstName, lastName, email, password, passwordConfirm } = req.body;

    // 1) Reject password update on this route
    if (password || passwordConfirm) {
      return next(
        new AppError(
          "This route is not for password updates. Please use /updateMyPassword",
          400
        )
      );
    }

    // 2) Validate and sanitize inputs
    const updates = {};

    if (firstName) {
      const trimmedFirstName = firstName.trim();
      if (!NAME_REGEX.test(trimmedFirstName)) {
        return next(new AppError("Invalid first name!", 401));
      }
      updates.firstName = trimmedFirstName;
    }

    if (lastName) {
      const trimmedLastName = lastName.trim();
      if (!NAME_REGEX.test(trimmedLastName)) {
        return next(new AppError("Invalid last name!", 401));
      }
      updates.lastName = trimmedLastName;
    }

    const user = await User.findById(req.user.id);
    if (!user) {
      return next(new AppError("User not found", 404));
    }

    if (email && email !== user.email) {
      const trimmedEmail = email.trim();
      if (!EMAIL_REGEX.test(trimmedEmail)) {
        return next(new AppError("Invalid email format!", 401));
      }

      // Generate verification code
      const verificationCode = Math.floor(
        100000 + Math.random() * 900000
      ).toString();

      user.pendingEmail = trimmedEmail;
      user.pendingEmailVerificationCode = verificationCode;
      user.pendingEmailVerificationExpires = Date.now() + 10 * 60 * 1000; // 10 mins
      await user.save({ validateBeforeSave: false });

      try {
        const sendEmail = new Email(user, verificationCode);
        await sendEmail.sendEmailVerificationCodeToPendingEmail?.(newEmail);

        return res.status(200).json({
          status: "pending",
          message:
            "Verification code sent to new email. Please verify to complete update.",
        });
      } catch (err) {
        console.log("EMAIL ERROR", error);
        return next(new AppError("Failed to send verification email.", 500));
      }
    }

    // Apply allowed updates
    const allowedFields = ["firstName", "lastName"];
    const filteredUpdates = filterObj(updates, ...allowedFields);

    const updatedUser = await User.findByIdAndUpdate(
      req.user.id,
      filteredUpdates,
      {
        new: true,
        runValidators: true,
      }
    );

    res.status(200).json({
      status: "success",
      data: {
        user: updatedUser,
      },
    });
  }),

  verifyEmailUpdate: asyncHandler(async (req, res, next) => {
    const { code } = req.body;

    if (!code) {
      return next(new AppError("Please provide the verification code.", 400));
    }

    const user = await User.findById(req.user.id);

    if (
      !user ||
      !user.pendingEmail ||
      user.pendingEmailVerificationCode !== code ||
      user.pendingEmailVerificationExpires < Date.now()
    ) {
      return next(new AppError("Invalid or expired verification code.", 400));
    }

    user.email = user.pendingEmail;
    user.emailVerified = false;
    user.pendingEmail = undefined;
    user.emailVerificationCode = undefined;
    user.emailVerificationExpires = undefined;

    await user.save({ validateBeforeSave: false });

    res.status(200).json({
      status: "success",
      message: "Email address updated successfully!",
      data: { email: user.email },
    });
  }),

  getMe: (req, res, next) => {
    req.params.id = req.user.id;
    next();
  },

  getUser: asyncHandler(async (req, res, next) => {
    const user = await User.findById(req.params.id).lean();

    if (!user) {
      return next(new AppError("No user with that ID", 404));
    }

    res.status(200).json({
      status: "success",
      data: { user },
    });
  }),

  disableMe: asyncHandler(async (req, res, next) => {
    await User.findByIdAndUpdate(req.user.id, { active: false });

    res.status(200).json({
      status: "success",
      message: "Account disabled successfully.",
    });
  }),

  deleteMe: asyncHandler(async (req, res, next) => {
    await User.findByIdAndUpdate(req.user.id, { active: false });

    res.status(204).json({
      status: "success",
      message: "User marked as deleted.",
      data: null,
    });
  }),
};

export default userController;
