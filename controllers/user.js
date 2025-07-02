import User from "../models/User.js";
import AppError from "../utils/appError.js";
import { filterObj } from "../utils/filterObj.js";
import asyncHandler from "express-async-handler";

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
      if (!/^[a-zA-Z0-9 -]+$/.test(trimmedFirstName)) {
        return next(new AppError("Invalid first name!", 401));
      }
      updates.firstName = trimmedFirstName;
    }

    if (lastName) {
      const trimmedLastName = lastName.trim();
      if (!/^[a-zA-Z0-9 -]+$/.test(trimmedLastName)) {
        return next(new AppError("Invalid last name!", 401));
      }
      updates.lastName = trimmedLastName;
    }

    if (email) {
      const trimmedEmail = email.trim();
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmedEmail)) {
        return next(new AppError("Invalid email format!", 401));
      }
      updates.email = trimmedEmail;
    }

    // 3) Prevent updating other fields
    const allowedFields = ["firstName", "lastName", "email"];
    const filteredUpdates = filterObj(updates, ...allowedFields);

    // 4) Update user
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
