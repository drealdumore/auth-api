import User from "../models/User.js";
import asyncHandler from "express-async-handler";
import AppError from "../utils/appError.js";

const adminController = {
  // GET /users?page=1&limit=20
  getAllUsers: asyncHandler(async (req, res, next) => {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;

    const [users, total] = await Promise.all([
      User.find({ active: true }).skip(skip).limit(limit).lean(),
      User.countDocuments({ active: true }),
    ]);

    if (!users.length) {
      return next(new AppError("No users found.", 404));
    }

    res.status(200).json({
      status: "success",
      results: users.length,
      total,
      page,
      totalPages: Math.ceil(total / limit),
      data: { users },
    });
  }),

  // GET /users/inactive?page=1&limit=20
  getInactiveUsers: asyncHandler(async (req, res, next) => {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;

    const [users, total] = await Promise.all([
      User.find({ active: false }).skip(skip).limit(limit).lean(),
      User.countDocuments({ active: false }),
    ]);

    if (!users.length) {
      return next(new AppError("No inactive users found.", 404));
    }

    res.status(200).json({
      status: "success",
      results: users.length,
      total,
      page,
      totalPages: Math.ceil(total / limit),
      data: { users },
    });
  }),

  // GET /users/:id
  getUser: asyncHandler(async (req, res, next) => {
    const user = await User.findById(req.params.id).lean();

    if (!user) {
      return next(new AppError("No user found with the provided ID.", 404));
    }

    res.status(200).json({
      status: "success",
      data: { user },
    });
  }),

  // PATCH /users/:id
  updateUser: asyncHandler(async (req, res, next) => {
    const { emailVerified, active, role, ...otherFields } = req.body;

    if (Object.keys(req.body).length === 0) {
      return next(
        new AppError(
          "At least one field (emailVerified, active, role) must be provided to update a user.",
          400
        )
      );
    }

    if (role && !["user", "admin"].includes(role)) {
      return next(new AppError("Role must be either 'user' or 'admin'.", 400));
    }

    // Prevent updating disallowed fields
    const disallowedFields = Object.keys(otherFields);
    if (disallowedFields.length > 0) {
      const msg =
        disallowedFields.length === 1
          ? `Admin cannot update ${disallowedFields[0]}.`
          : `Admin cannot update the following fields: ${disallowedFields.join(
              ", "
            )}.`;
      return next(new AppError(msg, 403));
    }

    const updates = { emailVerified, active, role };
    const user = await User.findByIdAndUpdate(req.params.id, updates, {
      new: true,
      runValidators: true,
    });

    if (!user) {
      return next(new AppError("No user found with the provided ID.", 404));
    }

    res.status(200).json({
      status: "success",
      data: { user },
    });
  }),

  // PATCH /users/:id/disable
  disableUser: asyncHandler(async (req, res, next) => {
    const user = await User.findByIdAndUpdate(
      req.params.id,
      { active: false },
      { new: true }
    );

    if (!user) {
      return next(new AppError("No user found with the provided ID.", 404));
    }

    res.status(200).json({
      status: "success",
      message: "User disabled successfully.",
      data: { user },
    });
  }),

  // PATCH /users/:id/enable
  enableUser: asyncHandler(async (req, res, next) => {
    const user = await User.findByIdAndUpdate(
      req.params.id,
      { active: true },
      { new: true }
    );

    if (!user) {
      return next(new AppError("No user found with the provided ID.", 404));
    }

    res.status(200).json({
      status: "success",
      message: "User enabled successfully.",
      data: { user },
    });
  }),

  // DELETE /users/:id
  deleteUser: asyncHandler(async (req, res, next) => {
    const user = await User.findByIdAndDelete(req.params.id);

    if (!user) {
      return next(new AppError("No user found with the provided ID.", 404));
    }

    res.status(204).json({
      status: "success",
      message: "User deleted successfully.",
    });
  }),

  // DELETE /users
  deleteAllUsers: asyncHandler(async (req, res) => {
    const result = await User.deleteMany();

    res.status(200).json({
      status: "success",
      message: `${result.deletedCount} users deleted successfully.`,
    });
  }),
};

export default adminController;
