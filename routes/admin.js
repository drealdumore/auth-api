import { Router } from "express";
import adminController from "../controllers/admin.js";
import authController from "../controllers/auth.js";
import { refreshAccessToken } from "../helpers/token.js";

const adminRouter = Router();

// Admin Login & OTP Verification
adminRouter.post("/login", authController.adminSignIn);
adminRouter.post("/verify-otp", authController.verifyAdminOtp);

// Create Admin
adminRouter.post("/admins", authController.createAdmin);

// Refresh Access Token
adminRouter.post("/refresh-token", refreshAccessToken);

// Protected Routes
adminRouter.use(authController.protect);
adminRouter.use(authController.restrictTo("admin"));

// Users Management (RESTful routes)
adminRouter.get("/users", adminController.getAllUsers);
adminRouter.get("/users/inactive", adminController.getInactiveUsers);
adminRouter.get("/users/:id", adminController.getUser);
adminRouter.patch("/users/:id", adminController.updateUser);
adminRouter.patch("/users/:id/disable", adminController.disableUser);
adminRouter.patch("/users/:id/enable", adminController.enableUser);
adminRouter.delete("/users/:id", adminController.deleteUser);
adminRouter.delete("/users", adminController.deleteAllUsers);

export default adminRouter;
