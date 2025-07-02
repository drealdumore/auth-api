import { Router } from "express";
import authController from "../controllers/auth.js";
import userController from "../controllers/user.js";
import {
  sendEmailVerificationCode,
  verifyEmailCode,
} from "../helpers/email.js";
import { refreshAccessToken } from "../helpers/token.js";

const userRouter = Router();

// Public routes
userRouter.post("/register", authController.register);
userRouter.post("/login", authController.login);
userRouter.get("/logout", authController.logOut);
userRouter.post("/forgotPassword", authController.forgotPassword);
userRouter.patch("/resetPassword/:token", authController.resetPassword);

// Email verification routes
userRouter.post("/sendEmailVerificationCode", sendEmailVerificationCode);
userRouter.post("/verifyEmailCode", verifyEmailCode);

// Refresh token route
userRouter.post("/refreshToken", refreshAccessToken);

// Protect all routes after this middleware (require login)
userRouter.use(authController.protect);

// Restrict to verified users only
userRouter.use(authController.protectVerified);

// Authenticated user routes
userRouter.get("/me", userController.getMe, userController.getUser);
userRouter.patch("/updateMyPassword", authController.updatePassword);
userRouter.patch("/updateMe", userController.updateMe);

userRouter.patch("/requestEmailChange", authController.requestEmailChange);
userRouter.post("/confirmEmailChange", authController.confirmEmailChange);

userRouter.post("/verifyEmailUpdate", userController.verifyEmailUpdate);

userRouter.patch("/disableMe", userController.disableMe);
userRouter.delete("/deleteMe", userController.deleteMe);

export default userRouter;
